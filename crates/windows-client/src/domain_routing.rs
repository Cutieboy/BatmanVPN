#![doc = "Domain rules and DNS-derived address mapping for split tunneling."]

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

const DNS_CACHE_TTL: Duration = Duration::from_secs(600);
const MAX_DOMAIN_RULES: usize = 4096;
const MAX_DNS_NAMES: usize = 8192;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainRoute {
    Tunnel,
    Direct,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainRule {
    pub domain: String,
    pub route: DomainRoute,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredRules {
    version: u8,
    rules: Vec<DomainRule>,
}

#[derive(Default)]
struct Cache {
    by_domain: HashMap<String, HashSet<IpAddr>>,
    by_ip: HashMap<IpAddr, Vec<(String, Instant)>>,
    queries: HashMap<u16, (String, Instant)>,
}

#[derive(Clone, Default)]
pub struct DomainRouting {
    rules: Arc<RwLock<Vec<DomainRule>>>,
    cache: Arc<RwLock<Cache>>,
}

impl DomainRouting {
    pub fn new(rules: Vec<DomainRule>) -> Result<Self, String> {
        let mut rules = rules;
        normalize_rules(&mut rules)?;
        Ok(Self {
            rules: Arc::new(RwLock::new(rules)),
            cache: Arc::new(RwLock::new(Cache::default())),
        })
    }

    pub fn rules(&self) -> Vec<DomainRule> {
        self.rules.read().map(|r| r.clone()).unwrap_or_default()
    }

    pub fn replace_rules(&self, mut rules: Vec<DomainRule>) -> Result<(), String> {
        normalize_rules(&mut rules)?;
        *self.rules.write().map_err(|_| "domain-rule lock poisoned".to_owned())? = rules;
        Ok(())
    }

    pub fn add_rule(&self, domain: &str, route: DomainRoute) -> Result<Vec<DomainRule>, String> {
        let domain = normalize_domain(domain)?;
        let mut rules = self.rules.write().map_err(|_| "domain-rule lock poisoned".to_owned())?;
        rules.retain(|rule| rule.domain != domain);
        rules.push(DomainRule { domain, route });
        normalize_rules(&mut rules)?;
        Ok(rules.clone())
    }

    pub fn remove_rule(&self, domain: &str) -> Result<Vec<DomainRule>, String> {
        let domain = normalize_domain(domain)?;
        let mut rules = self.rules.write().map_err(|_| "domain-rule lock poisoned".to_owned())?;
        rules.retain(|rule| rule.domain != domain);
        Ok(rules.clone())
    }

    /// Observe a DNS query or response carried as an inner UDP packet.
    /// Returns true when it was a valid DNS packet, false otherwise.
    pub fn observe_dns_packet(&self, packet: &[u8]) -> bool {
        let Some((src, dst, payload)) = udp_payload(packet) else { return false; };
        if src != 53 && dst != 53 { return false; }
        if payload.len() < 12 { return false; }

        let id = u16::from_be_bytes([payload[0], payload[1]]);
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let is_response = flags & 0x8000 != 0;
        let Some((name, question_end)) = read_qname(payload, 12) else { return false; };
        let Some(domain) = normalize_domain(&name).ok() else { return false; };

        if !is_response {
            if let Ok(mut cache) = self.cache.write() {
                if cache.queries.len() >= MAX_DNS_NAMES { cache.queries.clear(); }
                cache.queries.insert(id, (domain, Instant::now()));
            }
            return true;
        }

        let question_count = u16::from_be_bytes([payload[4], payload[5]]) as usize;
        let answer_count = u16::from_be_bytes([payload[6], payload[7]]) as usize;
        if question_count == 0 { return true; }
        // Match only a response associated with a recent query, avoiding
        // learning unsolicited packets as authoritative DNS answers.
        let queried = self.cache.write().ok().and_then(|mut cache| {
            let entry = cache.queries.remove(&id)?;
            (entry.1.elapsed() <= Duration::from_secs(30)).then_some(entry.0)
        }).unwrap_or(domain);

        let mut offset = question_end;
        // Skip additional questions if any.
        for _ in 1..question_count {
            let Some((_, next)) = read_qname(payload, offset) else { return true; };
            if next + 4 > payload.len() { return true; }
            offset = next + 4;
        }
        let Some(next) = offset.checked_add(4) else { return true; };
        if next > payload.len() { return true; }
        offset = next;

        let mut addresses = Vec::new();
        for _ in 0..answer_count {
            let Some((_, next)) = read_qname(payload, offset) else { break; };
            offset = next;
            if offset + 10 > payload.len() { break; }
            let rr_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let class = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
            let ttl = u32::from_be_bytes([payload[offset + 4], payload[offset + 5], payload[offset + 6], payload[offset + 7]]);
            let length = u16::from_be_bytes([payload[offset + 8], payload[offset + 9]]) as usize;
            offset += 10;
            if offset + length > payload.len() { break; }
            if class == 1 && ttl > 0 && rr_type == 1 && length == 4 {
                addresses.push((IpAddr::from([payload[offset], payload[offset + 1], payload[offset + 2], payload[offset + 3]]), ttl));
            } else if class == 1 && ttl > 0 && rr_type == 28 && length == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&payload[offset..offset + 16]);
                addresses.push((IpAddr::from(octets), ttl));
            }
            offset += length;
        }
        if let Ok(mut cache) = self.cache.write() {
            let set = cache.by_domain.entry(queried.clone()).or_default();
            for (ip, ttl) in addresses {
                set.insert(ip);
                cache.by_ip.entry(ip).or_default().push((queried.clone(), Instant::now() + DNS_CACHE_TTL.min(Duration::from_secs(ttl as u64))));
            }
        }
        true
    }

    #[cfg(test)]
    pub fn learn_domain_ip_for_test(&self, domain: &str, ip: IpAddr) {
        let domain = normalize_domain(domain).expect("test domain is valid");
        let mut cache = self.cache.write().expect("cache lock");
        cache.by_domain.entry(domain.clone()).or_default().insert(ip);
        cache.by_ip.entry(ip).or_default().push((domain, Instant::now() + DNS_CACHE_TTL));
    }

    pub fn route_for_ip(&self, ip: IpAddr) -> Option<DomainRoute> {
        let rules = self.rules.read().ok()?;
        let mut cache = self.cache.write().ok()?;
        let entries = cache.by_ip.get_mut(&ip)?;
        entries.retain(|(_, expires)| *expires > Instant::now());
        for (domain, _) in entries.iter() {
            if let Some(rule) = rules.iter().filter(|rule| domain_matches(domain, &rule.domain)).max_by_key(|rule| rule.domain.len()) {
                return Some(rule.route);
            }
        }
        None
    }
}

pub fn normalize_domain(raw: &str) -> Result<String, String> {
    let value = raw.trim().trim_end_matches('.').trim_start_matches("*.").to_ascii_lowercase();
    if value.is_empty() || value.len() > 253 || value.contains('/') || value.contains(':') || value.contains(' ') {
        return Err("Введите домен без схемы и пути, например chatgpt.com".to_owned());
    }
    let labels = value.split('.').collect::<Vec<_>>();
    if labels.len() < 2 || labels.iter().any(|label| label.is_empty() || label.len() > 63 ||
        label.starts_with('-') || label.ends_with('-') ||
        !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')) {
        return Err("Некорректное доменное имя".to_owned());
    }
    Ok(value)
}

fn normalize_rules(rules: &mut Vec<DomainRule>) -> Result<(), String> {
    if rules.len() > MAX_DOMAIN_RULES { return Err("Слишком много доменных правил".to_owned()); }
    let mut map = HashMap::new();
    for rule in rules.drain(..) {
        let domain = normalize_domain(&rule.domain)?;
        map.insert(domain.clone(), DomainRule { domain, route: rule.route });
    }
    *rules = map.into_values().collect();
    rules.sort_by(|a,b| a.domain.cmp(&b.domain));
    Ok(())
}

fn domain_matches(host: &str, rule: &str) -> bool {
    host == rule || host.strip_suffix(rule).is_some_and(|prefix| prefix.ends_with('.'))
}

fn udp_payload(packet: &[u8]) -> Option<(u16, u16, &[u8])> {
    let version = packet.first()? >> 4;
    let (protocol, start) = match version {
        4 => {
            let hlen = usize::from(packet[0] & 0x0f) * 4;
            if hlen < 20 || packet.len() < hlen { return None; }
            (packet[9], hlen)
        }
        6 => {
            if packet.len() < 40 || packet[6] != 17 { return None; }
            (packet[6], 40)
        }
        _ => return None,
    };
    if protocol != 17 || packet.len() < start + 8 { return None; }
    let src = u16::from_be_bytes([packet[start], packet[start + 1]]);
    let dst = u16::from_be_bytes([packet[start + 2], packet[start + 3]]);
    let len = u16::from_be_bytes([packet[start + 4], packet[start + 5]]) as usize;
    if len < 8 || start + len > packet.len() { return None; }
    Some((src, dst, &packet[start + 8..start + len]))
}

fn read_qname(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut consumed = None;
    let mut jumps = 0;
    loop {
        let length = *packet.get(offset)?;
        if length & 0xc0 == 0xc0 {
            let second = *packet.get(offset + 1)?;
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(second);
            if pointer >= packet.len() || jumps > 8 { return None; }
            consumed.get_or_insert(offset + 2);
            offset = pointer;
            jumps += 1;
            continue;
        }
        if length & 0xc0 != 0 || length > 63 { return None; }
        offset += 1;
        if length == 0 { break; }
        let end = offset.checked_add(length as usize)?;
        let label = std::str::from_utf8(packet.get(offset..end)?).ok()?;
        labels.push(label.to_ascii_lowercase());
        offset = end;
        if labels.iter().map(String::len).sum::<usize>() + labels.len() > 253 { return None; }
    }
    Some((labels.join("."), consumed.unwrap_or(offset)))
}

#[cfg(test)]
mod tests {
    use super::{domain_matches, normalize_domain, DomainRoute, DomainRule, DomainRouting};

    #[test]
    fn normalizes_user_domain_rules() {
        assert_eq!(normalize_domain("  *.ChatGPT.com. ").unwrap(), "chatgpt.com");
        assert!(normalize_domain("https://chatgpt.com/path").is_err());
    }

    #[test]
    fn domain_rule_matches_root_and_subdomains() {
        assert!(domain_matches("chatgpt.com", "chatgpt.com"));
        assert!(domain_matches("auth.chatgpt.com", "chatgpt.com"));
        assert!(!domain_matches("notchatgpt.com", "chatgpt.com"));
    }

    #[test]
    fn more_specific_domain_rules_win() {
        let routes = DomainRouting::new(vec![
            DomainRule { domain: "example.com".into(), route: DomainRoute::Tunnel },
            DomainRule { domain: "direct.example.com".into(), route: DomainRoute::Direct },
        ]).unwrap();
        assert_eq!(routes.rules()[0].domain, "direct.example.com");
    }
}
