use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use mousevpn_config::ClientProtocol;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const FORMAT_VERSION: u8 = 1;
const MINIMUM_OBSERVATION_SECONDS: u64 = 5 * 60;
const MINIMUM_KEEPALIVES: u64 = 20;

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct RuntimeMetrics {
    uptime_seconds: u64,
    outgoing_packets: u64,
    incoming_packets: u64,
    outgoing_drops: u64,
    keepalives_sent: u64,
    keepalive_responses: u64,
    keepalive_timeouts: u64,
    reconnects: u64,
    reconnect_failures: u64,
    peer_unreachable: u64,
    migrations: u64,
    keepalive_rtt_total_ms: u64,
    keepalive_rtt_samples: u64,
    last_keepalive_rtt_ms: u64,
    max_keepalive_rtt_ms: u64,
}

impl RuntimeMetrics {
    fn delta(self, previous: Self) -> Self {
        Self {
            uptime_seconds: self.uptime_seconds.saturating_sub(previous.uptime_seconds),
            outgoing_packets: self
                .outgoing_packets
                .saturating_sub(previous.outgoing_packets),
            incoming_packets: self
                .incoming_packets
                .saturating_sub(previous.incoming_packets),
            outgoing_drops: self.outgoing_drops.saturating_sub(previous.outgoing_drops),
            keepalives_sent: self
                .keepalives_sent
                .saturating_sub(previous.keepalives_sent),
            keepalive_responses: self
                .keepalive_responses
                .saturating_sub(previous.keepalive_responses),
            keepalive_timeouts: self
                .keepalive_timeouts
                .saturating_sub(previous.keepalive_timeouts),
            reconnects: self.reconnects.saturating_sub(previous.reconnects),
            reconnect_failures: self
                .reconnect_failures
                .saturating_sub(previous.reconnect_failures),
            peer_unreachable: self
                .peer_unreachable
                .saturating_sub(previous.peer_unreachable),
            migrations: self.migrations.saturating_sub(previous.migrations),
            keepalive_rtt_total_ms: self
                .keepalive_rtt_total_ms
                .saturating_sub(previous.keepalive_rtt_total_ms),
            keepalive_rtt_samples: self
                .keepalive_rtt_samples
                .saturating_sub(previous.keepalive_rtt_samples),
            last_keepalive_rtt_ms: self.last_keepalive_rtt_ms,
            max_keepalive_rtt_ms: self.max_keepalive_rtt_ms,
        }
    }
}

#[derive(Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
struct StoredDiagnostics {
    version: u8,
    profiles: BTreeMap<String, ProfileDiagnostics>,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
struct ProfileDiagnostics {
    modes: BTreeMap<String, ModeTotals>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
struct ModeTotals {
    sessions: u64,
    observed_seconds: u64,
    outgoing_packets: u64,
    incoming_packets: u64,
    outgoing_drops: u64,
    keepalives_sent: u64,
    keepalive_responses: u64,
    keepalive_timeouts: u64,
    reconnects: u64,
    reconnect_failures: u64,
    peer_unreachable: u64,
    migrations: u64,
    keepalive_rtt_total_ms: u64,
    keepalive_rtt_samples: u64,
    max_keepalive_rtt_ms: u64,
    updated_at: u64,
}

impl ModeTotals {
    fn add(&mut self, delta: RuntimeMetrics, first_observation: bool) {
        self.sessions += u64::from(first_observation);
        self.observed_seconds += delta.uptime_seconds;
        self.outgoing_packets += delta.outgoing_packets;
        self.incoming_packets += delta.incoming_packets;
        self.outgoing_drops += delta.outgoing_drops;
        self.keepalives_sent += delta.keepalives_sent;
        self.keepalive_responses += delta.keepalive_responses;
        self.keepalive_timeouts += delta.keepalive_timeouts;
        self.reconnects += delta.reconnects;
        self.reconnect_failures += delta.reconnect_failures;
        self.peer_unreachable += delta.peer_unreachable;
        self.migrations += delta.migrations;
        self.keepalive_rtt_total_ms += delta.keepalive_rtt_total_ms;
        self.keepalive_rtt_samples += delta.keepalive_rtt_samples;
        self.max_keepalive_rtt_ms = self.max_keepalive_rtt_ms.max(delta.max_keepalive_rtt_ms);
        self.updated_at = unix_time();
    }
}

struct ActiveSession {
    profile_id: String,
    protocol: ClientProtocol,
    previous: RuntimeMetrics,
    observed: bool,
}

pub(crate) struct ReliabilityMonitor {
    path: Option<PathBuf>,
    stored: StoredDiagnostics,
    active: Option<ActiveSession>,
}

impl Default for ReliabilityMonitor {
    fn default() -> Self {
        Self::load()
    }
}

impl ReliabilityMonitor {
    pub(crate) fn load() -> Self {
        let path = diagnostics_path();
        let stored = path
            .as_ref()
            .and_then(|path| fs::read(path).ok())
            .and_then(|bytes| serde_json::from_slice::<StoredDiagnostics>(&bytes).ok())
            .filter(|stored| stored.version == FORMAT_VERSION)
            .unwrap_or_else(|| StoredDiagnostics {
                version: FORMAT_VERSION,
                ..StoredDiagnostics::default()
            });
        Self {
            path,
            stored,
            active: None,
        }
    }

    pub(crate) fn begin(&mut self, profile_id: String, protocol: ClientProtocol) {
        self.active = Some(ActiveSession {
            profile_id,
            protocol,
            previous: RuntimeMetrics::default(),
            observed: false,
        });
    }

    pub(crate) fn observe(
        &mut self,
        profile_id: &str,
        protocol: ClientProtocol,
        current: RuntimeMetrics,
    ) -> Result<(), String> {
        let matches = self
            .active
            .as_ref()
            .is_some_and(|active| active.profile_id == profile_id && active.protocol == protocol);
        if !matches {
            self.begin(profile_id.to_owned(), protocol);
        }
        let active = self
            .active
            .as_mut()
            .expect("active session was initialized");
        let delta = current.delta(active.previous);
        let first_observation = !active.observed;
        active.previous = current;
        active.observed = true;

        self.stored
            .profiles
            .entry(profile_id.to_owned())
            .or_default()
            .modes
            .entry(protocol_key(protocol).to_owned())
            .or_default()
            .add(delta, first_observation);
        self.save()
    }

    pub(crate) fn summary(&self, profile_id: &str) -> ReliabilitySummary {
        let profile = self.stored.profiles.get(profile_id);
        let modes = ALL_PROTOCOLS
            .into_iter()
            .map(|protocol| {
                ModeSummary::from_totals(
                    protocol,
                    profile
                        .and_then(|profile| profile.modes.get(protocol_key(protocol)))
                        .cloned()
                        .unwrap_or_default(),
                )
            })
            .collect::<Vec<_>>();
        let mut eligible = modes
            .iter()
            .filter(|mode| mode.enough_data)
            .collect::<Vec<_>>();
        eligible.sort_by(|left, right| {
            right
                .stability_score
                .total_cmp(&left.stability_score)
                .then_with(|| left.average_rtt_ms.cmp(&right.average_rtt_ms))
                .then_with(|| right.observed_seconds.cmp(&left.observed_seconds))
        });
        ReliabilitySummary {
            best_protocol: (eligible.len() >= 2).then(|| eligible[0].protocol.clone()),
            eligible_modes: eligible.len(),
            modes,
        }
    }

    pub(crate) fn clear_profile(&mut self, profile_id: &str) -> Result<(), String> {
        self.stored.profiles.remove(profile_id);
        if let Some(active) = self
            .active
            .as_mut()
            .filter(|active| active.profile_id == profile_id)
        {
            active.observed = false;
        }
        self.save()
    }

    fn save(&self) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let parent = path
            .parent()
            .ok_or_else(|| "У файла диагностики нет родительского каталога".to_owned())?;
        if !parent.exists() {
            let mut builder = DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(parent).map_err(display_error)?;
        }
        let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
        let result = (|| {
            let bytes = serde_json::to_vec_pretty(&self.stored).map_err(display_error)?;
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(display_error)?;
            file.write_all(&bytes).map_err(display_error)?;
            file.sync_all().map_err(display_error)?;
            fs::rename(&temporary, path).map_err(display_error)
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReliabilitySummary {
    best_protocol: Option<String>,
    eligible_modes: usize,
    modes: Vec<ModeSummary>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ModeSummary {
    protocol: String,
    label: &'static str,
    sessions: u64,
    observed_seconds: u64,
    outgoing_packets: u64,
    incoming_packets: u64,
    outgoing_drops: u64,
    keepalives_sent: u64,
    keepalive_responses: u64,
    keepalive_timeouts: u64,
    loss_percent: f64,
    average_rtt_ms: u64,
    max_rtt_ms: u64,
    reconnects: u64,
    reconnects_per_hour: f64,
    reconnect_failures: u64,
    peer_unreachable: u64,
    migrations: u64,
    stability_score: f64,
    enough_data: bool,
    updated_at: u64,
}

impl ModeSummary {
    fn from_totals(protocol: ClientProtocol, totals: ModeTotals) -> Self {
        // Exclude the latest in-flight probes from the denominator: only a
        // response or an elapsed response budget makes a keepalive conclusive.
        let completed_keepalives = totals
            .keepalive_responses
            .saturating_add(totals.keepalive_timeouts);
        let loss_percent = percentage(totals.keepalive_timeouts, completed_keepalives);
        let reconnects_per_hour = hourly(totals.reconnects, totals.observed_seconds);
        let reconnect_failures_per_hour =
            hourly(totals.reconnect_failures, totals.observed_seconds);
        let peer_unreachable_per_hour = hourly(totals.peer_unreachable, totals.observed_seconds);
        let average_rtt_ms = totals
            .keepalive_rtt_total_ms
            .checked_div(totals.keepalive_rtt_samples)
            .unwrap_or(0);
        let stability_penalty = loss_percent * 3.5
            + reconnects_per_hour * 8.0
            + reconnect_failures_per_hour * 12.0
            + peer_unreachable_per_hour * 2.0;
        Self {
            protocol: protocol_key(protocol).to_owned(),
            label: protocol_label(protocol),
            sessions: totals.sessions,
            observed_seconds: totals.observed_seconds,
            outgoing_packets: totals.outgoing_packets,
            incoming_packets: totals.incoming_packets,
            outgoing_drops: totals.outgoing_drops,
            keepalives_sent: totals.keepalives_sent,
            keepalive_responses: totals.keepalive_responses,
            keepalive_timeouts: totals.keepalive_timeouts,
            loss_percent,
            average_rtt_ms,
            max_rtt_ms: totals.max_keepalive_rtt_ms,
            reconnects: totals.reconnects,
            reconnects_per_hour,
            reconnect_failures: totals.reconnect_failures,
            peer_unreachable: totals.peer_unreachable,
            migrations: totals.migrations,
            stability_score: (100.0 - stability_penalty).clamp(0.0, 100.0),
            enough_data: totals.observed_seconds >= MINIMUM_OBSERVATION_SECONDS
                && totals.keepalives_sent >= MINIMUM_KEEPALIVES,
            updated_at: totals.updated_at,
        }
    }
}

const ALL_PROTOCOLS: [ClientProtocol; 4] = [
    ClientProtocol::Legacy,
    ClientProtocol::MorphQuiet,
    ClientProtocol::MorphBalanced,
    ClientProtocol::MorphParanoid,
];

const fn protocol_key(protocol: ClientProtocol) -> &'static str {
    match protocol {
        ClientProtocol::Legacy => "legacy",
        ClientProtocol::MorphQuiet => "morph_quiet",
        ClientProtocol::MorphBalanced => "morph_balanced",
        ClientProtocol::MorphParanoid => "morph_paranoid",
    }
}

const fn protocol_label(protocol: ClientProtocol) -> &'static str {
    match protocol {
        ClientProtocol::Legacy => "Legacy",
        ClientProtocol::MorphQuiet => "Morph Quiet",
        ClientProtocol::MorphBalanced => "Morph Balanced",
        ClientProtocol::MorphParanoid => "Morph Paranoid",
    }
}

fn diagnostics_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|directory| {
        directory
            .join("MouseVPN")
            .join("diagnostics")
            .join("reliability-v1.json")
    })
}

#[allow(clippy::cast_precision_loss)]
fn percentage(value: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        value as f64 * 100.0 / total as f64
    }
}

#[allow(clippy::cast_precision_loss)]
fn hourly(value: u64, seconds: u64) -> f64 {
    if seconds == 0 {
        0.0
    } else {
        value as f64 * 3_600.0 / seconds as f64
    }
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::{ClientProtocol, ReliabilityMonitor, RuntimeMetrics, StoredDiagnostics};

    fn monitor() -> ReliabilityMonitor {
        ReliabilityMonitor {
            path: None,
            stored: StoredDiagnostics {
                version: 1,
                ..StoredDiagnostics::default()
            },
            active: None,
        }
    }

    #[test]
    fn accumulates_deltas_without_counting_snapshots_twice() {
        let mut monitor = monitor();
        monitor.begin("profile".to_owned(), ClientProtocol::MorphBalanced);
        monitor
            .observe(
                "profile",
                ClientProtocol::MorphBalanced,
                RuntimeMetrics {
                    uptime_seconds: 300,
                    keepalives_sent: 30,
                    keepalive_responses: 29,
                    keepalive_timeouts: 1,
                    keepalive_rtt_total_ms: 4_350,
                    keepalive_rtt_samples: 29,
                    max_keepalive_rtt_ms: 210,
                    ..RuntimeMetrics::default()
                },
            )
            .unwrap();
        monitor
            .observe(
                "profile",
                ClientProtocol::MorphBalanced,
                RuntimeMetrics {
                    uptime_seconds: 305,
                    keepalives_sent: 30,
                    keepalive_responses: 29,
                    keepalive_timeouts: 1,
                    keepalive_rtt_total_ms: 4_350,
                    keepalive_rtt_samples: 29,
                    max_keepalive_rtt_ms: 210,
                    ..RuntimeMetrics::default()
                },
            )
            .unwrap();
        let mode = &monitor.summary("profile").modes[2];
        assert_eq!(mode.sessions, 1);
        assert_eq!(mode.observed_seconds, 305);
        assert_eq!(mode.keepalives_sent, 30);
        assert_eq!(mode.keepalive_timeouts, 1);
        assert_eq!(mode.average_rtt_ms, 150);
        assert!(mode.enough_data);
    }

    #[test]
    fn recommends_only_after_two_modes_have_enough_data() {
        let mut monitor = monitor();
        for (protocol, losses) in [
            (ClientProtocol::MorphBalanced, 0),
            (ClientProtocol::MorphParanoid, 3),
        ] {
            monitor.begin("profile".to_owned(), protocol);
            monitor
                .observe(
                    "profile",
                    protocol,
                    RuntimeMetrics {
                        uptime_seconds: 600,
                        keepalives_sent: 60,
                        keepalive_responses: 60 - losses,
                        keepalive_timeouts: losses,
                        keepalive_rtt_total_ms: 9_000,
                        keepalive_rtt_samples: 60 - losses,
                        ..RuntimeMetrics::default()
                    },
                )
                .unwrap();
        }
        let summary = monitor.summary("profile");
        assert_eq!(summary.eligible_modes, 2);
        assert_eq!(summary.best_protocol.as_deref(), Some("morph_balanced"));
    }
}
