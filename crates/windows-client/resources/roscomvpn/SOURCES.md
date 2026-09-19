# Geo-direct routing data

MouseVPN vendors snapshots of public routing data from:

- hydraponique/roscomvpn-geoip — `release/text/direct.txt`
- hydraponique/roscomvpn-geosite — `data/category-ru`
- hydraponique/roscomvpn-geosite — `data/whitelist`

The data is used only for outbound split-tunnel classification. MouseVPN does not modify
Windows DNS configuration. The DNS watcher is WinDivert sniff-only and observes ordinary
UDP/53 responses to correlate direct domains with their resolved IP addresses.

Upstream data is intentionally vendored rather than downloaded at runtime so routing does
not depend on GitHub/CDN availability while the VPN is starting.
