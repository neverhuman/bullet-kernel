//! The nftables ruleset installed inside the provider namespace, its digest,
//! and parsers for the kernel's own view of it (`nft list ...`).

use crate::error::{EgressCode, EgressError};
use std::net::Ipv4Addr;

/// nftables table name.
pub const TABLE: &str = "bf_egress";
/// Named counter incremented for every refused DNS packet (UDP/TCP 53).
pub const COUNTER_DNS: &str = "dns_rejected";
/// Named counter incremented for every other refused packet.
pub const COUNTER_OTHER: &str = "other_rejected";

/// Ruleset text fed to `nft -f -` inside the namespace.
///
/// Chain policy is `drop`; the explicit counted `reject` rules exist so a
/// sandboxed CLI fails immediately (ECONNREFUSED / EPERM) instead of hanging
/// on silently dropped packets, and so the receipt can show counter deltas.
#[must_use]
pub fn ruleset_text(gateway: Ipv4Addr, proxy_port: u16) -> String {
    format!(
        "# bullet-harness-egress: default-drop egress inside the provider namespace.\n\
         # Only loopback and TCP to the host-side CONNECT proxy at {gateway}:{proxy_port} may leave.\n\
         table inet {TABLE} {{\n\
         \x20 counter {COUNTER_DNS} {{}}\n\
         \x20 counter {COUNTER_OTHER} {{}}\n\
         \x20 chain output {{\n\
         \x20   type filter hook output priority filter; policy drop;\n\
         \x20   oif \"lo\" accept\n\
         \x20   ip daddr {gateway} tcp dport {proxy_port} accept\n\
         \x20   udp dport 53 counter name \"{COUNTER_DNS}\" reject\n\
         \x20   tcp dport 53 counter name \"{COUNTER_DNS}\" reject with tcp reset\n\
         \x20   meta l4proto tcp counter name \"{COUNTER_OTHER}\" reject with tcp reset\n\
         \x20   counter name \"{COUNTER_OTHER}\" reject with icmpx type admin-prohibited\n\
         \x20 }}\n\
         }}\n"
    )
}

/// BLAKE3 hex of the ruleset text bytes.
#[must_use]
pub fn ruleset_digest(text: &str) -> String {
    blake3::hash(text.as_bytes()).to_hex().to_string()
}

/// Verify the kernel's `nft list ruleset` output shows exactly the intended
/// shape: our table, output policy drop, and only the two accept rules.
///
/// # Errors
///
/// `EGRESS_RULESET_FAILED` naming the first missing or surplus element.
pub fn verify_listing(
    listing: &str,
    gateway: Ipv4Addr,
    proxy_port: u16,
) -> Result<(), EgressError> {
    let required = [
        format!("table inet {TABLE} {{"),
        "type filter hook output priority filter; policy drop;".to_string(),
        "oif \"lo\" accept".to_string(),
        format!("ip daddr {gateway} tcp dport {proxy_port} accept"),
        format!("udp dport 53 counter name \"{COUNTER_DNS}\" reject"),
        format!("tcp dport 53 counter name \"{COUNTER_DNS}\" reject with tcp reset"),
        format!("counter name \"{COUNTER_OTHER}\" reject"),
    ];
    for needle in &required {
        if !listing.contains(needle.as_str()) {
            return Err(EgressError::new(
                EgressCode::RulesetFailed,
                format!("installed ruleset lacks {needle:?}"),
            ));
        }
    }
    let accepts = listing
        .lines()
        .filter(|line| line.trim_end().ends_with(" accept"))
        .count();
    if accepts != 2 {
        return Err(EgressError::new(
            EgressCode::RulesetFailed,
            format!("installed ruleset has {accepts} accept rules, expected 2"),
        ));
    }
    if listing.contains("policy accept") {
        return Err(EgressError::new(
            EgressCode::RulesetFailed,
            "installed ruleset contains a policy accept chain",
        ));
    }
    let tables = listing.matches("\ntable ").count() + usize::from(listing.starts_with("table "));
    if tables != 1 {
        return Err(EgressError::new(
            EgressCode::RulesetFailed,
            format!("namespace has {tables} tables, expected exactly 1"),
        ));
    }
    Ok(())
}

/// Packet counts of the two named counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CounterSnapshot {
    /// Packets refused by the DNS rules.
    pub dns: u64,
    /// Packets refused by the catch-all rules.
    pub other: u64,
}

/// Parse `nft -j list counters table inet bf_egress` output.
///
/// # Errors
///
/// `EGRESS_RULESET_FAILED` when the JSON is unusable or a counter is missing.
pub fn parse_counters(json: &str) -> Result<CounterSnapshot, EgressError> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|err| {
        EgressError::new(EgressCode::RulesetFailed, format!("counter json: {err}"))
    })?;
    let mut snapshot = CounterSnapshot::default();
    let mut seen = 0;
    for item in value["nftables"].as_array().into_iter().flatten() {
        let counter = &item["counter"];
        if counter["table"] != TABLE {
            continue;
        }
        let packets = counter["packets"].as_u64().unwrap_or(0);
        match counter["name"].as_str() {
            Some(COUNTER_DNS) => {
                snapshot.dns = packets;
                seen += 1;
            }
            Some(COUNTER_OTHER) => {
                snapshot.other = packets;
                seen += 1;
            }
            _ => {}
        }
    }
    if seen != 2 {
        return Err(EgressError::new(
            EgressCode::RulesetFailed,
            format!("expected 2 named counters, found {seen}"),
        ));
    }
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace::GATEWAY;

    const LISTING: &str = "table inet bf_egress {\n\tcounter dns_rejected {\n\t\tpackets 0 bytes 0\n\t}\n\n\tcounter other_rejected {\n\t\tpackets 0 bytes 0\n\t}\n\n\tchain output {\n\t\ttype filter hook output priority filter; policy drop;\n\t\toif \"lo\" accept\n\t\tip daddr 10.0.2.2 tcp dport 65000 accept\n\t\tudp dport 53 counter name \"dns_rejected\" reject\n\t\ttcp dport 53 counter name \"dns_rejected\" reject with tcp reset\n\t\tmeta l4proto tcp counter name \"other_rejected\" reject with tcp reset\n\t\tcounter name \"other_rejected\" reject with icmpx admin-prohibited\n\t}\n}\n";

    #[test]
    fn text_names_only_loopback_and_the_proxy_port() {
        let text = ruleset_text(GATEWAY, 43111);
        assert!(text.contains("policy drop;"));
        assert!(text.contains("ip daddr 10.0.2.2 tcp dport 43111 accept"));
        assert_eq!(text.matches(" accept").count(), 2);
        assert!(!text.contains("policy accept"));
        assert_eq!(
            ruleset_digest(&text),
            ruleset_digest(&ruleset_text(GATEWAY, 43111))
        );
        assert_ne!(
            ruleset_digest(&text),
            ruleset_digest(&ruleset_text(GATEWAY, 43112))
        );
    }

    #[test]
    fn listing_verification_accepts_the_kernel_view_and_rejects_tampering() {
        verify_listing(LISTING, GATEWAY, 65000).unwrap();
        assert!(verify_listing(LISTING, GATEWAY, 65001).is_err());
        let extra_accept = LISTING.replace(
            "oif \"lo\" accept",
            "oif \"lo\" accept\n\t\tip daddr 10.0.2.2 tcp dport 8787 accept",
        );
        assert!(verify_listing(&extra_accept, GATEWAY, 65000).is_err());
        let policy_accept = LISTING.replace("policy drop", "policy accept");
        assert!(verify_listing(&policy_accept, GATEWAY, 65000).is_err());
        let two_tables = format!("{LISTING}table inet other {{\n}}\n");
        assert!(verify_listing(&two_tables, GATEWAY, 65000).is_err());
        assert_eq!(
            verify_listing("", GATEWAY, 65000).unwrap_err().code,
            EgressCode::RulesetFailed
        );
    }

    #[test]
    fn counters_parse_from_nft_json() {
        let json = r#"{"nftables": [{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}}, {"counter": {"family": "inet", "name": "dns_rejected", "table": "bf_egress", "handle": 2, "packets": 4, "bytes": 238}}, {"counter": {"family": "inet", "name": "other_rejected", "table": "bf_egress", "handle": 3, "packets": 9, "bytes": 556}}]}"#;
        assert_eq!(
            parse_counters(json).unwrap(),
            CounterSnapshot { dns: 4, other: 9 }
        );
        assert!(parse_counters(r#"{"nftables": []}"#).is_err());
        assert!(parse_counters("not json").is_err());
    }
}
