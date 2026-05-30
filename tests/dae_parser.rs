use std::fs;

use sing_dae::dae::{ast, parser, serializer};

#[test]
fn parse_fixture_dae() {
    let input = fs::read_to_string("assets/absx.dae").expect("read fixture");
    let config = parser::parse(&input).expect("parse failed");

    assert!(!config.global.is_empty(), "global should have entries");
    assert!(
        config.global.iter().any(|kv| kv.key == "log_level"),
        "should have log_level"
    );
    assert!(!config.nodes.is_empty(), "should have nodes");
    assert!(!config.groups.is_empty(), "should have groups");
    assert!(!config.routing.rules.is_empty(), "should have routing rules");
    assert_eq!(config.routing.fallback.as_deref(), Some("proxy"));
}

#[test]
fn parse_global_section() {
    let config = parser::parse(
        "global {\n    tproxy_port: 12345\n    log_level: info\n    dial_mode: domain\n    allow_insecure: false\n}",
    )
    .expect("parse failed");

    assert_eq!(config.global.len(), 4);
    let kv_map: std::collections::HashMap<&str, &str> =
        config.global.iter().map(|kv| (kv.key.as_str(), kv.value.as_str())).collect();
    assert_eq!(kv_map.get("tproxy_port").copied(), Some("12345"));
    assert_eq!(kv_map.get("log_level").copied(), Some("info"));
    assert_eq!(kv_map.get("dial_mode").copied(), Some("domain"));
}

#[test]
fn parse_node_section() {
    let config = parser::parse(
        "node {\n    my-node: 'hy2://pass@host:443/?sni=host#name'\n}",
    )
    .expect("parse failed");

    assert_eq!(config.nodes.len(), 1);
    match &config.nodes[0] {
        ast::Entry::Tagged { key, value } => {
            assert_eq!(key, "my-node");
            assert!(value.starts_with("hy2://"));
        }
        ast::Entry::Untagged(_) => panic!("expected tagged entry"),
    }
}

#[test]
fn parse_group_section() {
    let config = parser::parse(
        "group {\n    proxy {\n        policy: min_moving_avg\n    }\n    no_hk {\n        filter: !name(regex: '^hk')\n        policy: min_moving_avg\n    }\n}",
    )
    .expect("parse failed");

    assert_eq!(config.groups.len(), 2);
    assert_eq!(config.groups[0].name, "proxy");
    assert!(matches!(config.groups[0].policy, ast::PolicyDef::MinMovingAvg));

    assert_eq!(config.groups[1].name, "no_hk");
    assert_eq!(config.groups[1].filters.len(), 1);
    assert!(config.groups[1].filters[0].expression.contains("regex"));
}
#[test]
fn parse_routing_section() {
    let config = parser::parse(
        "routing {\n    pname(NetworkManager) -> must_direct\n    dip(geoip:private) -> direct\n    domain(geosite:cn) -> direct\n    fallback: proxy\n}",
    )
    .expect("parse failed");

    assert_eq!(config.routing.rules.len(), 3);
    assert_eq!(config.routing.fallback.as_deref(), Some("proxy"));
    assert!(config.routing.rules[0].condition.contains("pname"));
    assert_eq!(config.routing.rules[0].target, "must_direct");
}

#[test]
fn parse_dns_section() {
    let config = parser::parse(
        "dns {\n    ipversion_prefer: 4\n    upstream {\n        alidns: 'udp://223.5.5.5:53'\n    }\n    routing {\n        request {\n            qname(geosite:cn) -> alidns\n            fallback: cloudflare\n        }\n    }\n}",
    )
    .expect("parse failed");

    assert_eq!(config.dns.entries.len(), 1);
    assert_eq!(config.dns.upstream.len(), 1);
    assert_eq!(config.dns.request_rules.len(), 1);
}

#[test]
fn parse_full_dae() {
    let input = fs::read_to_string("assets/full.dae").expect("read full.dae");
    let config = parser::parse(&input).expect("parse full.dae failed");

    assert!(!config.global.is_empty(), "global should have entries");
    assert!(!config.subscriptions.is_empty(), "subscriptions should have entries");
    assert!(!config.nodes.is_empty(), "nodes should have entries");
    assert!(!config.dns.upstream.is_empty(), "dns upstream should have entries");
    assert!(!config.groups.is_empty(), "groups should have entries");
    assert!(!config.routing.rules.is_empty(), "routing rules should exist");
    assert!(config.routing.fallback.is_some(), "routing fallback should exist");
}

#[test]
fn parse_subscription_untagged() {
    let config = parser::parse(
        "subscription {\n    my_sub: 'https://example.com/link'\n    'https://example.com/no_tag'\n}",
    )
    .expect("parse failed");

    assert_eq!(config.subscriptions.len(), 2);
}

#[test]
fn parse_full_dae_roundtrip() {
    let input = fs::read_to_string("assets/full.dae").expect("read full.dae");
    let config = parser::parse(&input).expect("parse failed");

    let output = serializer::serialize(&config);
    let reparsed = parser::parse(&output).expect("re-parse failed");

    assert_eq!(config.subscriptions.len(), reparsed.subscriptions.len());
    assert_eq!(config.nodes.len(), reparsed.nodes.len());
    assert_eq!(config.groups.len(), reparsed.groups.len());
    assert_eq!(config.routing.rules.len(), reparsed.routing.rules.len());
    assert_eq!(config.dns.upstream.len(), reparsed.dns.upstream.len());
}
