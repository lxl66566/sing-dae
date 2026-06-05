use std::fs;

use sing_dae::dae::{ast, parser, serializer};

#[test]
fn serialize_simple_config() {
    let config = ast::DaeConfig {
        global: vec![
            ast::KeyValue {
                key: "log_level".into(),
                value: "info".into(),
            },
            ast::KeyValue {
                key: "dial_mode".into(),
                value: "domain".into(),
            },
        ],
        nodes: vec![ast::Entry::Tagged {
            key: "my-node".into(),
            value: "hy2://pass@host:443".into(),
        }],
        groups: vec![ast::GroupDef {
            name: "proxy".into(),
            filters: vec![],
            policy: ast::PolicyDef::MinMovingAvg,
            extra: vec![],
        }],
        routing: ast::RoutingSection {
            rules: vec![ast::RoutingRule {
                condition: "domain(geosite:cn)".into(),
                target: "direct".into(),
            }],
            fallback: Some("proxy".into()),
        },
        ..Default::default()
    };

    let text = serializer::serialize(&config);
    assert!(text.contains("global {"));
    assert!(text.contains("log_level: info"));
    assert!(text.contains("node {"));
    assert!(text.contains("my-node: 'hy2://pass@host:443'"));
    assert!(text.contains("policy: min_moving_avg"));
    assert!(text.contains("domain(geosite:cn) -> direct"));
    assert!(text.contains("fallback: proxy"));
}

#[test]
fn roundtrip_fixture() {
    let input = fs::read_to_string("assets/absx.dae").expect("read");
    let config = parser::parse(&input).expect("parse");

    let output = serializer::serialize(&config);
    let reparsed = parser::parse(&output).expect("re-parse");

    assert_eq!(config.nodes.len(), reparsed.nodes.len());
    assert_eq!(config.groups.len(), reparsed.groups.len());
    assert_eq!(config.routing.rules.len(), reparsed.routing.rules.len());
    assert_eq!(config.dns.upstream.len(), reparsed.dns.upstream.len());
    assert_eq!(
        config.dns.request_rules.len(),
        reparsed.dns.request_rules.len()
    );
    assert_eq!(config.dns.fallback, reparsed.dns.fallback);

    for (a, b) in config.groups.iter().zip(reparsed.groups.iter()) {
        assert_eq!(a.name, b.name);
    }

    for (a, b) in config
        .routing
        .rules
        .iter()
        .zip(reparsed.routing.rules.iter())
    {
        assert_eq!(a.condition.trim(), b.condition.trim());
        assert_eq!(a.target, b.target);
    }
}
