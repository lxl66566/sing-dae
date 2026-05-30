use std::fs;

use sing_dae::convert::{dae_to_sing, sing_to_dae};
use sing_dae::dae::parser;

#[test]
fn dae_to_sing_from_fixture() {
    let input = fs::read_to_string("assets/absx.dae").expect("read");
    let dae_config = parser::parse(&input).expect("parse dae");

    let sing_config = dae_to_sing::convert(&dae_config).expect("convert to sing");

    assert!(sing_config.log.is_some());
    assert!(!sing_config.outbounds.is_empty());
    assert!(sing_config.route.is_some());

    let has_hy2 = sing_config
        .outbounds
        .iter()
        .any(|ob| ob.outbound_type == "hysteria2");
    assert!(has_hy2, "should have at least one hysteria2 outbound");

    let has_direct = sing_config
        .outbounds
        .iter()
        .any(|ob| ob.tag.as_deref() == Some("direct"));
    assert!(has_direct, "should have a direct outbound");

    let route = sing_config.route.as_ref().unwrap();
    assert!(!route.rules.is_empty());
    assert_eq!(route.final_outbound.as_deref(), Some("proxy"));
}

#[test]
fn sing_to_dae_from_fixture() {
    let input = fs::read_to_string("assets/config.json").expect("read");
    let sing_config: sing_dae::singbox::config::SingBoxConfig =
        serde_json::from_str(&input).expect("parse sing");

    let dae_config = sing_to_dae::convert(&sing_config).expect("convert to dae");

    assert!(!dae_config.nodes.is_empty(), "should have nodes");
    assert!(!dae_config.routing.rules.is_empty(), "should have routing rules");
    assert!(dae_config.routing.fallback.is_some(), "should have fallback");
}

#[test]
fn dae_roundtrip_via_sing() {
    let input = fs::read_to_string("assets/absx.dae").expect("read");
    let original = parser::parse(&input).expect("parse dae");

    let sing = dae_to_sing::convert(&original).expect("to sing");

    let dae2 = sing_to_dae::convert(&sing).expect("back to dae");

    assert_eq!(original.nodes.len(), dae2.nodes.len());
    assert_eq!(original.routing.fallback, dae2.routing.fallback);
}

#[test]
fn sing_roundtrip_via_dae() {
    let input = fs::read_to_string("assets/config.json").expect("read");
    let original: sing_dae::singbox::config::SingBoxConfig =
        serde_json::from_str(&input).expect("parse sing");

    let dae = sing_to_dae::convert(&original).expect("to dae");

    let sing2 = dae_to_sing::convert(&dae).expect("back to sing");

    assert_eq!(
        original.outbounds.len(),
        sing2.outbounds.len(),
        "outbound count should be preserved"
    );
}
