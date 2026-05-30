use std::fs;

use sing_dae::singbox::config::SingBoxConfig;

#[test]
fn deserialize_fixture_config() {
    let json = fs::read_to_string("assets/config.json").expect("read fixture");
    let config: SingBoxConfig = serde_json::from_str(&json).expect("deserialize");
    assert!(config.log.is_some());
    assert!(config.dns.is_some());
    assert!(config.route.is_some());
    assert!(!config.inbounds.is_empty());
    assert!(!config.outbounds.is_empty());
}

#[test]
fn roundtrip_fixture_config() {
    let json = fs::read_to_string("assets/config.json").expect("read fixture");
    let config: SingBoxConfig = serde_json::from_str(&json).expect("deserialize");
    let re_json = serde_json::to_string_pretty(&config).expect("serialize");
    let config2: SingBoxConfig = serde_json::from_str(&re_json).expect("re-deserialize");
    assert_eq!(config.outbounds.len(), config2.outbounds.len());
    assert_eq!(config.route.unwrap().rules.len(), config2.route.unwrap().rules.len());
}
