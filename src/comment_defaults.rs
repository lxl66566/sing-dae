use crate::dae::ast::{DaeConfig, DnsSection, Entry, GroupDef, KeyValue, RoutingSection};

#[cfg(feature = "comment-defaults")]
pub fn extract_dae_comment_json(text: &str) -> Option<serde_json::Value> {
    extract_comment_json(text, "#")
}

#[cfg(feature = "comment-defaults")]
pub fn extract_singbox_comment_dae(text: &str) -> Option<DaeConfig> {
    let content = extract_comment_text(text, "//")?;
    let config = crate::dae::parser::parse(&content).ok()?;
    if is_empty_config(&config) {
        return None;
    }
    Some(config)
}

#[cfg(feature = "comment-defaults")]
pub fn deep_merge(base: serde_json::Value, overrides: serde_json::Value) -> serde_json::Value {
    match (base, overrides) {
        (serde_json::Value::Object(mut base_map), serde_json::Value::Object(over_map)) => {
            for (key, val) in over_map {
                match base_map.entry(key) {
                    serde_json::map::Entry::Occupied(mut e) => {
                        *e.get_mut() = deep_merge(e.get().clone(), val);
                    }
                    serde_json::map::Entry::Vacant(e) => {
                        e.insert(val);
                    }
                }
            }
            serde_json::Value::Object(base_map)
        }
        (_, over) => over,
    }
}

pub fn merge_dae_config(base: &mut DaeConfig, overrides: &DaeConfig) {
    merge_key_values(&mut base.global, &overrides.global);
    merge_entries(&mut base.subscriptions, &overrides.subscriptions);
    merge_entries(&mut base.nodes, &overrides.nodes);
    merge_dns_section(&mut base.dns, &overrides.dns);
    merge_groups(&mut base.groups, &overrides.groups);
    merge_routing_section(&mut base.routing, &overrides.routing);
}

#[cfg(feature = "comment-defaults")]
fn extract_comment_json(text: &str, prefix: &str) -> Option<serde_json::Value> {
    let comment_lines = collect_comment_lines(text, prefix);
    if comment_lines.is_empty() {
        return None;
    }

    let start_idx = comment_lines.iter().position(|l| {
        let t = l.trim();
        t.starts_with('{') || t.starts_with('[')
    })?;

    let mut buffer = String::new();
    for line in &comment_lines[start_idx..] {
        if !buffer.is_empty() {
            buffer.push('\n');
        }
        buffer.push_str(line);
        if let Ok(value) = serde_json::from_str(&buffer) {
            return Some(value);
        }
    }
    None
}

#[cfg(feature = "comment-defaults")]
fn extract_comment_text(text: &str, prefix: &str) -> Option<String> {
    let lines = collect_comment_lines(text, prefix);
    if lines.is_empty() {
        return None;
    }
    Some(lines.join("\n"))
}

#[cfg(feature = "comment-defaults")]
fn collect_comment_lines<'a>(text: &'a str, prefix: &str) -> Vec<&'a str> {
    let mut comment_lines = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() && comment_lines.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            comment_lines.push(rest);
        } else {
            break;
        }
    }
    comment_lines
}

#[cfg(feature = "comment-defaults")]
fn is_empty_config(config: &DaeConfig) -> bool {
    config.global.is_empty()
        && config.subscriptions.is_empty()
        && config.nodes.is_empty()
        && config.dns.entries.is_empty()
        && config.dns.upstream.is_empty()
        && config.dns.request_rules.is_empty()
        && config.dns.response_rules.is_empty()
        && config.groups.is_empty()
        && config.routing.rules.is_empty()
        && config.routing.fallback.is_none()
}

fn merge_key_values(base: &mut Vec<KeyValue>, overrides: &[KeyValue]) {
    for kv in overrides {
        if let Some(existing) = base.iter_mut().find(|k| k.key == kv.key) {
            existing.value.clone_from(&kv.value);
        } else {
            base.push(kv.clone());
        }
    }
}

fn merge_entries(base: &mut Vec<Entry>, overrides: &[Entry]) {
    for entry in overrides {
        match entry {
            Entry::Tagged { key, .. } => {
                if let Some(existing) = base
                    .iter_mut()
                    .find(|e| matches!(e, Entry::Tagged { key: k, .. } if k == key))
                {
                    *existing = entry.clone();
                } else {
                    base.push(entry.clone());
                }
            }
            Entry::Untagged(_) => {
                base.push(entry.clone());
            }
        }
    }
}

fn merge_dns_section(base: &mut DnsSection, overrides: &DnsSection) {
    merge_key_values(&mut base.entries, &overrides.entries);
    merge_key_values(&mut base.upstream, &overrides.upstream);
    if !overrides.request_rules.is_empty() {
        let mut rules = overrides.request_rules.clone();
        rules.append(&mut base.request_rules);
        base.request_rules = rules;
    }
    if !overrides.response_rules.is_empty() {
        let mut rules = overrides.response_rules.clone();
        rules.append(&mut base.response_rules);
        base.response_rules = rules;
    }
}

fn merge_groups(base: &mut Vec<GroupDef>, overrides: &[GroupDef]) {
    for group in overrides {
        if let Some(existing) = base.iter_mut().find(|g| g.name == group.name) {
            existing.filters = group.filters.clone();
            existing.policy = group.policy.clone();
            merge_key_values(&mut existing.extra, &group.extra);
        } else {
            base.push(group.clone());
        }
    }
}

fn merge_routing_section(base: &mut RoutingSection, overrides: &RoutingSection) {
    if !overrides.rules.is_empty() {
        let mut rules = overrides.rules.clone();
        rules.append(&mut base.rules);
        base.rules = rules;
    }
    if overrides.fallback.is_some() {
        base.fallback.clone_from(&overrides.fallback);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dae::ast::{DaeConfig, PolicyDef};

    #[test]
    fn extract_dae_multiline_json() {
        let input = r#"#{
#  "inbounds": [
#    {
#      "type": "mixed",
#      "tag": "mixed",
#      "listen": "127.0.0.1",
#      "listen_port": 10450
#    }
#  ]
#}
global {
    log_level: debug
}"#;
        let val = extract_dae_comment_json(input).unwrap();
        assert_eq!(val["inbounds"][0]["listen_port"], 10450);
    }

    #[test]
    fn extract_dae_no_comment_block() {
        let input = "global {\n    log_level: debug\n}";
        assert!(extract_dae_comment_json(input).is_none());
    }

    #[test]
    fn extract_dae_invalid_json_returns_none() {
        let input = "# This is not JSON\n# Another line\nglobal {}";
        assert!(extract_dae_comment_json(input).is_none());
    }

    #[test]
    fn extract_singbox_dae_dsl() {
        let input = "//global {\n//    tproxy_port: 54321\n//}\n{\"log\": {}}";
        let config = extract_singbox_comment_dae(input).unwrap();
        assert_eq!(config.global[0].key, "tproxy_port");
        assert_eq!(config.global[0].value, "54321");
    }

    #[test]
    fn extract_singbox_dae_multiple_sections() {
        let input = "//global {\n//    tproxy_port: 54321\n//}\n//routing {\n//    domain(geosite:cn) -> direct\n//    fallback: proxy\n//}\n{\"log\": {}}";
        let config = extract_singbox_comment_dae(input).unwrap();
        assert_eq!(config.global[0].key, "tproxy_port");
        assert_eq!(config.routing.rules.len(), 1);
        assert_eq!(config.routing.fallback.as_deref(), Some("proxy"));
    }

    #[test]
    fn extract_singbox_empty_comment_returns_none() {
        let input = "// Just a comment\n{\"log\": {}}";
        assert!(extract_singbox_comment_dae(input).is_none());
    }

    #[test]
    fn extract_singbox_no_comment_returns_none() {
        let input = "{\"log\": {}}";
        assert!(extract_singbox_comment_dae(input).is_none());
    }

    #[test]
    fn extract_skips_leading_blank_lines() {
        let input = "\n\n#{\"key\": 1}\nglobal {}";
        let val = extract_dae_comment_json(input).unwrap();
        assert_eq!(val["key"], 1);
    }

    #[test]
    fn deep_merge_objects_recursive() {
        let base = serde_json::json!({
            "log": {"level": "info", "timestamp": true},
            "dns": {"servers": [{"tag": "a"}]}
        });
        let overrides = serde_json::json!({
            "log": {"level": "debug"},
            "experimental": {"cache_file": {"enabled": true}}
        });
        let result = deep_merge(base, overrides);
        assert_eq!(result["log"]["level"], "debug");
        assert_eq!(result["log"]["timestamp"], true);
        assert_eq!(result["experimental"]["cache_file"]["enabled"], true);
        assert!(result["dns"]["servers"].is_array());
    }

    #[test]
    fn deep_merge_array_replaced() {
        let base = serde_json::json!({"inbounds": [{"type": "mixed", "port": 1080}]});
        let overrides = serde_json::json!({"inbounds": [{"type": "tun"}]});
        let result = deep_merge(base, overrides);
        assert_eq!(result["inbounds"].as_array().unwrap().len(), 1);
        assert_eq!(result["inbounds"][0]["type"], "tun");
    }

    #[test]
    fn deep_merge_primitive_overrides() {
        let base = serde_json::json!({"a": 1, "b": "hello"});
        let overrides = serde_json::json!({"a": 2});
        let result = deep_merge(base, overrides);
        assert_eq!(result["a"], 2);
        assert_eq!(result["b"], "hello");
    }

    #[test]
    fn merge_global_by_key() {
        let mut base = DaeConfig {
            global: vec![
                KeyValue {
                    key: "tproxy_port".into(),
                    value: "12345".into(),
                },
                KeyValue {
                    key: "dial_mode".into(),
                    value: "domain".into(),
                },
            ],
            ..DaeConfig::default()
        };
        let overrides = DaeConfig {
            global: vec![
                KeyValue {
                    key: "tproxy_port".into(),
                    value: "54321".into(),
                },
                KeyValue {
                    key: "allow_insecure".into(),
                    value: "true".into(),
                },
            ],
            ..DaeConfig::default()
        };
        merge_dae_config(&mut base, &overrides);
        assert_eq!(base.global.len(), 3);
        let tproxy = base
            .global
            .iter()
            .find(|kv| kv.key == "tproxy_port")
            .unwrap();
        assert_eq!(tproxy.value, "54321");
        let dial = base.global.iter().find(|kv| kv.key == "dial_mode").unwrap();
        assert_eq!(dial.value, "domain");
        let insecure = base
            .global
            .iter()
            .find(|kv| kv.key == "allow_insecure")
            .unwrap();
        assert_eq!(insecure.value, "true");
    }

    #[test]
    fn merge_routing_prepends_rules() {
        let mut base = DaeConfig {
            routing: RoutingSection {
                rules: vec![crate::dae::ast::RoutingRule {
                    condition: "domain(example.com)".into(),
                    target: "direct".into(),
                }],
                fallback: Some("proxy".into()),
            },
            ..DaeConfig::default()
        };
        let overrides = DaeConfig {
            routing: RoutingSection {
                rules: vec![crate::dae::ast::RoutingRule {
                    condition: "domain(ads.com)".into(),
                    target: "block".into(),
                }],
                fallback: Some("my_group".into()),
            },
            ..DaeConfig::default()
        };
        merge_dae_config(&mut base, &overrides);
        assert_eq!(base.routing.rules.len(), 2);
        assert_eq!(base.routing.rules[0].target, "block");
        assert_eq!(base.routing.rules[1].target, "direct");
        assert_eq!(base.routing.fallback.as_deref(), Some("my_group"));
    }

    #[test]
    fn merge_dns_upstream_by_key() {
        let mut base = DaeConfig {
            dns: DnsSection {
                upstream: vec![KeyValue {
                    key: "alidns".into(),
                    value: "udp://223.5.5.5:53".into(),
                }],
                ..DnsSection::default()
            },
            ..DaeConfig::default()
        };
        let overrides = DaeConfig {
            dns: DnsSection {
                upstream: vec![
                    KeyValue {
                        key: "alidns".into(),
                        value: "udp://223.5.5.5:5353".into(),
                    },
                    KeyValue {
                        key: "googledns".into(),
                        value: "udp://8.8.8.8:53".into(),
                    },
                ],
                ..DnsSection::default()
            },
            ..DaeConfig::default()
        };
        merge_dae_config(&mut base, &overrides);
        assert_eq!(base.dns.upstream.len(), 2);
        assert_eq!(base.dns.upstream[0].value, "udp://223.5.5.5:5353");
        assert_eq!(base.dns.upstream[1].key, "googledns");
    }

    #[test]
    fn merge_groups_by_name() {
        let mut base = DaeConfig {
            groups: vec![GroupDef {
                name: "proxy".into(),
                filters: vec![],
                policy: PolicyDef::MinMovingAvg,
                extra: vec![],
            }],
            ..DaeConfig::default()
        };
        let overrides = DaeConfig {
            groups: vec![GroupDef {
                name: "proxy".into(),
                filters: vec![crate::dae::ast::FilterDef {
                    expression: "name(regex: '^us')".into(),
                    latency_offset: None,
                }],
                policy: PolicyDef::Random,
                extra: vec![],
            }],
            ..DaeConfig::default()
        };
        merge_dae_config(&mut base, &overrides);
        assert_eq!(base.groups.len(), 1);
        assert_eq!(base.groups[0].policy, PolicyDef::Random);
        assert_eq!(base.groups[0].filters.len(), 1);
    }
}
