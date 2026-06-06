use std::{collections::HashSet, net::IpAddr, str::FromStr};

use regex_lite::Regex;

use crate::{
    convert::{
        dns_utils::{clean_quoted, extract_paren_args, parse_comma_args, parse_dns_upstream},
        protocol,
    },
    dae::ast::{DaeConfig, Entry, FilterDef, PolicyDef, RoutingRule},
    error::Result,
    singbox::config::{
        Dns, DnsRule, DnsServer, HttpClient, Inbound, Log, Outbound, Route, RouteRule, RuleSet,
        SingBoxConfig,
    },
};

/// Built-in outbound names in dae that must not be overridden by group
/// definitions.
const BUILTIN_OUTBOUNDS: [&str; 3] = ["direct", "must_direct", "block"];

#[allow(clippy::missing_errors_doc)]
pub fn convert(dae: &DaeConfig) -> Result<SingBoxConfig> {
    let log = build_log(dae);

    let node_outbounds = build_node_outbounds(dae)?;
    let node_tags: Vec<String> = node_outbounds
        .iter()
        .filter_map(|ob| ob.tag.as_deref())
        .filter(|tag| {
            // Only include tags from originally tagged (not auto-tagged untagged) nodes
            dae.nodes
                .iter()
                .any(|n| matches!(n, Entry::Tagged { key, .. } if key == tag))
        })
        .map(str::to_string)
        .collect();
    let group_outbounds = build_group_outbounds(dae, &node_tags)?;

    let mut outbounds = Vec::new();
    outbounds.extend(node_outbounds);
    outbounds.push(Outbound {
        outbound_type: "direct".into(),
        tag: Some("direct".into()),
        ..Default::default()
    });
    outbounds.extend(group_outbounds);

    let mut dns = build_dns(dae);
    let rule_set_tags = collect_rule_set_tags(dae);
    let domain_resolver_tag = resolve_domain_resolver(&mut dns, &outbounds);

    let (http_clients, default_http_client) = build_http_clients(&outbounds);
    let route = build_route(
        dae,
        &rule_set_tags,
        domain_resolver_tag,
        default_http_client,
    );

    let inbounds = build_default_inbounds();
    let experimental = build_default_experimental();

    Ok(SingBoxConfig {
        log,
        dns,
        inbounds,
        outbounds,
        endpoints: vec![],
        http_clients,
        route,
        experimental: Some(experimental),
    })
}

// ---- Log ----

fn build_log(dae: &DaeConfig) -> Option<Log> {
    dae.global
        .iter()
        .find(|kv| kv.key == "log_level")
        .map(|kv| Log {
            level: Some(kv.value.clone()),
            timestamp: Some(true),
        })
}

fn build_default_inbounds() -> Vec<Inbound> {
    vec![Inbound {
        inbound_type: "mixed".to_string(),
        tag: Some("mixed".to_string()),
        listen: Some("127.0.0.1".to_string()),
        listen_port: Some(1080),
    }]
}

fn build_default_experimental() -> serde_json::Value {
    serde_json::json!({
        "cache_file": {
            "enabled": true,
            "store_fakeip": true
        }
    })
}

// ---- Nodes -> Outbounds ----

fn build_node_outbounds(dae: &DaeConfig) -> Result<Vec<Outbound>> {
    let outbounds: Vec<Outbound> = dae
        .nodes
        .iter()
        .filter_map(|entry| match entry {
            Entry::Tagged { key, value } => protocol::parse_node_link(key, value).ok(),
            Entry::Untagged(val) => {
                let tag = format!("untagged_{}", &val[..val.len().min(8)]);
                protocol::parse_node_link(&tag, val).ok()
            }
        })
        .collect();
    Ok(outbounds)
}

// ---- Groups -> Selector/UrlTest Outbounds ----

fn build_group_outbounds(dae: &DaeConfig, all_node_tags: &[String]) -> Result<Vec<Outbound>> {
    dae.groups
        .iter()
        .filter(|g| !BUILTIN_OUTBOUNDS.contains(&g.name.as_str()))
        .filter_map(|group| {
            let matched = filter_nodes(&group.filters, all_node_tags);
            if matched.is_empty() {
                eprintln!(
                    "warning: group '{}' has no matching nodes, skipping",
                    group.name
                );
                return None;
            }
            let outbound_type = match &group.policy {
                PolicyDef::Random | PolicyDef::Fixed(_) => "selector",
                PolicyDef::Min | PolicyDef::MinMovingAvg | PolicyDef::MinAvg10 => "urltest",
            };
            Some(Ok(Outbound {
                outbound_type: outbound_type.to_string(),
                tag: Some(group.name.clone()),
                outbounds: Some(matched),
                ..Default::default()
            }))
        })
        .collect()
}

fn filter_nodes(filters: &[FilterDef], all_tags: &[String]) -> Vec<String> {
    if filters.is_empty() {
        return all_tags.to_vec();
    }

    let mut result = Vec::new();
    for filter in filters {
        let matched = apply_filter(&filter.expression, all_tags);
        result.extend(matched);
    }
    result.sort();
    result.dedup();
    result
}

fn apply_filter(expr: &str, tags: &[String]) -> Vec<String> {
    let expr = expr.trim();

    if let Some(rest) = expr.strip_prefix('!') {
        let included = apply_filter(rest, tags);
        return tags
            .iter()
            .filter(|t| !included.contains(t))
            .cloned()
            .collect();
    }

    if let Some(inner) = extract_paren_args(expr, "name") {
        if let Some(regex_content) = inner.trim().strip_prefix("regex:") {
            let pattern = clean_quoted(regex_content.trim());
            if let Ok(re) = Regex::new(&pattern) {
                return tags.iter().filter(|t| re.is_match(t)).cloned().collect();
            }
            return tags.to_vec();
        }
        let names: Vec<String> = inner.split(',').map(|s| clean_quoted(s.trim())).collect();
        return tags
            .iter()
            .filter(|t| names.iter().any(|n| n == *t))
            .cloned()
            .collect();
    }

    tags.to_vec()
}

// ---- DNS ----

fn build_dns(dae: &DaeConfig) -> Option<Dns> {
    let must_direct_rules = build_must_direct_dns_rules(dae);

    if dae.dns.upstream.is_empty()
        && dae.dns.request_rules.is_empty()
        && dae.dns.response_rules.is_empty()
        && must_direct_rules.is_empty()
    {
        return None;
    }

    let mut servers: Vec<DnsServer> = dae
        .dns
        .upstream
        .iter()
        .map(|up| parse_dns_upstream(&up.key, &up.value))
        .collect();

    // For DNS servers whose address is a domain (not IP), set domain_resolver
    // pointing to the local system resolver to avoid circular resolution.
    if servers
        .iter()
        .any(|s| is_domain_address(s.server.as_deref()))
    {
        let resolver_tag = match servers.iter().find_map(|s| {
            if s.dns_type.as_deref() == Some("local") {
                s.tag.clone()
            } else {
                None
            }
        }) {
            Some(tag) => tag,
            None => {
                let tag = "dns-local".to_string();
                servers.push(DnsServer {
                    dns_type: Some("local".into()),
                    tag: Some(tag.clone()),
                    ..Default::default()
                });
                tag
            }
        };
        for server in &mut servers {
            if is_domain_address(server.server.as_deref()) && server.domain_resolver.is_none() {
                server.domain_resolver = Some(resolver_tag.clone());
            }
        }
    }

    let mut final_dns = dae.dns.fallback.clone();
    let mut rules = Vec::new();

    // must_direct DNS rules come first — they take priority over normal DNS
    // routing, matching the dae semantics where must_direct bypasses DNS
    // hijacking
    if !must_direct_rules.is_empty() {
        servers.push(DnsServer {
            dns_type: Some("local".into()),
            tag: Some("dns-direct".into()),
            ..Default::default()
        });
        rules.extend(must_direct_rules);
        // ensure there's always a fallback DNS server
        final_dns = final_dns.or(Some("dns-direct".to_string()));
    }

    for rule in &dae.dns.request_rules {
        let cond = rule.condition.trim();
        if cond.eq_ignore_ascii_case("fallback") {
            // backward compatibility: old format used "fallback -> target"
            final_dns = final_dns.or(Some(rule.target.clone()));
            continue;
        }
        rules.push(convert_dns_rule(rule));
    }

    for rule in &dae.dns.response_rules {
        let cond = rule.condition.trim();
        if cond.eq_ignore_ascii_case("fallback") {
            continue;
        }
        rules.push(convert_dns_rule(rule));
    }

    Some(Dns {
        servers,
        rules,
        final_dns,
    })
}

/// Extract domain-based DNS rules from `must_direct` routing rules.
/// In dae, `must_direct` means traffic AND DNS both bypass the proxy.
/// These DNS rules ensure matched domains are resolved directly (via system
/// resolver) rather than through the proxy's DNS upstream.
fn build_must_direct_dns_rules(dae: &DaeConfig) -> Vec<DnsRule> {
    let mut rules = Vec::new();

    for rule in &dae.routing.rules {
        if rule.target.trim() != "must_direct" {
            continue;
        }
        let condition = rule.condition.trim();
        let Some(args_str) = extract_paren_args(condition, "domain") else {
            continue;
        };
        let args = parse_comma_args(args_str);
        if args.is_empty() {
            continue;
        }
        let mut dns_rule = DnsRule {
            server: Some("dns-direct".into()),
            ..Default::default()
        };
        for arg in &args {
            if let Some(name) = arg.strip_prefix("geosite:") {
                dns_rule.rule_set.push(format!("geosite-{name}"));
            } else {
                dns_rule.domain_suffix.push(arg.clone());
            }
        }
        if !dns_rule.rule_set.is_empty() || !dns_rule.domain_suffix.is_empty() {
            rules.push(dns_rule);
        }
    }

    rules
}

fn is_ip_address(addr: Option<&str>) -> bool {
    match addr {
        Some(a) => {
            let trimmed = a.trim_start_matches('[').trim_end_matches(']');
            IpAddr::from_str(trimmed).is_ok()
        }
        None => false,
    }
}

fn is_domain_address(addr: Option<&str>) -> bool {
    addr.is_some_and(|a| !a.trim_start_matches('[').trim_end_matches(']').is_empty())
        && !is_ip_address(addr)
}

fn convert_dns_rule(rule: &RoutingRule) -> DnsRule {
    let condition = rule.condition.trim();
    let target = rule.target.trim();

    if let Some(args_str) = extract_paren_args(condition, "qname") {
        let args = parse_comma_args(args_str);
        let mut dns_rule = DnsRule::default();

        if target == "reject" || target == "asis" {
            dns_rule.action = Some("predefined".to_string());
            dns_rule.rcode = Some("NOERROR".to_string());
        } else {
            dns_rule.server = Some(target.to_string());
        }

        for arg in &args {
            if let Some(name) = arg.strip_prefix("geosite:") {
                dns_rule.rule_set.push(format!("geosite-{name}"));
            } else if let Some(name) = arg.strip_prefix("full:") {
                dns_rule.domain.push(clean_quoted(name));
            } else if let Some(name) = arg.strip_prefix("keyword:") {
                dns_rule.domain_keyword.push(clean_quoted(name));
            } else if let Some(name) = arg.strip_prefix("regex:") {
                dns_rule.domain_regex.push(clean_quoted(name));
            } else if let Some(name) = arg.strip_prefix("suffix:") {
                dns_rule.domain_suffix.push(clean_quoted(name));
            } else {
                dns_rule.domain_suffix.push(arg.clone());
            }
        }
        return dns_rule;
    }

    if let Some(args_str) = extract_paren_args(condition, "ip") {
        let args = parse_comma_args(args_str);
        let mut dns_rule = DnsRule::default();

        if target != "accept" {
            dns_rule.server = Some(target.to_string());
        }

        for arg in &args {
            if arg == "geoip:private" {
                dns_rule.ip_accept_any = Some(true);
            } else if let Some(name) = arg.strip_prefix("geoip:") {
                dns_rule.rule_set.push(format!("geoip-{name}"));
            }
        }
        return dns_rule;
    }

    if extract_paren_args(condition, "upstream").is_some() {
        let mut dns_rule = DnsRule::default();
        if target != "accept" {
            dns_rule.server = Some(target.to_string());
        }
        return dns_rule;
    }

    DnsRule {
        server: Some(target.to_string()),
        ..Default::default()
    }
}

/// Find or create a "local" type DNS server to use as
/// `route.default_domain_resolver`. This is needed when any outbound connects
/// via a domain address, so sing-box can resolve it before establishing the
/// proxy connection.
fn resolve_domain_resolver(dns: &mut Option<Dns>, outbounds: &[Outbound]) -> Option<String> {
    let needs_resolver = outbounds.iter().any(|ob| {
        ob.server
            .as_deref()
            .is_some_and(|s| is_domain_address(Some(s)))
    });

    if !needs_resolver {
        return None;
    }

    // Reuse an existing "local" type DNS server if available
    if let Some(dns_config) = dns.as_ref()
        && let Some(tag) = dns_config
            .servers
            .iter()
            .find(|s| s.dns_type.as_deref() == Some("local"))
            .and_then(|s| s.tag.clone())
    {
        return Some(tag);
    }

    // No local DNS server exists — create one
    let tag = "dns-local".to_string();
    let local_server = DnsServer {
        dns_type: Some("local".into()),
        tag: Some(tag.clone()),
        ..Default::default()
    };

    match dns {
        Some(dns_config) => dns_config.servers.push(local_server),
        None => {
            *dns = Some(Dns {
                servers: vec![local_server],
                rules: vec![],
                final_dns: None,
            });
        }
    }

    Some(tag)
}

// ---- HTTP Clients ----

fn find_proxy_detour_tag(outbounds: &[Outbound]) -> Option<String> {
    // Prefer the first group (selector/urltest) tag — groups are appended last
    for ob in outbounds.iter().rev() {
        if matches!(ob.outbound_type.as_str(), "selector" | "urltest") {
            return ob.tag.clone();
        }
    }
    // Fall back to first non-direct proxy node
    for ob in outbounds {
        if ob.tag.as_deref() != Some("direct") {
            return ob.tag.clone();
        }
    }
    None
}

fn build_http_clients(outbounds: &[Outbound]) -> (Vec<HttpClient>, Option<String>) {
    let detour_tag = find_proxy_detour_tag(outbounds);
    if let Some(detour) = detour_tag {
        let client = HttpClient {
            tag: Some("proxy-client".to_string()),
            detour: Some(detour),
        };
        (vec![client], Some("proxy-client".to_string()))
    } else {
        (vec![], None)
    }
}

// ---- Route ----

fn build_route(
    dae: &DaeConfig,
    rule_set_tags: &HashSet<String>,
    domain_resolver_tag: Option<String>,
    default_http_client: Option<String>,
) -> Option<Route> {
    let rule_set = build_rule_set(rule_set_tags);

    if dae.routing.rules.is_empty()
        && dae.routing.fallback.is_none()
        && rule_set.is_empty()
        && domain_resolver_tag.is_none()
        && default_http_client.is_none()
    {
        return None;
    }

    let rules: Vec<RouteRule> = dae.routing.rules.iter().map(convert_routing_rule).collect();

    Some(Route {
        rules,
        rule_set,
        final_outbound: dae.routing.fallback.clone(),
        default_domain_resolver: domain_resolver_tag.map(serde_json::Value::String),
        default_http_client,
    })
}

fn convert_routing_rule(rule: &RoutingRule) -> RouteRule {
    let condition = rule.condition.trim();
    let target = resolve_target(rule.target.trim());

    if let Some(args_str) = extract_paren_args(condition, "domain") {
        let args = parse_comma_args(args_str);
        let (rule_set, domain_suffix) = categorize_domain_args(&args);
        return RouteRule {
            outbound: target.outbound,
            action: target.action,
            rule_set,
            domain_suffix,
            ..Default::default()
        };
    }

    if let Some(args_str) = extract_paren_args(condition, "dip") {
        let args = parse_comma_args(args_str);
        let (ip_is_private, rule_set, ip_cidr) = categorize_dip_args(&args);
        return RouteRule {
            outbound: target.outbound,
            action: target.action,
            ip_is_private,
            rule_set,
            ip_cidr,
            ..Default::default()
        };
    }

    if let Some(args_str) = extract_paren_args(condition, "pname") {
        let args = parse_comma_args(args_str);
        return RouteRule {
            outbound: target.outbound,
            action: target.action,
            process_name: args,
            ..Default::default()
        };
    }

    RouteRule {
        outbound: target.outbound,
        action: target.action,
        ..Default::default()
    }
}

struct ResolvedTarget {
    outbound: Option<String>,
    action: Option<String>,
}

fn resolve_target(target: &str) -> ResolvedTarget {
    match target {
        "direct" | "must_direct" => ResolvedTarget {
            outbound: Some("direct".to_string()),
            action: None,
        },
        "block" => ResolvedTarget {
            outbound: None,
            action: Some("reject".to_string()),
        },
        name => ResolvedTarget {
            outbound: Some(name.to_string()),
            action: None,
        },
    }
}

// ---- Rule set generation ----

fn collect_rule_set_tags(dae: &DaeConfig) -> HashSet<String> {
    let mut tags = HashSet::new();

    for rule in &dae.routing.rules {
        collect_tags_from_condition(&rule.condition, &mut tags);
    }
    for rule in &dae.dns.request_rules {
        collect_tags_from_condition(&rule.condition, &mut tags);
    }
    for rule in &dae.dns.response_rules {
        collect_tags_from_condition(&rule.condition, &mut tags);
    }

    tags
}

fn collect_tags_from_condition(condition: &str, tags: &mut HashSet<String>) {
    let text = condition.trim();

    for func_name in &["domain", "dip", "qname", "ip"] {
        if let Some(args_str) = extract_paren_args(text, func_name) {
            let args = parse_comma_args(args_str);
            for arg in &args {
                if let Some(name) = arg.strip_prefix("geosite:") {
                    tags.insert(format!("geosite-{name}"));
                } else if let Some(name) = arg.strip_prefix("geoip:")
                    && name != "private"
                {
                    tags.insert(format!("geoip-{name}"));
                }
            }
        }
    }
}

fn build_rule_set(tags: &HashSet<String>) -> Vec<RuleSet> {
    let mut sorted: Vec<&String> = tags.iter().collect();
    sorted.sort();

    sorted
        .into_iter()
        .map(|tag| {
            let url = if tag.starts_with("geoip-") {
                format!("https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/{tag}.srs")
            } else {
                format!(
                    "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/{tag}.srs"
                )
            };
            RuleSet {
                tag: Some(tag.clone()),
                rule_set_type: Some("remote".to_string()),
                format: Some("binary".to_string()),
                path: None,
                url: Some(url),
            }
        })
        .collect()
}

// ---- Argument categorization ----

fn categorize_domain_args(args: &[String]) -> (Vec<String>, Vec<String>) {
    let mut rule_set = Vec::new();
    let mut domain_suffix = Vec::new();

    for arg in args {
        if let Some(name) = arg.strip_prefix("geosite:") {
            rule_set.push(format!("geosite-{name}"));
        } else if let Some(name) = arg.strip_prefix("geoip:") {
            rule_set.push(format!("geoip-{name}"));
        } else {
            domain_suffix.push(arg.clone());
        }
    }

    (rule_set, domain_suffix)
}

fn categorize_dip_args(args: &[String]) -> (Option<bool>, Vec<String>, Vec<String>) {
    let mut ip_is_private = None;
    let mut rule_set = Vec::new();
    let mut ip_cidr = Vec::new();

    for arg in args {
        if arg == "geoip:private" {
            ip_is_private = Some(true);
        } else if let Some(name) = arg.strip_prefix("geoip:") {
            rule_set.push(format!("geoip-{name}"));
        } else {
            ip_cidr.push(arg.clone());
        }
    }

    (ip_is_private, rule_set, ip_cidr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dae::ast::*;

    #[test]
    fn roundtrip_log_level() {
        let dae = DaeConfig {
            global: vec![KeyValue {
                key: "log_level".into(),
                value: "debug".into(),
            }],
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        assert_eq!(cfg.log.as_ref().unwrap().level.as_deref(), Some("debug"));
    }

    #[test]
    fn converts_hy2_node() {
        let dae = DaeConfig {
            nodes: vec![Entry::Tagged {
                key: "my-hy".into(),
                value: "hy2://pass123@1.2.3.4:443/?sni=example.com#display".into(),
            }],
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let ob = &cfg.outbounds[0];
        assert_eq!(ob.outbound_type, "hysteria2");
        assert_eq!(ob.tag.as_deref(), Some("my-hy"));
        assert_eq!(ob.server.as_deref(), Some("1.2.3.4"));
        assert_eq!(ob.server_port, Some(443));
        assert_eq!(ob.password.as_deref(), Some("pass123"));
        let tls = ob.tls.as_ref().unwrap();
        assert_eq!(tls.server_name.as_deref(), Some("example.com"));
    }

    #[test]
    fn converts_trojan_node() {
        let dae = DaeConfig {
            nodes: vec![Entry::Tagged {
                key: "my-tr".into(),
                value: "trojan://pw@host:8080/?type=tcp&security=tls&sni=host#name".into(),
            }],
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let ob = &cfg.outbounds[0];
        assert_eq!(ob.outbound_type, "trojan");
        assert_eq!(ob.server_port, Some(8080));
    }

    #[test]
    fn direct_outbound_always_present() {
        let dae = DaeConfig::default();
        let cfg = convert(&dae).unwrap();
        assert!(
            cfg.outbounds
                .iter()
                .any(|ob| ob.tag.as_deref() == Some("direct") && ob.outbound_type == "direct")
        );
    }

    #[test]
    fn group_urltest_with_name_filter() {
        let dae = DaeConfig {
            nodes: vec![
                Entry::Tagged {
                    key: "jp-1".into(),
                    value: "hy2://p@h:1".into(),
                },
                Entry::Tagged {
                    key: "us-1".into(),
                    value: "hy2://p@h:2".into(),
                },
            ],
            groups: vec![GroupDef {
                name: "jp".into(),
                filters: vec![FilterDef {
                    expression: "name(regex: '^jp')".into(),
                    latency_offset: None,
                }],
                policy: PolicyDef::MinMovingAvg,
                extra: vec![],
            }],
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let jp_group = cfg
            .outbounds
            .iter()
            .find(|ob| ob.tag.as_deref() == Some("jp"))
            .unwrap();
        assert_eq!(jp_group.outbound_type, "urltest");
        assert_eq!(jp_group.outbounds, Some(vec!["jp-1".to_string()]));
    }

    #[test]
    fn group_selector_with_negated_filter() {
        let dae = DaeConfig {
            nodes: vec![
                Entry::Tagged {
                    key: "jp-1".into(),
                    value: "hy2://p@h:1".into(),
                },
                Entry::Tagged {
                    key: "us-1".into(),
                    value: "hy2://p@h:2".into(),
                },
            ],
            groups: vec![GroupDef {
                name: "no_jp".into(),
                filters: vec![FilterDef {
                    expression: "!name(regex: '^jp')".into(),
                    latency_offset: None,
                }],
                policy: PolicyDef::Random,
                extra: vec![],
            }],
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let g = cfg
            .outbounds
            .iter()
            .find(|ob| ob.tag.as_deref() == Some("no_jp"))
            .unwrap();
        assert_eq!(g.outbound_type, "selector");
        assert_eq!(g.outbounds, Some(vec!["us-1".to_string()]));
    }

    #[test]
    fn route_domain_condition() {
        let dae = DaeConfig {
            routing: RoutingSection {
                rules: vec![RoutingRule {
                    condition: "domain(example.com, geosite:cn)".into(),
                    target: "direct".into(),
                }],
                fallback: Some("proxy".into()),
            },
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let route = cfg.route.as_ref().unwrap();
        let r = &route.rules[0];
        assert_eq!(r.outbound.as_deref(), Some("direct"));
        assert_eq!(r.domain_suffix, vec!["example.com"]);
        assert_eq!(r.rule_set, vec!["geosite-cn"]);
        assert_eq!(route.final_outbound.as_deref(), Some("proxy"));
    }

    #[test]
    fn route_dip_condition() {
        let dae = DaeConfig {
            routing: RoutingSection {
                rules: vec![RoutingRule {
                    condition: "dip(geoip:private, 10.0.0.0/8)".into(),
                    target: "direct".into(),
                }],
                fallback: None,
            },
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let r = &cfg.route.unwrap().rules[0];
        assert_eq!(r.ip_is_private, Some(true));
        assert_eq!(r.ip_cidr, vec!["10.0.0.0/8"]);
    }

    #[test]
    fn route_block_target() {
        let dae = DaeConfig {
            routing: RoutingSection {
                rules: vec![RoutingRule {
                    condition: "domain(ads.example.com)".into(),
                    target: "block".into(),
                }],
                fallback: None,
            },
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let r = &cfg.route.unwrap().rules[0];
        assert_eq!(r.action.as_deref(), Some("reject"));
        assert!(r.outbound.is_none());
    }

    #[test]
    fn route_pname_and_must_direct() {
        let dae = DaeConfig {
            routing: RoutingSection {
                rules: vec![RoutingRule {
                    condition: "pname(sshd, systemd-resolved)".into(),
                    target: "must_direct".into(),
                }],
                fallback: None,
            },
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let r = &cfg.route.unwrap().rules[0];
        assert_eq!(r.process_name, vec!["sshd", "systemd-resolved"]);
        assert_eq!(r.outbound.as_deref(), Some("direct"));
    }

    #[test]
    fn dns_https_upstream_with_path_to_sing() {
        let dae = DaeConfig {
            dns: DnsSection {
                upstream: vec![KeyValue {
                    key: "mydoh".into(),
                    value: "https://dns.cloudflare.com:443/dns-query".into(),
                }],
                ..DnsSection::default()
            },
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let dns = cfg.dns.unwrap();
        assert_eq!(dns.servers.len(), 2);
        assert_eq!(dns.servers[0].tag.as_deref(), Some("mydoh"));
        assert_eq!(dns.servers[0].dns_type.as_deref(), Some("https"));
        assert_eq!(dns.servers[0].server.as_deref(), Some("dns.cloudflare.com"));
        assert_eq!(dns.servers[0].path.as_deref(), Some("/dns-query"));
        assert_eq!(
            dns.servers[0].domain_resolver.as_deref(),
            Some("dns-local"),
            "domain-based DNS server needs domain_resolver"
        );
        assert_eq!(dns.servers[1].dns_type.as_deref(), Some("local"));
        assert_eq!(dns.servers[1].tag.as_deref(), Some("dns-local"));
    }

    #[test]
    fn dns_rule_qname_full_keyword_regex() {
        let dae = DaeConfig {
            dns: DnsSection {
                upstream: vec![KeyValue {
                    key: "mydns".into(),
                    value: "udp://1.1.1.1:53".into(),
                }],
                request_rules: vec![RoutingRule {
                    condition: "qname(full:exact.com, keyword:ad, regex:'\\.cn$')".into(),
                    target: "mydns".into(),
                }],
                ..DnsSection::default()
            },
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let dns = cfg.dns.unwrap();
        assert_eq!(dns.rules.len(), 1);
        let rule = &dns.rules[0];
        assert_eq!(rule.domain, vec!["exact.com"]);
        assert_eq!(rule.domain_keyword, vec!["ad"]);
        assert_eq!(rule.domain_regex, vec!["\\.cn$"]);
    }

    #[test]
    fn dns_upstream_and_request_rules() {
        let dae = DaeConfig {
            dns: DnsSection {
                upstream: vec![
                    KeyValue {
                        key: "alidns".into(),
                        value: "udp://223.5.5.5:53".into(),
                    },
                    KeyValue {
                        key: "googledns".into(),
                        value: "tcp+udp://dns.google.com:53".into(),
                    },
                ],
                request_rules: vec![
                    RoutingRule {
                        condition: "qname(geosite:cn)".into(),
                        target: "alidns".into(),
                    },
                    RoutingRule {
                        condition: "qname(geosite:category-ads)".into(),
                        target: "reject".into(),
                    },
                ],
                fallback: Some("googledns".to_string()),
                ..DnsSection::default()
            },
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let dns = cfg.dns.unwrap();

        // dns-local is added as domain_resolver for domain-based servers
        assert_eq!(dns.servers.len(), 3);
        assert_eq!(dns.servers[0].tag.as_deref(), Some("alidns"));
        assert_eq!(dns.servers[0].dns_type.as_deref(), Some("udp"));
        assert_eq!(dns.servers[0].server.as_deref(), Some("223.5.5.5"));

        assert_eq!(dns.servers[1].tag.as_deref(), Some("googledns"));
        assert_eq!(dns.servers[1].dns_type.as_deref(), Some("udp"));
        assert_eq!(dns.servers[1].server.as_deref(), Some("dns.google.com"));
        assert_eq!(
            dns.servers[1].domain_resolver.as_deref(),
            Some("dns-local"),
            "domain-based DNS server uses local resolver"
        );

        let dns_local = dns
            .servers
            .iter()
            .find(|s| s.tag.as_deref() == Some("dns-local"))
            .expect("dns-local server should exist");
        assert_eq!(dns_local.dns_type.as_deref(), Some("local"));

        assert_eq!(dns.rules.len(), 2);
        assert_eq!(dns.rules[0].server.as_deref(), Some("alidns"));
        assert_eq!(dns.rules[0].rule_set, vec!["geosite-cn"]);

        assert_eq!(dns.rules[1].action.as_deref(), Some("predefined"));
        assert_eq!(dns.rules[1].rule_set, vec!["geosite-category-ads"]);

        assert_eq!(dns.final_dns.as_deref(), Some("googledns"));
    }

    #[test]
    fn dns_upstream_ipv6_bracketed_with_port() {
        let dae = DaeConfig {
            dns: DnsSection {
                upstream: vec![KeyValue {
                    key: "v6dns".into(),
                    value: "udp://[2001:db8::1]:53".into(),
                }],
                ..DnsSection::default()
            },
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let srv = &cfg.dns.unwrap().servers[0];
        assert_eq!(srv.tag.as_deref(), Some("v6dns"));
        assert_eq!(srv.dns_type.as_deref(), Some("udp"));
        assert_eq!(srv.server.as_deref(), Some("[2001:db8::1]"));
    }

    #[test]
    fn group_urltest_with_regex_alternation() {
        let dae = DaeConfig {
            nodes: vec![
                Entry::Tagged {
                    key: "node-jp".into(),
                    value: "hy2://p@h:1".into(),
                },
                Entry::Tagged {
                    key: "node-sg".into(),
                    value: "hy2://p@h:2".into(),
                },
                Entry::Tagged {
                    key: "node-us".into(),
                    value: "hy2://p@h:3".into(),
                },
                Entry::Tagged {
                    key: "node-de".into(),
                    value: "hy2://p@h:4".into(),
                },
            ],
            groups: vec![GroupDef {
                name: "proxy".into(),
                filters: vec![FilterDef {
                    expression: "name(regex: 'node-jp|node-sg|node-us')".into(),
                    latency_offset: None,
                }],
                policy: PolicyDef::MinMovingAvg,
                extra: vec![],
            }],
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let proxy_group = cfg
            .outbounds
            .iter()
            .find(|ob| ob.tag.as_deref() == Some("proxy"))
            .unwrap();
        assert_eq!(proxy_group.outbound_type, "urltest");
        let mut outbounds = proxy_group.outbounds.clone().unwrap();
        outbounds.sort();
        assert_eq!(outbounds, vec!["node-jp", "node-sg", "node-us"]);
    }

    #[test]
    fn group_urltest_with_regex_alternation_and_suffix() {
        let dae = DaeConfig {
            nodes: vec![
                Entry::Tagged {
                    key: "hk-01".into(),
                    value: "hy2://p@h:1".into(),
                },
                Entry::Tagged {
                    key: "jp-01".into(),
                    value: "hy2://p@h:2".into(),
                },
                Entry::Tagged {
                    key: "jp-02".into(),
                    value: "hy2://p@h:3".into(),
                },
            ],
            groups: vec![GroupDef {
                name: "jp_nodes".into(),
                filters: vec![FilterDef {
                    expression: "name(regex: '^jp-0[12]$')".into(),
                    latency_offset: None,
                }],
                policy: PolicyDef::Random,
                extra: vec![],
            }],
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let g = cfg
            .outbounds
            .iter()
            .find(|ob| ob.tag.as_deref() == Some("jp_nodes"))
            .unwrap();
        assert_eq!(g.outbound_type, "selector");
        let mut outbounds = g.outbounds.clone().unwrap();
        outbounds.sort();
        assert_eq!(outbounds, vec!["jp-01", "jp-02"]);
    }

    #[test]
    fn must_direct_generates_direct_dns_rules() {
        let dae = DaeConfig {
            routing: RoutingSection {
                rules: vec![
                    RoutingRule {
                        condition: "domain(example.com, geosite:google)".into(),
                        target: "must_direct".into(),
                    },
                    RoutingRule {
                        condition: "domain(geosite:cn)".into(),
                        target: "direct".into(),
                    },
                    RoutingRule {
                        condition: "pname(sshd)".into(),
                        target: "must_direct".into(),
                    },
                ],
                fallback: Some("proxy".into()),
            },
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();

        // must_direct triggers DNS section even without explicit dns config
        let dns = cfg.dns.as_ref().expect("dns section should exist");

        // dns-direct server should be present
        let direct_server = dns
            .servers
            .iter()
            .find(|s| s.tag.as_deref() == Some("dns-direct"));
        assert!(direct_server.is_some(), "dns-direct server should exist");
        assert_eq!(direct_server.unwrap().dns_type.as_deref(), Some("local"));

        // first DNS rule should be for the must_direct domain rule
        assert!(!dns.rules.is_empty(), "DNS rules should exist");
        let must_direct_rule = &dns.rules[0];
        assert_eq!(
            must_direct_rule.server.as_deref(),
            Some("dns-direct"),
            "must_direct domain rule should point to dns-direct server"
        );
        assert!(
            must_direct_rule
                .domain_suffix
                .contains(&"example.com".to_string()),
            "must_direct rule should contain example.com"
        );
        assert!(
            must_direct_rule
                .rule_set
                .contains(&"geosite-google".to_string()),
            "must_direct rule should contain geosite-google"
        );

        // pname rule should NOT generate a DNS rule
        let pname_rules: Vec<&DnsRule> = dns
            .rules
            .iter()
            .filter(|r| r.server.as_deref() == Some("dns-direct"))
            .collect();
        // Only one dns-direct rule (from the domain() rule, not the pname() rule)
        // But actually the second is from domain(geosite:cn) -> direct, not must_direct
        // So only 1 rule for dns-direct
        assert_eq!(
            pname_rules.len(),
            1,
            "only domain() must_direct generates DNS rules"
        );

        // final should fall back to dns-direct when no explicit DNS config
        assert_eq!(
            dns.final_dns.as_deref(),
            Some("dns-direct"),
            "final DNS should be dns-direct when must_direct rules exist"
        );
    }

    #[test]
    fn http_clients_uses_group_tag_when_groups_exist() {
        let dae = DaeConfig {
            nodes: vec![
                Entry::Tagged {
                    key: "jp-1".into(),
                    value: "hy2://p@h:1".into(),
                },
                Entry::Tagged {
                    key: "us-1".into(),
                    value: "hy2://p@h:2".into(),
                },
            ],
            groups: vec![GroupDef {
                name: "proxy".into(),
                filters: vec![FilterDef {
                    expression: "name(regex: '.*')".into(),
                    latency_offset: None,
                }],
                policy: PolicyDef::MinMovingAvg,
                extra: vec![],
            }],
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        assert_eq!(cfg.http_clients.len(), 1);
        assert_eq!(cfg.http_clients[0].tag.as_deref(), Some("proxy-client"));
        assert_eq!(cfg.http_clients[0].detour.as_deref(), Some("proxy"));
        let route = cfg.route.as_ref().unwrap();
        assert_eq!(route.default_http_client.as_deref(), Some("proxy-client"));
    }

    #[test]
    fn http_clients_falls_back_to_first_node_when_no_group() {
        let dae = DaeConfig {
            nodes: vec![Entry::Tagged {
                key: "my-proxy".into(),
                value: "hy2://p@h:1".into(),
            }],
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        assert_eq!(cfg.http_clients.len(), 1);
        assert_eq!(cfg.http_clients[0].detour.as_deref(), Some("my-proxy"));
        let route = cfg.route.as_ref().unwrap();
        assert_eq!(route.default_http_client.as_deref(), Some("proxy-client"));
    }

    #[test]
    fn no_http_clients_when_no_nodes() {
        let dae = DaeConfig::default();
        let cfg = convert(&dae).unwrap();
        assert!(cfg.http_clients.is_empty());
    }

    #[test]
    fn domain_resolver_set_when_outbound_uses_domain() {
        let dae = DaeConfig {
            nodes: vec![Entry::Tagged {
                key: "my-proxy".into(),
                value: "ss://YWVzLTEyOC1nY206cGFzc3dk@proxy.example.com:8443".into(),
            }],
            routing: RoutingSection {
                rules: vec![RoutingRule {
                    condition: "domain(example.com)".into(),
                    target: "my-proxy".into(),
                }],
                fallback: Some("direct".into()),
            },
            ..DaeConfig::default()
        };
        let cfg = convert(&dae).unwrap();
        let route = cfg.route.as_ref().expect("route should exist");
        let resolver = route
            .default_domain_resolver
            .as_ref()
            .expect("default_domain_resolver should be set");
        assert_eq!(resolver, "dns-local");
        let dns = cfg.dns.as_ref().expect("dns section should exist");
        let local = dns
            .servers
            .iter()
            .find(|s| s.tag.as_deref() == Some("dns-local"));
        assert!(local.is_some(), "dns-local server should exist");
        assert_eq!(local.unwrap().dns_type.as_deref(), Some("local"));
    }
}
