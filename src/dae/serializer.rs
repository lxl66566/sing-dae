use std::fmt::Write;

use super::ast;

#[allow(clippy::missing_panics_doc)]
#[must_use]
pub fn serialize(config: &ast::DaeConfig) -> String {
    let mut out = String::new();

    if !config.global.is_empty() {
        out.push_str("global {\n");
        for kv in &config.global {
            writeln!(out, "    {}: {}", kv.key, format_value(&kv.value)).unwrap();
        }
        out.push_str("}\n\n");
    }

    if !config.subscriptions.is_empty() {
        out.push_str("subscription {\n");
        for entry in &config.subscriptions {
            match entry {
                ast::Entry::Tagged { key, value } => {
                    writeln!(out, "    {key}: {}", format_value(value)).unwrap();
                }
                ast::Entry::Untagged(value) => {
                    writeln!(out, "    {}", format_value(value)).unwrap();
                }
            }
        }
        out.push_str("}\n\n");
    }

    if !config.nodes.is_empty() {
        out.push_str("node {\n");
        for entry in &config.nodes {
            match entry {
                ast::Entry::Tagged { key, value } => {
                    writeln!(out, "    {key}: {}", format_value(value)).unwrap();
                }
                ast::Entry::Untagged(value) => {
                    writeln!(out, "    {}", format_value(value)).unwrap();
                }
            }
        }
        out.push_str("}\n\n");
    }

    serialize_dns(&config.dns, &mut out);

    if !config.groups.is_empty() {
        out.push_str("group {\n");
        for group in &config.groups {
            writeln!(out, "    {} {{", group.name).unwrap();
            for filter in &group.filters {
                write!(out, "        filter: {}", filter.expression).unwrap();
                if let Some(ref offset) = filter.latency_offset {
                    write!(out, " [{offset}]").unwrap();
                }
                out.push('\n');
            }
            writeln!(out, "        policy: {}", format_policy(&group.policy)).unwrap();
            for kv in &group.extra {
                writeln!(out, "        {}: {}", kv.key, format_value(&kv.value)).unwrap();
            }
            out.push_str("    }\n");
        }
        out.push_str("}\n\n");
    }

    if !config.routing.rules.is_empty() || config.routing.fallback.is_some() {
        out.push_str("routing {\n");
        for rule in &config.routing.rules {
            writeln!(out, "    {} -> {}", rule.condition, rule.target).unwrap();
        }
        if let Some(ref fb) = config.routing.fallback {
            writeln!(out, "    fallback: {fb}").unwrap();
        }
        out.push_str("}\n");
    }

    out
}

fn serialize_dns(dns: &ast::DnsSection, out: &mut String) {
    let has_content = !dns.entries.is_empty()
        || !dns.upstream.is_empty()
        || !dns.request_rules.is_empty()
        || !dns.response_rules.is_empty();

    if !has_content {
        return;
    }

    out.push_str("dns {\n");

    for kv in &dns.entries {
        writeln!(out, "    {}: {}", kv.key, format_value(&kv.value)).unwrap();
    }

    if !dns.upstream.is_empty() {
        out.push_str("    upstream {\n");
        for kv in &dns.upstream {
            writeln!(out, "        {}: {}", kv.key, format_value(&kv.value)).unwrap();
        }
        out.push_str("    }\n");
    }

    if !dns.request_rules.is_empty() || !dns.response_rules.is_empty() {
        out.push_str("    routing {\n");

        if !dns.request_rules.is_empty() {
            out.push_str("        request {\n");
            for rule in &dns.request_rules {
                writeln!(out, "            {} -> {}", rule.condition, rule.target).unwrap();
            }
            out.push_str("        }\n");
        }

        if !dns.response_rules.is_empty() {
            out.push_str("        response {\n");
            for rule in &dns.response_rules {
                writeln!(out, "            {} -> {}", rule.condition, rule.target).unwrap();
            }
            out.push_str("        }\n");
        }

        out.push_str("    }\n");
    }

    out.push_str("}\n\n");
}

fn format_value(v: &str) -> String {
    let needs_quoting = v.contains(' ')
        || v.contains('\t')
        || v.contains(':')
        || v.contains('/')
        || v.contains('@')
        || v.contains('=')
        || v.contains(',');
    if needs_quoting {
        format!("'{v}'")
    } else {
        v.to_owned()
    }
}

fn format_policy(p: &ast::PolicyDef) -> String {
    match p {
        ast::PolicyDef::Random => "random".to_owned(),
        ast::PolicyDef::Fixed(i) => format!("fixed({i})"),
        ast::PolicyDef::Min => "min".to_owned(),
        ast::PolicyDef::MinMovingAvg => "min_moving_avg".to_owned(),
        ast::PolicyDef::MinAvg10 => "min_avg10".to_owned(),
    }
}
