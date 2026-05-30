use pest::Parser;

use super::ast;

#[derive(pest_derive::Parser)]
#[grammar = "dae/dae.pest"]
pub struct DaeParser;

#[allow(clippy::missing_errors_doc)]
pub fn parse(input: &str) -> crate::error::Result<ast::DaeConfig> {
    let pairs = DaeParser::parse(Rule::config, input)?;
    let mut config = ast::DaeConfig::default();

    let config_pair = pairs
        .into_iter()
        .next()
        .ok_or_else(|| crate::error::AppError::Parse("empty input".into()))?;

    for pair in config_pair.into_inner() {
        if pair.as_rule() != Rule::section {
            continue;
        }
        let Some(inner) = pair.into_inner().next() else {
            continue;
        };
        match inner.as_rule() {
            Rule::global_section => {
                config.global = parse_kv_block(inner);
            }
            Rule::subscription_section => {
                config.subscriptions = parse_entry_block(inner);
            }
            Rule::node_section => {
                config.nodes = parse_entry_block(inner);
            }
            Rule::dns_section => {
                config.dns = parse_dns_section(inner);
            }
            Rule::group_section => {
                config.groups = parse_group_section(inner);
            }
            Rule::routing_section => {
                config.routing = parse_routing_section(inner);
            }
            _ => {}
        }
    }

    Ok(config)
}

fn parse_kv_block(pair: pest::iterators::Pair<Rule>) -> Vec<ast::KeyValue> {
    pair.into_inner()
        .filter(|p| p.as_rule() == Rule::global_kv)
        .map(|p| {
            let mut inner = p.into_inner();
            let key = inner
                .next()
                .map(|k| k.as_str().trim().to_owned())
                .unwrap_or_default();
            let value = inner
                .next()
                .map(|v| clean_value(v.as_str()))
                .unwrap_or_default();
            ast::KeyValue { key, value }
        })
        .collect()
}

fn parse_entry_block(pair: pest::iterators::Pair<Rule>) -> Vec<ast::Entry> {
    pair.into_inner()
        .filter(|p| p.as_rule() == Rule::sub_entry || p.as_rule() == Rule::node_entry)
        .filter_map(|p| {
            let inner = p.into_inner().next()?;
            match inner.as_rule() {
                Rule::sub_tagged | Rule::node_tagged => {
                    let mut parts = inner.into_inner();
                    let key = parts
                        .next()
                        .map(|k| k.as_str().trim().to_owned())
                        .unwrap_or_default();
                    let value = parts
                        .next()
                        .map(|v| clean_value(v.as_str()))
                        .unwrap_or_default();
                    Some(ast::Entry::Tagged { key, value })
                }
                Rule::sub_untagged | Rule::node_untagged => {
                    let value = inner
                        .into_inner()
                        .next()
                        .map(|v| clean_value(v.as_str()))
                        .unwrap_or_default();
                    Some(ast::Entry::Untagged(value))
                }
                _ => None,
            }
        })
        .collect()
}

fn parse_dns_section(pair: pest::iterators::Pair<Rule>) -> ast::DnsSection {
    let mut section = ast::DnsSection::default();

    for p in pair.into_inner() {
        if p.as_rule() != Rule::dns_content {
            continue;
        }
        let Some(inner) = p.into_inner().next() else {
            continue;
        };
        match inner.as_rule() {
            Rule::dns_kv => {
                let kv = parse_single_kv(inner);
                section.entries.push(kv);
            }
            Rule::upstream_block => {
                section.upstream = inner
                    .into_inner()
                    .filter(|pp| pp.as_rule() == Rule::upstream_entry)
                    .map(|pp| parse_single_kv(pp))
                    .collect();
            }
            Rule::dns_routing_block => {
                for rp in inner.into_inner() {
                    if rp.as_rule() != Rule::dns_routing_content {
                        continue;
                    }
                    let Some(rc) = rp.into_inner().next() else {
                        continue;
                    };
                    match rc.as_rule() {
                        Rule::request_block => {
                            section.request_rules = parse_dns_routing_rules(rc);
                        }
                        Rule::response_block => {
                            section.response_rules = parse_dns_routing_rules(rc);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    section
}

fn parse_dns_routing_rules(pair: pest::iterators::Pair<Rule>) -> Vec<ast::RoutingRule> {
    pair.into_inner()
        .filter(|p| p.as_rule() == Rule::dns_routing_rule)
        .map(|p| parse_routing_rule(p))
        .collect()
}

fn parse_routing_rule(pair: pest::iterators::Pair<Rule>) -> ast::RoutingRule {
    let mut inner = pair.into_inner();
    let condition = inner
        .next()
        .map(|p| p.as_str().trim().to_owned())
        .unwrap_or_default();
    let target = inner
        .next()
        .map(|p| p.as_str().trim().to_owned())
        .unwrap_or_default();
    ast::RoutingRule { condition, target }
}

fn parse_group_section(pair: pest::iterators::Pair<Rule>) -> Vec<ast::GroupDef> {
    pair.into_inner()
        .filter(|p| p.as_rule() == Rule::group_def)
        .map(|p| {
            let mut inner = p.into_inner();
            let name = inner.next().map(|n| n.as_str().to_owned()).unwrap_or_default();

            let mut filters = Vec::new();
            let mut policy = ast::PolicyDef::default();
            let mut extra = Vec::new();

            for content in inner {
                if content.as_rule() != Rule::group_content {
                    continue;
                }
                let Some(inner_rule) = content.into_inner().next() else {
                    continue;
                };
                match inner_rule.as_rule() {
                    Rule::filter_line => {
                        filters.push(parse_filter_line(inner_rule));
                    }
                    Rule::policy_line => {
                        policy = parse_policy_line(inner_rule);
                    }
                    Rule::group_kv => {
                        extra.push(parse_single_kv(inner_rule));
                    }
                    _ => {}
                }
            }

            ast::GroupDef {
                name,
                filters,
                policy,
                extra,
            }
        })
        .collect()
}

fn parse_filter_line(pair: pest::iterators::Pair<Rule>) -> ast::FilterDef {
    let mut inner = pair.into_inner();
    let expression = inner
        .next()
        .map(|p| p.as_str().trim().to_owned())
        .unwrap_or_default();
    let latency_offset = inner
        .next()
        .map(|p| {
            p.into_inner()
                .next()
                .map(|pp| pp.as_str().trim().to_owned())
                .unwrap_or_default()
        });
    ast::FilterDef {
        expression,
        latency_offset,
    }
}

fn parse_policy_line(pair: pest::iterators::Pair<Rule>) -> ast::PolicyDef {
    let inner = pair.into_inner().next();
    let Some(pv) = inner else {
        return ast::PolicyDef::default();
    };

    let mut pv_inner = pv.into_inner();
    let name = pv_inner
        .next()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_default();

    let index = pv_inner.next().and_then(|p| p.as_str().parse::<usize>().ok());

    match name.as_str() {
        "random" => ast::PolicyDef::Random,
        "fixed" => ast::PolicyDef::Fixed(index.unwrap_or(0)),
        "min" => ast::PolicyDef::Min,
        "min_moving_avg" => ast::PolicyDef::MinMovingAvg,
        "min_avg10" => ast::PolicyDef::MinAvg10,
        _ => ast::PolicyDef::default(),
    }
}

fn parse_routing_section(pair: pest::iterators::Pair<Rule>) -> ast::RoutingSection {
    let mut section = ast::RoutingSection::default();

    for p in pair.into_inner() {
        if p.as_rule() != Rule::routing_content {
            continue;
        }
        let inner = p.into_inner().next().unwrap();
        match inner.as_rule() {
            Rule::routing_rule => {
                section.rules.push(parse_routing_rule(inner));
            }
            Rule::fallback_line => {
                let mut fi = inner.into_inner();
                section.fallback =
                    fi.next().map(|t| t.as_str().trim().to_owned());
            }
            _ => {}
        }
    }

    section
}

fn parse_single_kv(pair: pest::iterators::Pair<Rule>) -> ast::KeyValue {
    let mut inner = pair.into_inner();
    let key = inner.next().map(|k| k.as_str().trim().to_owned()).unwrap_or_default();
    let value = inner
        .next()
        .map(|v| clean_value(v.as_str()))
        .unwrap_or_default();
    ast::KeyValue { key, value }
}

fn clean_value(s: &str) -> String {
    let trimmed = s.trim();
    if (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        || (trimmed.starts_with('"') && trimmed.ends_with('"'))
    {
        trimmed[1..trimmed.len() - 1].to_owned()
    } else {
        trimmed.to_owned()
    }
}
