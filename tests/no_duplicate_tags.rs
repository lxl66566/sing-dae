use std::{collections::HashSet, fs};

use sing_dae::{convert::dae_to_sing, dae::parser};
#[test]
fn no_duplicate_tags_when_group_named_direct() {
    let input = fs::read_to_string("assets/direct_group_conflict.dae").expect("read fixture");
    let dae_config = parser::parse(&input).expect("parse dae");

    let sing_config = dae_to_sing::convert(&dae_config).expect("convert to sing");

    let mut seen_tags = HashSet::new();
    for ob in &sing_config.outbounds {
        if let Some(tag) = &ob.tag {
            assert!(
                seen_tags.insert(tag.clone()),
                "duplicate outbound tag found: {tag}"
            );
        }
    }

    // built-in direct outbound with tag "direct" must still exist
    let has_builtin_direct = sing_config
        .outbounds
        .iter()
        .any(|ob| ob.tag.as_deref() == Some("direct") && ob.outbound_type == "direct");
    assert!(has_builtin_direct, "built-in direct outbound should exist");

    // the group named "direct" should have been renamed to "direct_group"
    let has_renamed_direct_group = sing_config
        .outbounds
        .iter()
        .any(|ob| ob.tag.as_deref() == Some("direct_group"));
    assert!(
        has_renamed_direct_group,
        "group 'direct' should be renamed to 'direct_group'"
    );

    // the built-in direct should be type "direct", the renamed group should be type
    // "urltest"
    let renamed_group = sing_config
        .outbounds
        .iter()
        .find(|ob| ob.tag.as_deref() == Some("direct_group"))
        .expect("direct_group outbound should exist");
    assert_eq!(
        renamed_group.outbound_type, "urltest",
        "renamed direct group should be urltest type"
    );
}
