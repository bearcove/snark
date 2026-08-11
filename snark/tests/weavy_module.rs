use snark::module::{SnarkModule, SnarkModuleInspection};

const FIXTURE_GRAMMAR: &str = r#"{
  "name": "module_fixture",
  "rules": {
    "document": {
      "type": "REPEAT1",
      "content": {
        "type": "CHOICE",
        "members": [
          { "type": "STRING", "value": "let" },
          { "type": "PATTERN", "value": "[a-z]+", "flags": "i" }
        ]
      }
    }
  }
}"#;

#[test]
fn module_round_trip_matches_live_parser_without_construction_workspace() {
    let built = SnarkModule::compile_grammar_json(FIXTURE_GRAMMAR).expect("compile");
    let live = built.parse("letName", None).expect("live parse");

    let first = built.save().expect("save");
    let loaded = SnarkModule::load(&first).expect("load");
    let second = loaded.save().expect("save again");
    let loaded_tree = loaded.parse("letName", None).expect("loaded parse");
    assert_eq!(loaded.grammar_fingerprint(), built.grammar_fingerprint());

    assert_eq!(first, second);
    assert_eq!(loaded_tree, live);
    assert!(loaded.parse_table().item_sets().is_empty());
    assert!(loaded.parse_table().transitions().is_empty());
    assert_eq!(
        loaded.parse_table().states().len(),
        built.parse_table().states().len()
    );
    assert_eq!(
        loaded.parse_table().conflicts().len(),
        built.parse_table().conflicts().len()
    );
    assert_eq!(loaded.regex_compile_count(), loaded.unique_regex_count());
}

#[test]
fn module_inspection_reports_snark_constants_and_sections() {
    let built = SnarkModule::compile_grammar_json(FIXTURE_GRAMMAR).expect("compile");
    let bytes = built.save().expect("save");
    let report: SnarkModuleInspection = SnarkModule::inspect(&bytes).expect("inspect");
    assert_eq!(report.constant_count, 4);
    assert!(
        report
            .sections
            .iter()
            .any(|section| section.name == "program")
    );
    assert!(
        report
            .sections
            .iter()
            .any(|section| section.name == "constants")
    );
    assert!(
        report
            .dialects
            .iter()
            .any(|dialect| dialect.name() == "snark")
    );
}
