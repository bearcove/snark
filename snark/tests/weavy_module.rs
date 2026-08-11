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
    assert_eq!(loaded.runtime_state_count(), built.runtime_state_count());
    assert_eq!(
        loaded.runtime_conflict_count(),
        built.runtime_conflict_count()
    );
    assert_eq!(loaded.regex_compile_count(), loaded.unique_regex_count());
}

#[test]
fn live_parser_executes_through_runtime_facts_interface() {
    let module = SnarkModule::compile_grammar_json(FIXTURE_GRAMMAR).expect("compile");
    let before = module.runtime_facts_read_count();
    module.parse("letName", None).expect("parse");
    assert!(module.runtime_facts_read_count() > before);
}

#[test]
fn runtime_fact_rows_are_portable_copy_views() {
    assert!(snark::module::runtime_fact_rows_are_portable());
}

#[test]
fn module_inspection_reports_snark_constants_and_sections() {
    let built = SnarkModule::compile_grammar_json(FIXTURE_GRAMMAR).expect("compile");
    let bytes = built.save().expect("save");
    let report: SnarkModuleInspection = SnarkModule::inspect(&bytes).expect("inspect");
    assert_eq!(report.constant_count, 4);
    assert_eq!(report.constant_ranges.len(), 13);
    assert!(
        report
            .constant_ranges
            .iter()
            .all(|range| range.profile == weavy::module::StorageProfile::DenseAligned)
    );
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

#[test]
fn loaded_module_borrows_runtime_ranges_from_file_bytes() {
    let built = SnarkModule::compile_grammar_json(FIXTURE_GRAMMAR).expect("compile");
    let bytes = built.save().expect("save");
    let loaded = SnarkModule::load_borrowed(&bytes).expect("load");
    assert!(loaded.runtime_ranges_borrow(&bytes));
    assert_eq!(
        loaded.parse("letName", None).expect("parse"),
        built.parse("letName", None).expect("live"),
    );
}
