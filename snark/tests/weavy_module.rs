use snark::module::{
    SnarkModule, SnarkModuleError, SnarkModuleInspection, SnarkModuleLoadLimits,
};
use weavy_phon::{CodecError, ContainerLimitKind};

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
    let loaded = SnarkModule::load_borrowed(&first).expect("load borrowed");
    let second = built.save().expect("save again");
    let loaded_tree = loaded.parse("letName", None).expect("loaded parse");
    assert_eq!(loaded.runtime_state_count(), built.runtime_state_count());

    assert_eq!(first, second);
    assert_eq!(loaded_tree, live);
    assert_eq!(loaded.regex_compile_count(), loaded.unique_regex_count());
}

#[test]
fn borrowed_module_enforces_caller_selected_decode_ceiling() {
    let built = SnarkModule::compile_grammar_json(FIXTURE_GRAMMAR).expect("compile");
    let bytes = built.save().expect("save");
    let limits = SnarkModuleLoadLimits::default().with_max_decoded_bytes(0);

    assert!(matches!(
        SnarkModule::load_borrowed_with_limits(&bytes, limits),
        Err(SnarkModuleError::Codec(CodecError::ContainerLimitExceeded {
            kind: ContainerLimitKind::DecodedBytes,
            configured: 0,
            actual,
        })) if actual > 0
    ));
    SnarkModule::load_borrowed(&bytes).expect("default bounded load");
}

#[test]
fn loaded_module_uses_only_module_local_runtime_data() {
    let built = SnarkModule::compile_grammar_json(FIXTURE_GRAMMAR).expect("compile");
    let bytes = built.save().expect("save");
    let loaded = SnarkModule::load_borrowed(&bytes).expect("load borrowed");
    let report: SnarkModuleInspection = SnarkModule::inspect(&bytes).expect("inspect");

    assert_eq!(report.constant_count, 3);
    assert!(loaded.runtime_ranges_borrow(&bytes));
    assert_eq!(loaded.parse("letName", None), built.parse("letName", None));
}

#[test]
fn borrowed_module_uses_persisted_runtime_caches() {
    let built = SnarkModule::compile_grammar_json(FIXTURE_GRAMMAR).expect("compile");
    let bytes = built.save().expect("save");
    let loaded = SnarkModule::load_borrowed(&bytes).expect("load borrowed");

    assert_eq!(loaded.unique_regex_count(), built.unique_regex_count());
    assert_eq!(loaded.regex_compile_count(), loaded.unique_regex_count());
    assert_eq!(loaded.runtime_state_count(), built.runtime_state_count());
    assert_eq!(
        loaded.runtime_conflict_count(),
        built.runtime_conflict_count()
    );
}

#[test]
fn borrowed_module_supports_recovery_and_incremental_sessions() {
    let built = SnarkModule::compile_grammar_json(FIXTURE_GRAMMAR).expect("compile");
    let bytes = built.save().expect("save");
    let loaded = SnarkModule::load_borrowed(&bytes).expect("load borrowed");

    let recovered = loaded
        .parse_recovering("let?Name", None)
        .expect("borrowed recovery");
    assert_eq!(
        recovered
            .accepted_resolved_cst(loaded.parser_grammar(), "let?Name")
            .expect("recovered CST")
            .root()
            .expect("root")
            .kind(),
        "document"
    );

    let mut session = loaded.session();
    session
        .parse_recovering("letName")
        .expect("session baseline");
    let edited = "let?Name";
    let reparsed = session
        .reparse_recovering(snark::parser::ParserInputEdit::new(3, 3, 4), edited)
        .expect("borrowed incremental recovery");
    assert!(
        reparsed
            .accepted_resolved_cst(loaded.parser_grammar(), edited)
            .is_some()
    );
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
    assert_eq!(report.constant_count, 3);
    assert_eq!(report.constant_ranges.len(), 15);
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

#[test]
fn borrowed_module_preserves_glr_action_sets() {
    const AMBIGUOUS_GRAMMAR: &str = r#"{
      "name": "ambiguous_module",
      "rules": {
        "source_file": {
          "type": "CHOICE",
          "members": [
            { "type": "SYMBOL", "name": "left" },
            { "type": "SYMBOL", "name": "right" }
          ]
        },
        "left": { "type": "SYMBOL", "name": "token" },
        "right": { "type": "SYMBOL", "name": "token" },
        "token": { "type": "STRING", "value": "x" }
      }
    }"#;

    let built = SnarkModule::compile_grammar_json(AMBIGUOUS_GRAMMAR).expect("compile");
    let bytes = built.save().expect("save");
    let loaded = SnarkModule::load_borrowed(&bytes).expect("load borrowed");

    assert!(matches!(
        loaded.parse("x", None),
        Err(snark::lower::weavy::WeavyParseError::AmbiguousParse { .. })
    ));
}
