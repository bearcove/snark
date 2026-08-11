use snark::{
    artifact::{
        ArtifactLoadErrorKind, PARSER_ARTIFACT_FORMAT_VERSION, ParserArtifact,
        ParserArtifactBuilder, grammar_fingerprint,
    },
    lower::weavy::parse_prepared_weavy_tree,
};

const FIXTURE_GRAMMAR: &str = r#"{
  "name": "artifact_fixture",
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
fn precompiled_artifact_round_trips_and_matches_live_parse_behavior() {
    let built = ParserArtifactBuilder::from_grammar_json(FIXTURE_GRAMMAR).unwrap();
    let live_tree = parse_prepared_weavy_tree(
        built.plan(),
        built.parser_grammar(),
        built.parse_table(),
        "letName",
    )
    .unwrap();

    let runtime_table = built.parse_table().runtime_clone();
    assert!(runtime_table.item_sets().is_empty());
    assert!(runtime_table.transitions().is_empty());
    assert_eq!(
        runtime_table.states().len(),
        built.parse_table().states().len()
    );

    let bytes = built.encode().unwrap();
    let loaded = ParserArtifact::load(&bytes, built.grammar_fingerprint()).unwrap();
    let loaded_tree = parse_prepared_weavy_tree(
        loaded.plan(),
        loaded.parser_grammar(),
        loaded.parse_table(),
        "letName",
    )
    .unwrap();

    assert_eq!(loaded.parser_grammar(), built.parser_grammar());
    assert!(loaded.parse_table().item_sets().is_empty());
    assert!(loaded.parse_table().transitions().is_empty());
    assert_eq!(loaded.parse_table().states(), runtime_table.states());
    assert_eq!(loaded_tree, live_tree);
    assert_eq!(
        loaded.grammar_fingerprint(),
        grammar_fingerprint(FIXTURE_GRAMMAR)
    );
}

#[test]
fn artifact_encoding_is_deterministic() {
    let first = ParserArtifactBuilder::from_grammar_json(FIXTURE_GRAMMAR)
        .unwrap()
        .encode()
        .unwrap();
    let second = ParserArtifactBuilder::from_grammar_json(FIXTURE_GRAMMAR)
        .unwrap()
        .encode()
        .unwrap();

    assert_eq!(first, second);
}

#[test]
fn grammar_fingerprint_ignores_json_whitespace() {
    let compact = FIXTURE_GRAMMAR.replace([' ', '\n'], "");
    assert_eq!(
        grammar_fingerprint(FIXTURE_GRAMMAR),
        grammar_fingerprint(&compact)
    );
}

#[test]
fn artifact_load_rejects_fingerprint_mismatch_and_corruption() {
    let built = ParserArtifactBuilder::from_grammar_json(FIXTURE_GRAMMAR).unwrap();
    let mut bytes = built.encode().unwrap();

    let mismatch = ParserArtifact::load(&bytes, [0x55; 32]).unwrap_err();
    assert!(matches!(
        mismatch.kind(),
        ArtifactLoadErrorKind::GrammarFingerprintMismatch { .. }
    ));

    let last = bytes.last_mut().unwrap();
    *last ^= 0x80;
    let corrupt = ParserArtifact::load(&bytes, built.grammar_fingerprint()).unwrap_err();
    assert!(matches!(
        corrupt.kind(),
        ArtifactLoadErrorKind::ChecksumMismatch { .. } | ArtifactLoadErrorKind::Decode { .. }
    ));
}

#[test]
fn artifact_load_rejects_unknown_format_version() {
    let built = ParserArtifactBuilder::from_grammar_json(FIXTURE_GRAMMAR).unwrap();
    let mut bytes = built.encode().unwrap();
    bytes[8..12].copy_from_slice(&(PARSER_ARTIFACT_FORMAT_VERSION + 1).to_le_bytes());

    let error = ParserArtifact::load(&bytes, built.grammar_fingerprint()).unwrap_err();
    assert!(matches!(
        error.kind(),
        ArtifactLoadErrorKind::UnsupportedFormatVersion { .. }
    ));
}
