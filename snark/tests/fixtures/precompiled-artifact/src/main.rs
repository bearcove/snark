use snark::{
    artifact::{ParserArtifact, grammar_fingerprint},
    lower::weavy::parse_prepared_weavy_tree,
};

const GRAMMAR: &str = include_str!("../grammar.json");
const ARTIFACT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/parser.snark"));

fn main() {
    let parser = ParserArtifact::load(ARTIFACT, grammar_fingerprint(GRAMMAR))
        .expect("load precompiled parser artifact");
    let tree = parse_prepared_weavy_tree(
        parser.plan(),
        parser.parser_grammar(),
        parser.parse_table(),
        "letName",
    )
    .expect("parse fixture input");
    assert_eq!(tree.kind, "document");
}
