//! Compare live parser construction with encoding and loading a precompiled artifact.

use std::{env, path::PathBuf, time::Instant};

use snark::artifact::{ParserArtifact, ParserArtifactBuilder};

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn main() {
    let grammar_js = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: artifact_timing GRAMMAR_JS");
    let grammar_json = snark_dsl::emit_with_boa(&grammar_js).expect("emit grammar.js -> json");

    let start = Instant::now();
    let built = ParserArtifactBuilder::from_grammar_json(&grammar_json).expect("build artifact");
    let live_ms = elapsed_ms(start);

    let start = Instant::now();
    let parser_bytes = facet_postcard::to_vec(built.parser_grammar()).expect("encode parser");
    let parser_encode_ms = elapsed_ms(start);
    let start = Instant::now();
    let table_bytes = facet_postcard::to_vec(built.parse_table()).expect("encode table");
    let table_encode_ms = elapsed_ms(start);

    let start = Instant::now();
    let bytes = built.encode().expect("encode artifact");
    let encode_ms = elapsed_ms(start);

    let start = Instant::now();
    let loaded = ParserArtifact::load(&bytes, built.grammar_fingerprint()).expect("load artifact");
    let load_ms = elapsed_ms(start);

    assert_eq!(loaded.parser_grammar(), built.parser_grammar());
    assert_eq!(loaded.parse_table(), built.parse_table());
    assert_eq!(loaded.plan().analysis(), built.plan().analysis());

    println!("grammar.json bytes: {}", grammar_json.len());
    println!(
        "parser bytes: {} ({parser_encode_ms:.3} ms)",
        parser_bytes.len()
    );
    println!(
        "table bytes: {} ({table_encode_ms:.3} ms)",
        table_bytes.len()
    );
    println!("artifact bytes: {}", bytes.len());
    println!("states: {}", loaded.parse_table().states().len());
    println!("conflicts: {}", loaded.parse_table().conflicts().len());
    println!("live table + plan build: {live_ms:.3} ms");
    println!("artifact encode: {encode_ms:.3} ms");
    println!("artifact load: {load_ms:.3} ms");
    println!("load speedup: {:.2}x", live_ms / load_ms);
}
