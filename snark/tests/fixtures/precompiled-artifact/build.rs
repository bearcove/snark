use std::{env, fs, path::PathBuf};

fn main() {
    let grammar_path = PathBuf::from("grammar.json");
    println!("cargo::rerun-if-changed={}", grammar_path.display());
    let grammar_json = fs::read_to_string(&grammar_path).expect("read fixture grammar");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"))
        .join("parser.snark");
    snark::artifact::compile_grammar_json_to_path(&grammar_json, output)
        .expect("compile fixture parser artifact");
}
