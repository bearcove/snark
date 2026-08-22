# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/bearcove/snark/releases/tag/snark-dsl-v0.1.0) - 2026-08-22

### Added

- make generated Snark AST lowering fallible

### Fixed

- validate generated enum leaf shapes

### Other

- *(snark-dsl)* enable publication
- raw-escape keyword field names in typed-ast codegen ([#2465](https://github.com/bearcove/snark/pull/2465))
- unblock the pre-commit hook (internal dev-deps + arborium headers)
- fix rodin's failing checks, drop Boa for a real JS runtime
- vix + fable on the snark/weavy substrate: demand-driven build language, typed frames, one codegen ([#2431](https://github.com/bearcove/snark/pull/2431))
- apply rustfmt to snark spike files
- item 1: annotation-driven reflection builder (no hardcoded hints)
- capture inline AST-enrichment annotations from the DSL
- Support table-driven auto close rules
- Add node-driven auto close primitive
- Add declarative auto close runtime primitive
- Resolve inherited grammar modules in snark-dsl
- Resolve Arborium grammar helper modules
- Load ESM grammar helpers in snark-dsl
- Load CommonJS grammar helpers in snark-dsl
- Add declarative lexical primitives
- Load Tree-sitter grammar.js directly in Snark playground
