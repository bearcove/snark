//! Versioned precompiled parser artifacts for build-time generation and runtime loading.

use std::{error::Error, fmt};
#[cfg(feature = "json-import")]
use std::{fs, io, path::Path};

use facet::Facet;

use crate::{
    lower::weavy::{WeavyParsePlan, WeavyParsePlanData},
    parser::{ParseTable, ParserGrammar},
};
#[cfg(feature = "json-import")]
use crate::{
    grammar::RawGrammarJson,
    lexical::LexicalFacts,
    lower::weavy::WeavyParseError,
    parser::{ParserNormalizeError, ParserPrepareError, ParserTableBuildError},
    validated::{GrammarValidationError, ValidatedGrammar},
};

const ARTIFACT_MAGIC: [u8; 8] = *b"SNARKPAR";
/// Current binary parser artifact envelope and payload format version.
pub const PARSER_ARTIFACT_FORMAT_VERSION: u32 = 1;
const ARTIFACT_COMPILER_VERSION: &str =
    concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION"));
const HEADER_LEN: usize = 8 + 4 + 32 + 32;

/// Stable 256-bit identity for normalized grammar input and artifact compiler version.
pub type GrammarFingerprint = [u8; 32];

/// Compute the grammar fingerprint expected by [`ParserArtifact::load`].
///
/// The grammar JSON is decoded and re-encoded through Facet before hashing, so
/// insignificant input whitespace does not change the fingerprint. The artifact
#[cfg(feature = "json-import")]
pub fn grammar_fingerprint(grammar_json: &str) -> GrammarFingerprint {
    match RawGrammarJson::from_tree_sitter_json_str(grammar_json) {
        Ok(raw) => fingerprint_raw_grammar(&raw).unwrap_or_else(|_| fallback_fingerprint(grammar_json)),
        Err(_) => fallback_fingerprint(grammar_json),
    }
}
#[cfg(feature = "json-import")]
fn fingerprint_raw_grammar(raw: &RawGrammarJson) -> Result<GrammarFingerprint, ArtifactBuildError> {
    let normalized = facet_postcard::to_vec(raw).map_err(|source| {
        ArtifactBuildError::new(ArtifactBuildErrorKind::Encode {
            message: source.to_string(),
        })
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"snark-parser-artifact-grammar\0");
    hasher.update(&PARSER_ARTIFACT_FORMAT_VERSION.to_le_bytes());
    hasher.update(ARTIFACT_COMPILER_VERSION.as_bytes());
    hasher.update(&normalized);
    Ok(*hasher.finalize().as_bytes())
}
#[cfg(feature = "json-import")]
fn fallback_fingerprint(grammar_json: &str) -> GrammarFingerprint {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"snark-parser-artifact-invalid-grammar\0");
    hasher.update(&PARSER_ARTIFACT_FORMAT_VERSION.to_le_bytes());
    hasher.update(ARTIFACT_COMPILER_VERSION.as_bytes());
    hasher.update(grammar_json.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Build-time parser/table/plan construction ready to encode as an artifact.
#[cfg(feature = "json-import")]
#[derive(Debug)]
pub struct ParserArtifactBuilder {
    grammar_fingerprint: GrammarFingerprint,
    parser_grammar: ParserGrammar,
    parse_table: ParseTable,
    plan: WeavyParsePlan,
}

#[cfg(feature = "json-import")]
impl ParserArtifactBuilder {
    /// Compile a Tree-sitter-compatible grammar JSON document into runtime parser data.
    pub fn from_grammar_json(grammar_json: &str) -> Result<Self, ArtifactBuildError> {
        let raw = RawGrammarJson::from_tree_sitter_json_str(grammar_json)
            .map_err(|source| ArtifactBuildError::new(ArtifactBuildErrorKind::Import {
                message: source.to_string(),
            }))?;
        let grammar_fingerprint = fingerprint_raw_grammar(&raw)?;
        let validated = ValidatedGrammar::from_raw(&raw).map_err(ArtifactBuildError::validation)?;
        let lexical = LexicalFacts::from_grammar(&validated);
        let parser_grammar = ParserGrammar::normalize_from_validated(&validated, &lexical)
            .map_err(ArtifactBuildError::normalize)?
            .prepare_productions_for_items()
            .map_err(ArtifactBuildError::prepare)?;
        let parse_table = ParseTable::from_grammar(&parser_grammar)
            .map_err(ArtifactBuildError::table)?;
        let plan = WeavyParsePlan::new(&validated, &parser_grammar, &parse_table)
            .map_err(ArtifactBuildError::plan)?;
        Ok(Self {
            grammar_fingerprint,
            parser_grammar,
            parse_table,
            plan,
        })
    }

    /// Grammar fingerprint embedded in the artifact.
    pub const fn grammar_fingerprint(&self) -> GrammarFingerprint {
        self.grammar_fingerprint
    }

    /// Prepared parser grammar produced during build-time compilation.
    pub const fn parser_grammar(&self) -> &ParserGrammar {
        &self.parser_grammar
    }

    /// Generated parse table produced during build-time compilation.
    pub const fn parse_table(&self) -> &ParseTable {
        &self.parse_table
    }

    /// Prepared Weavy plan produced during build-time compilation.
    pub const fn plan(&self) -> &WeavyParsePlan {
        &self.plan
    }

    /// Encode a deterministic versioned artifact.
    pub fn encode(&self) -> Result<Vec<u8>, ArtifactBuildError> {
        let payload = ArtifactPayload {
            compiler_version: ARTIFACT_COMPILER_VERSION.to_owned(),
            parser_grammar: self.parser_grammar.clone(),
            parse_table: self.parse_table.clone(),
            weavy_plan: self.plan.artifact_data(),
        };
        let payload = facet_postcard::to_vec(&payload).map_err(|source| {
            ArtifactBuildError::new(ArtifactBuildErrorKind::Encode {
                message: source.to_string(),
            })
        })?;
        let checksum = blake3::hash(&payload);
        let mut bytes = Vec::with_capacity(HEADER_LEN + payload.len());
        bytes.extend_from_slice(&ARTIFACT_MAGIC);
        bytes.extend_from_slice(&PARSER_ARTIFACT_FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.grammar_fingerprint);
        bytes.extend_from_slice(checksum.as_bytes());
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    /// Encode and write an artifact for a downstream `build.rs`.
    pub fn write_to_path(&self, path: impl AsRef<Path>) -> Result<(), ArtifactBuildError> {
        let path = path.as_ref();
        let bytes = self.encode()?;
        fs::write(path, bytes).map_err(|source| {
            ArtifactBuildError::new(ArtifactBuildErrorKind::Write {
                path: path.display().to_string(),
                message: source.to_string(),
            })
        })
    }
}

/// Compile grammar JSON and write a precompiled parser artifact in one call.
#[cfg(feature = "json-import")]
pub fn compile_grammar_json_to_path(
    grammar_json: &str,
    path: impl AsRef<Path>,
) -> Result<GrammarFingerprint, ArtifactBuildError> {
    let built = ParserArtifactBuilder::from_grammar_json(grammar_json)?;
    built.write_to_path(path)?;
    Ok(built.grammar_fingerprint())
}

/// Runtime parser bundle loaded from a precompiled artifact.
#[derive(Debug)]
pub struct ParserArtifact {
    grammar_fingerprint: GrammarFingerprint,
    parser_grammar: ParserGrammar,
    parse_table: ParseTable,
    plan: WeavyParsePlan,
}

impl ParserArtifact {
    /// Load an artifact from `include_bytes!` output or any byte slice.
    ///
    /// This path does not call [`ParseTable::from_grammar`] or
    /// [`WeavyParsePlan::new`]. It validates the envelope, deserializes the
    /// prepared parser/table data, and materializes only runtime matcher caches
    /// from the plan's serialized plain source data.
    pub fn load(
        bytes: &[u8],
        expected_fingerprint: GrammarFingerprint,
    ) -> Result<Self, ArtifactLoadError> {
        let header = ArtifactHeader::decode(bytes)?;
        if header.format_version != PARSER_ARTIFACT_FORMAT_VERSION {
            return Err(ArtifactLoadError::new(
                ArtifactLoadErrorKind::UnsupportedFormatVersion {
                    expected: PARSER_ARTIFACT_FORMAT_VERSION,
                    actual: header.format_version,
                },
            ));
        }
        if header.grammar_fingerprint != expected_fingerprint {
            return Err(ArtifactLoadError::new(
                ArtifactLoadErrorKind::GrammarFingerprintMismatch {
                    expected: expected_fingerprint,
                    actual: header.grammar_fingerprint,
                },
            ));
        }
        let actual_checksum = *blake3::hash(header.payload).as_bytes();
        if actual_checksum != header.checksum {
            return Err(ArtifactLoadError::new(
                ArtifactLoadErrorKind::ChecksumMismatch {
                    expected: header.checksum,
                    actual: actual_checksum,
                },
            ));
        }
        let payload: ArtifactPayload = facet_postcard::from_slice(header.payload).map_err(|source| {
            ArtifactLoadError::new(ArtifactLoadErrorKind::Decode {
                message: source.to_string(),
            })
        })?;
        if payload.compiler_version != ARTIFACT_COMPILER_VERSION {
            return Err(ArtifactLoadError::new(
                ArtifactLoadErrorKind::CompilerVersionMismatch {
                    expected: ARTIFACT_COMPILER_VERSION.to_owned(),
                    actual: payload.compiler_version,
                },
            ));
        }
        validate_loaded_data(&payload.parser_grammar, &payload.parse_table)?;
        let plan = WeavyParsePlan::from_artifact_data(
            payload.weavy_plan,
            &payload.parser_grammar,
            &payload.parse_table,
        )
        .map_err(|source| {
            ArtifactLoadError::new(ArtifactLoadErrorKind::Plan {
                message: source.to_string(),
            })
        })?;
        Ok(Self {
            grammar_fingerprint: header.grammar_fingerprint,
            parser_grammar: payload.parser_grammar,
            parse_table: payload.parse_table,
            plan,
        })
    }

    /// Embedded grammar fingerprint.
    pub const fn grammar_fingerprint(&self) -> GrammarFingerprint {
        self.grammar_fingerprint
    }

    /// Prepared parser grammar loaded from the artifact.
    pub const fn parser_grammar(&self) -> &ParserGrammar {
        &self.parser_grammar
    }

    /// Generated parse table loaded from the artifact.
    pub const fn parse_table(&self) -> &ParseTable {
        &self.parse_table
    }

    /// Prepared Weavy runtime plan loaded from the artifact.
    pub const fn plan(&self) -> &WeavyParsePlan {
        &self.plan
    }
}

fn validate_loaded_data(
    parser: &ParserGrammar,
    table: &ParseTable,
) -> Result<(), ArtifactLoadError> {
    if parser.stage() != crate::parser::ParserGenerationStage::Productions {
        return Err(ArtifactLoadError::new(ArtifactLoadErrorKind::InvalidData {
            message: format!("parser grammar has unexpected stage {:?}", parser.stage()),
        }));
    }
    if table.states().is_empty() {
        return Err(ArtifactLoadError::new(ArtifactLoadErrorKind::InvalidData {
            message: "parse table has no states".to_owned(),
        }));
    }
    for (index, state) in table.states().iter().enumerate() {
        if state.id().get() as usize != index {
            return Err(ArtifactLoadError::new(ArtifactLoadErrorKind::InvalidData {
                message: format!("parse state {index} has non-dense id {}", state.id().get()),
            }));
        }
        if state.lex_mode().get() as usize >= table.lexical_modes().len() {
            return Err(ArtifactLoadError::new(ArtifactLoadErrorKind::InvalidData {
                message: format!("parse state {index} references a missing lexical mode"),
            }));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Facet, PartialEq, Eq)]
struct ArtifactPayload {
    compiler_version: String,
    parser_grammar: ParserGrammar,
    parse_table: ParseTable,
    weavy_plan: WeavyParsePlanData,
}

struct ArtifactHeader<'a> {
    format_version: u32,
    grammar_fingerprint: GrammarFingerprint,
    checksum: [u8; 32],
    payload: &'a [u8],
}

impl<'a> ArtifactHeader<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Self, ArtifactLoadError> {
        if bytes.len() < HEADER_LEN {
            return Err(ArtifactLoadError::new(ArtifactLoadErrorKind::Truncated {
                minimum: HEADER_LEN,
                actual: bytes.len(),
            }));
        }
        if bytes[..8] != ARTIFACT_MAGIC {
            let mut actual = [0; 8];
            actual.copy_from_slice(&bytes[..8]);
            return Err(ArtifactLoadError::new(ArtifactLoadErrorKind::InvalidMagic {
                expected: ARTIFACT_MAGIC,
                actual,
            }));
        }
        let format_version = u32::from_le_bytes(bytes[8..12].try_into().expect("fixed header range"));
        let mut grammar_fingerprint = [0; 32];
        grammar_fingerprint.copy_from_slice(&bytes[12..44]);
        let mut checksum = [0; 32];
        checksum.copy_from_slice(&bytes[44..76]);
        Ok(Self {
            format_version,
            grammar_fingerprint,
            checksum,
            payload: &bytes[HEADER_LEN..],
        })
    }
}

/// Error while constructing or writing a precompiled artifact.
#[cfg(feature = "json-import")]
#[derive(Debug)]
pub struct ArtifactBuildError {
    kind: ArtifactBuildErrorKind,
}

#[cfg(feature = "json-import")]
impl ArtifactBuildError {
    fn new(kind: ArtifactBuildErrorKind) -> Self {
        Self { kind }
    }

    fn validation(source: GrammarValidationError) -> Self {
        Self::new(ArtifactBuildErrorKind::Validation {
            message: source.to_string(),
        })
    }

    fn normalize(source: ParserNormalizeError) -> Self {
        Self::new(ArtifactBuildErrorKind::Normalize {
            message: source.to_string(),
        })
    }

    fn prepare(source: ParserPrepareError) -> Self {
        Self::new(ArtifactBuildErrorKind::Prepare {
            message: source.to_string(),
        })
    }

    fn table(source: ParserTableBuildError) -> Self {
        Self::new(ArtifactBuildErrorKind::Table {
            message: source.to_string(),
        })
    }

    fn plan(source: WeavyParseError) -> Self {
        Self::new(ArtifactBuildErrorKind::Plan {
            message: source.to_string(),
        })
    }

    /// Error category.
    pub const fn kind(&self) -> &ArtifactBuildErrorKind {
        &self.kind
    }
}

#[cfg(feature = "json-import")]
impl fmt::Display for ArtifactBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ArtifactBuildErrorKind::Import { message } => write!(f, "grammar import failed: {message}"),
            ArtifactBuildErrorKind::Validation { message } => write!(f, "grammar validation failed: {message}"),
            ArtifactBuildErrorKind::Normalize { message } => write!(f, "parser normalization failed: {message}"),
            ArtifactBuildErrorKind::Prepare { message } => write!(f, "parser preparation failed: {message}"),
            ArtifactBuildErrorKind::Table { message } => write!(f, "parse-table construction failed: {message}"),
            ArtifactBuildErrorKind::Plan { message } => write!(f, "Weavy plan construction failed: {message}"),
            ArtifactBuildErrorKind::Encode { message } => write!(f, "artifact encoding failed: {message}"),
            ArtifactBuildErrorKind::Write { path, message } => write!(f, "could not write artifact {path}: {message}"),
        }
    }
}

#[cfg(feature = "json-import")]
impl Error for ArtifactBuildError {}
#[cfg(feature = "json-import")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactBuildErrorKind {
    /// Grammar JSON import failed.
    Import {
        /// Underlying import message.
        message: String,
    },
    /// Validated grammar construction failed.
    Validation {
        /// Underlying validation message.
        message: String,
    },
    /// Parser normalization failed.
    Normalize {
        /// Underlying normalization message.
        message: String,
    },
    /// Parser production preparation failed.
    Prepare {
        /// Underlying preparation message.
        message: String,
    },
    /// Parse-table construction failed.
    Table {
        /// Underlying table construction message.
        message: String,
    },
    /// Weavy plan construction failed.
    Plan {
        /// Underlying plan construction message.
        message: String,
    },
    /// Facet-postcard encoding failed.
    Encode {
        /// Underlying encoder message.
        message: String,
    },
    /// Writing the artifact file failed.
    Write {
        /// Destination path.
        path: String,
        /// Underlying I/O message.
        message: String,
    },
}

/// Error while validating or loading a precompiled artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactLoadError {
    kind: ArtifactLoadErrorKind,
}

impl ArtifactLoadError {
    fn new(kind: ArtifactLoadErrorKind) -> Self {
        Self { kind }
    }

    /// Error category.
    pub const fn kind(&self) -> &ArtifactLoadErrorKind {
        &self.kind
    }
}

impl fmt::Display for ArtifactLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ArtifactLoadErrorKind::Truncated { minimum, actual } => write!(f, "artifact is truncated: expected at least {minimum} bytes, found {actual}"),
            ArtifactLoadErrorKind::InvalidMagic { .. } => write!(f, "artifact magic does not match Snark parser artifacts"),
            ArtifactLoadErrorKind::UnsupportedFormatVersion { expected, actual } => write!(f, "artifact format version {actual} is unsupported; expected {expected}"),
            ArtifactLoadErrorKind::GrammarFingerprintMismatch { .. } => write!(f, "artifact grammar fingerprint does not match the expected grammar"),
            ArtifactLoadErrorKind::ChecksumMismatch { .. } => write!(f, "artifact payload checksum mismatch"),
            ArtifactLoadErrorKind::Decode { message } => write!(f, "artifact payload decode failed: {message}"),
            ArtifactLoadErrorKind::CompilerVersionMismatch { expected, actual } => write!(f, "artifact compiler version {actual} does not match runtime {expected}"),
            ArtifactLoadErrorKind::InvalidData { message } => write!(f, "artifact payload is structurally invalid: {message}"),
            ArtifactLoadErrorKind::Plan { message } => write!(f, "artifact Weavy plan materialization failed: {message}"),
        }
    }
}

impl Error for ArtifactLoadError {}

/// Runtime artifact validation/load error category.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactLoadErrorKind {
    /// Artifact bytes are shorter than the fixed envelope header.
    Truncated {
        /// Required fixed header length.
        minimum: usize,
        /// Actual artifact length.
        actual: usize,
    },
    /// Envelope magic is not recognized.
    InvalidMagic {
        /// Snark parser artifact magic.
        expected: [u8; 8],
        /// Magic found in the input.
        actual: [u8; 8],
    },
    /// Envelope format version is unsupported.
    UnsupportedFormatVersion {
        /// Runtime-supported format version.
        expected: u32,
        /// Version embedded in the artifact.
        actual: u32,
    },
    /// The caller expected a different normalized grammar/compiler fingerprint.
    GrammarFingerprintMismatch {
        /// Fingerprint expected by the caller.
        expected: GrammarFingerprint,
        /// Fingerprint embedded in the artifact.
        actual: GrammarFingerprint,
    },
    /// Payload bytes do not match the embedded checksum.
    ChecksumMismatch {
        /// Checksum embedded in the envelope.
        expected: [u8; 32],
        /// Checksum computed from payload bytes.
        actual: [u8; 32],
    },
    /// Facet-postcard payload decoding failed.
    Decode {
        /// Underlying decoder message.
        message: String,
    },
    /// Artifact compiler identity does not match the runtime crate.
    CompilerVersionMismatch {
        /// Runtime compiler identity.
        expected: String,
        /// Compiler identity embedded in the payload.
        actual: String,
    },
    /// Decoded parser/table invariants are invalid.
    InvalidData {
        /// Structural validation message.
        message: String,
    },
    /// Runtime-only plan cache materialization failed.
    Plan {
        /// Underlying plan materialization message.
        message: String,
    },
}

#[cfg(feature = "json-import")]
impl From<io::Error> for ArtifactBuildError {
    fn from(source: io::Error) -> Self {
        Self::new(ArtifactBuildErrorKind::Write {
            path: "<unknown>".to_owned(),
            message: source.to_string(),
        })
    }
}
