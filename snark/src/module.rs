//! Durable PHON-backed Snark parser modules.

use core::fmt;

use facet::Facet;
use phon::api;
use weavy::DenseLowered;
use weavy::ir::WeavyOp;
use weavy::module::{
    Constant, ConstantId, ConstantPool, ConstantReference, DialectRequirement, IntrinsicContract,
    ModuleManifest, ModuleVerifier, WeavyModule,
};
use weavy_phon::{CodecError, InspectionReport, IntrinsicCodec, SectionReport};

use crate::artifact::{ArtifactBuildError, GrammarFingerprint, ParserArtifactBuilder};
use crate::lower::weavy::{
    WeavyParseError, WeavyParsePlan, WeavyParsePlanData, WeavyParseReport,
    parse_prepared_weavy_recovering_with_report_and_scanner,
    parse_prepared_weavy_with_report_and_scanner,
};
use crate::parser::{ExternalScannerHost, ParseTable, ParserGrammar};

const GRAMMAR_FINGERPRINT_SCHEMA: u64 = 0xc067_9971_e3ea_4a4e;
const PARSER_GRAMMAR_SCHEMA: u64 = 0x38fe_226c_5a19_8d0e;
const PARSE_TABLE_SCHEMA: u64 = 0x2746_d4b8_93d0_e2ac;
const PARSE_PLAN_SCHEMA: u64 = 0x9fa7_5d2c_1b40_a866;

#[derive(Clone, Debug, Facet, PartialEq, Eq)]
struct SnarkModuleData {
    grammar_fingerprint: GrammarFingerprint,
    parser_grammar: ParserGrammar,
    parse_table: ParseTable,
    parse_plan: WeavyParsePlanData,
}

/// A self-contained admitted Snark parser module.
pub struct SnarkModule {
    grammar_fingerprint: GrammarFingerprint,
    parser_grammar: ParserGrammar,
    parse_table: ParseTable,
    plan: WeavyParsePlan,
}

impl SnarkModule {
    /// Compile grammar JSON into a runtime-only self-contained module.
    pub fn compile_grammar_json(grammar_json: &str) -> Result<Self, SnarkModuleError> {
        let built = ParserArtifactBuilder::from_grammar_json(grammar_json)?;
        Ok(Self {
            grammar_fingerprint: built.grammar_fingerprint(),
            parser_grammar: built.parser_grammar().clone(),
            parse_table: built.parse_table().runtime_clone(),
            plan: built.plan().clone(),
        })
    }

    /// Package already prepared runtime facts without parser-generator workspace.
    pub fn from_prepared(
        grammar_fingerprint: GrammarFingerprint,
        parser_grammar: ParserGrammar,
        parse_table: ParseTable,
        plan: WeavyParsePlan,
    ) -> Self {
        Self {
            grammar_fingerprint,
            parser_grammar,
            parse_table: parse_table.runtime_clone(),
            plan,
        }
    }

    /// Save the module as deterministic `.weavy` bytes.
    pub fn save(&self) -> Result<Vec<u8>, SnarkModuleError> {
        let data = SnarkModuleData {
            grammar_fingerprint: self.grammar_fingerprint,
            parser_grammar: self.parser_grammar.clone(),
            parse_table: self.parse_table.runtime_clone(),
            parse_plan: self.plan.artifact_data(),
        };
        let grammar = api::encode(&data.parser_grammar).map_err(SnarkModuleError::Phon)?;
        let table = api::encode(&data.parse_table).map_err(SnarkModuleError::Phon)?;
        let plan = api::encode(&data.parse_plan).map_err(SnarkModuleError::Phon)?;
        let module = WeavyModule::new(
            ModuleManifest::new(
                "snark.parser",
                [DialectRequirement::new("snark", 1, 0)],
                [0],
            ),
            DenseLowered::new(
                vec![
                    WeavyOp::Intrinsic(SnarkModuleIntrinsic::GrammarFingerprint(ConstantId::new(
                        0,
                    ))),
                    WeavyOp::Intrinsic(SnarkModuleIntrinsic::ParserGrammar(ConstantId::new(1))),
                    WeavyOp::Intrinsic(SnarkModuleIntrinsic::ParseTable(ConstantId::new(2))),
                    WeavyOp::Intrinsic(SnarkModuleIntrinsic::ParsePlan(ConstantId::new(3))),
                ],
                Vec::new(),
            ),
            ConstantPool::new(vec![
                Constant::new(
                    GRAMMAR_FINGERPRINT_SCHEMA,
                    data.grammar_fingerprint.to_vec(),
                ),
                Constant::new(PARSER_GRAMMAR_SCHEMA, grammar),
                Constant::new(PARSE_TABLE_SCHEMA, table),
                Constant::new(PARSE_PLAN_SCHEMA, plan),
            ]),
        );
        weavy_phon::save::<SnarkCodec>(&module).map_err(SnarkModuleError::Codec)
    }

    /// Load and admit a Snark module without rebuilding LR tables or lexer plans.
    pub fn load(bytes: &[u8]) -> Result<Self, SnarkModuleError> {
        let module = weavy_phon::load::<SnarkCodec>(bytes).map_err(SnarkModuleError::Codec)?;
        let admitted = ModuleVerifier::new([DialectRequirement::new("snark", 1, 0)])
            .admit(module)
            .map_err(SnarkModuleError::Admission)?;
        let constants = admitted.module().constants();
        if constants.len() != 4 {
            return Err(SnarkModuleError::WrongConstantCount(constants.len()));
        }
        let grammar_fingerprint: GrammarFingerprint = constants[0]
            .bytes()
            .try_into()
            .map_err(|_| SnarkModuleError::MalformedGrammarFingerprint)?;
        let parser_grammar: ParserGrammar =
            api::decode(constants[1].bytes()).map_err(SnarkModuleError::Phon)?;
        let parse_table: ParseTable =
            api::decode(constants[2].bytes()).map_err(SnarkModuleError::Phon)?;
        let parse_data: WeavyParsePlanData =
            api::decode(constants[3].bytes()).map_err(SnarkModuleError::Phon)?;
        let plan = WeavyParsePlan::from_artifact_data(parse_data, &parser_grammar, &parse_table)?;
        Ok(Self {
            grammar_fingerprint,
            parser_grammar,
            parse_table,
            plan,
        })
    }

    /// Inspect a module without linking its producing grammar.
    pub fn inspect(bytes: &[u8]) -> Result<SnarkModuleInspection, SnarkModuleError> {
        let report = weavy_phon::inspect(bytes).map_err(SnarkModuleError::Codec)?;
        Ok(report.into())
    }

    /// Fingerprint of the source grammar that produced this module.
    pub const fn grammar_fingerprint(&self) -> GrammarFingerprint {
        self.grammar_fingerprint
    }

    /// Runtime parser grammar obtained from module constants.
    pub const fn parser_grammar(&self) -> &ParserGrammar {
        &self.parser_grammar
    }

    /// Runtime-only LR/GLR table obtained from module constants.
    pub const fn parse_table(&self) -> &ParseTable {
        &self.parse_table
    }

    /// Admitted Weavy parser and lexer plan.
    pub const fn plan(&self) -> &WeavyParsePlan {
        &self.plan
    }

    /// Parse input using only runtime facts owned by this admitted module.
    pub fn parse(
        &self,
        input: &str,
        external_scanner: Option<&dyn ExternalScannerHost>,
    ) -> Result<WeavyParseReport, WeavyParseError> {
        parse_prepared_weavy_with_report_and_scanner(
            &self.plan,
            &self.parser_grammar,
            &self.parse_table,
            input,
            external_scanner,
        )
    }

    /// Parse input with skip-invalid recovery using runtime facts owned by this module.
    pub fn parse_recovering(
        &self,
        input: &str,
        external_scanner: Option<&dyn ExternalScannerHost>,
    ) -> Result<WeavyParseReport, WeavyParseError> {
        parse_prepared_weavy_recovering_with_report_and_scanner(
            &self.plan,
            &self.parser_grammar,
            &self.parse_table,
            input,
            external_scanner,
        )
    }

    /// Number of unique regular-expression specifications retained by the loaded plan.
    pub fn unique_regex_count(&self) -> usize {
        self.plan.unique_regex_count()
    }

    /// Number of regular-expression engine compilations performed for the admitted module.
    pub fn regex_compile_count(&self) -> usize {
        self.plan.regex_compile_count()
    }

    /// Encoded PHON sizes of all module constants in module-local ID order.
    pub fn constant_sizes(&self) -> Result<[usize; 4], SnarkModuleError> {
        Ok([
            self.grammar_fingerprint.len(),
            api::encode(&self.parser_grammar)
                .map_err(SnarkModuleError::Phon)?
                .len(),
            api::encode(&self.parse_table)
                .map_err(SnarkModuleError::Phon)?
                .len(),
            api::encode(&self.plan.artifact_data())
                .map_err(SnarkModuleError::Phon)?
                .len(),
        ])
    }
}

/// Discoverable Snark-specific projection of Weavy module inspection.
pub struct SnarkModuleInspection {
    /// Declared module name.
    pub module_name: String,
    /// Required dialects and versions.
    pub dialects: Vec<DialectRequirement>,
    /// Physical section inventory.
    pub sections: Vec<SectionReport>,
    /// Number of module-local constants.
    pub constant_count: usize,
}

impl From<InspectionReport> for SnarkModuleInspection {
    fn from(report: InspectionReport) -> Self {
        Self {
            module_name: report.module_name,
            dialects: report.dialects,
            sections: report.sections,
            constant_count: report.constant_count,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SnarkModuleIntrinsic {
    GrammarFingerprint(ConstantId),
    ParserGrammar(ConstantId),
    ParseTable(ConstantId),
    ParsePlan(ConstantId),
}

impl IntrinsicContract for SnarkModuleIntrinsic {
    fn constant_references(&self, visit: &mut dyn FnMut(ConstantReference)) {
        let (id, schema) = match self {
            Self::GrammarFingerprint(id) => (*id, GRAMMAR_FINGERPRINT_SCHEMA),
            Self::ParserGrammar(id) => (*id, PARSER_GRAMMAR_SCHEMA),
            Self::ParseTable(id) => (*id, PARSE_TABLE_SCHEMA),
            Self::ParsePlan(id) => (*id, PARSE_PLAN_SCHEMA),
        };
        visit(ConstantReference::new(id, schema));
    }
}

struct SnarkCodec;

impl IntrinsicCodec for SnarkCodec {
    type Intrinsic = SnarkModuleIntrinsic;
    const DIALECT: &'static str = "snark";
    const SCHEMA_ID: u64 = 0x99f3_525f_a240_6d1c;

    fn encode(intrinsic: &Self::Intrinsic, out: &mut Vec<u8>) {
        let (tag, id) = match intrinsic {
            SnarkModuleIntrinsic::GrammarFingerprint(id) => (0, *id),
            SnarkModuleIntrinsic::ParserGrammar(id) => (1, *id),
            SnarkModuleIntrinsic::ParseTable(id) => (2, *id),
            SnarkModuleIntrinsic::ParsePlan(id) => (3, *id),
        };
        out.push(tag);
        out.extend_from_slice(&id.index().to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self::Intrinsic, CodecError> {
        if bytes.len() != 5 {
            return Err(CodecError::MalformedIntrinsic);
        }
        let id = ConstantId::new(u32::from_le_bytes(bytes[1..].try_into().expect("length")));
        match bytes[0] {
            0 => Ok(SnarkModuleIntrinsic::GrammarFingerprint(id)),
            1 => Ok(SnarkModuleIntrinsic::ParserGrammar(id)),
            2 => Ok(SnarkModuleIntrinsic::ParseTable(id)),
            3 => Ok(SnarkModuleIntrinsic::ParsePlan(id)),
            _ => Err(CodecError::MalformedIntrinsic),
        }
    }
}

/// Why Snark module construction, storage, or admission failed.
#[derive(Debug)]
pub enum SnarkModuleError {
    /// Live grammar compilation failed.
    Build(ArtifactBuildError),
    /// The `.weavy` physical codec rejected the file.
    Codec(CodecError),
    /// Weavy semantic admission rejected the module.
    Admission(weavy::module::AdmissionError),
    /// PHON typed encoding or decoding failed.
    Phon(api::Error),
    /// Runtime plan reconstruction failed.
    Plan(WeavyParseError),
    /// The module did not contain exactly the required runtime constants.
    WrongConstantCount(usize),
    /// The grammar fingerprint constant did not contain exactly 32 bytes.
    MalformedGrammarFingerprint,
}

impl From<ArtifactBuildError> for SnarkModuleError {
    fn from(error: ArtifactBuildError) -> Self {
        Self::Build(error)
    }
}

impl From<WeavyParseError> for SnarkModuleError {
    fn from(error: WeavyParseError) -> Self {
        Self::Plan(error)
    }
}

impl fmt::Display for SnarkModuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Snark module error: {self:?}")
    }
}

impl std::error::Error for SnarkModuleError {}
