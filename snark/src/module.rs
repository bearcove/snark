//! Durable PHON-backed Snark parser modules.

use core::fmt;

use facet::Facet;
use facet_value::{VArray, VObject, VString, Value};
use phon::api;
use phon_schema::{
    Field, Primitive, Schema, SchemaId, SchemaKind, SchemaRef, primitive_id, resolve_ids,
};
use phon_storage::{AlignedRegistry, DenseRangeWriter};
use weavy::DenseLowered;
use weavy::ir::WeavyOp;
use weavy::module::{
    Constant, ConstantId, ConstantPool, ConstantRange, ConstantRangeId, ConstantRangeReference,
    ConstantReference, DialectRequirement, IntrinsicContract, ModuleManifest, ModuleVerifier,
    StorageProfile, WeavyModule,
};
use weavy_phon::{
    CodecError, ConstantRangeReport, InspectionReport, IntrinsicCodec, SectionReport,
};

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

// Durable runtime range contract. Range IDs are module-local and carried by
// executable Snark intrinsics. The admitted runtime exposes typed accessors
// over these immutable rows for state/mode lookup, dispatch, goto, reduction,
// scanner metadata, tree names, and plan blocks. Regex engines and lookup
// indexes are process-local derivatives built once from the matcher/name
// ranges; they are never a second semantic parser source. A loaded module is
// lifetime-bound to the `.weavy` bytes through `weavy_phon::BorrowedModule`.
const RANGE_RUNTIME_HEADER: u32 = 0;
const RANGE_PARSE_STATES: u32 = 1;
const RANGE_ACTION_ENTRIES: u32 = 2;
const RANGE_GOTOS: u32 = 3;
const RANGE_LEX_MODES: u32 = 4;
const RANGE_LEX_TERMINALS: u32 = 5;
const RANGE_LEX_EXTERNALS: u32 = 6;
const RANGE_PRODUCTIONS: u32 = 7;
const RANGE_PRODUCTION_STEPS: u32 = 8;
const RANGE_PRODUCTION_METADATA: u32 = 9;
const RANGE_EXTERNALS: u32 = 10;
const RANGE_RESERVED_TERMINALS: u32 = 11;
const RANGE_VALID_SYMBOL_EXTERNALS: u32 = 12;

#[derive(Clone, Debug, Facet, PartialEq, Eq)]
struct SnarkModuleData {
    grammar_fingerprint: GrammarFingerprint,
    parser_grammar: ParserGrammar,
    parse_table: ParseTable,
    parse_plan: WeavyParsePlanData,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RuntimeHeaderRow {
    fingerprint_0: u64,
    fingerprint_1: u64,
    fingerprint_2: u64,
    fingerprint_3: u64,
    state_count: u32,
    conflict_count: u32,
    production_count: u32,
    metadata_count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ParseStateRow {
    lex_mode: u32,
    first_entry: u32,
    entry_count: u32,
    first_goto: u32,
    goto_count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ActionEntryRow {
    state: u32,
    lookahead_kind: u8,
    lookahead_a: u32,
    lookahead_b: u32,
    entry_index: u32,
    action_count: u32,
    first_action_kind: u8,
    first_action_a: u32,
    first_action_b: u32,
    first_action_c: u32,
    first_action_d: u32,
    first_action_e: i32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GotoRow {
    state: u32,
    nonterminal: u32,
    target: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LexModeRow {
    first_terminal: u32,
    terminal_count: u32,
    first_external: u32,
    external_count: u32,
    reserved_context: u32,
    valid_symbols: u32,
    word: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IndexedIdRow {
    owner: u32,
    value: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExternalRow {
    ordinal: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProductionRow {
    first_step: u32,
    step_count: u32,
    metadata: u32,
    dynamic_precedence: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProductionStepRow {
    symbol_kind: u8,
    symbol: u32,
    field: u32,
    alias: u32,
    alias_named: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProductionMetadataRow {
    public_node: u32,
    dynamic_precedence: i32,
}

struct RuntimeRanges {
    header: ConstantRange,
    states: ConstantRange,
    action_entries: ConstantRange,
    gotos: ConstantRange,
    lex_modes: ConstantRange,
    lex_terminals: ConstantRange,
    lex_externals: ConstantRange,
    productions: ConstantRange,
    production_steps: ConstantRange,
    production_metadata: ConstantRange,
    externals: ConstantRange,
    reserved_terminals: ConstantRange,
    valid_symbol_externals: ConstantRange,
}

fn encode_lookahead(lookahead: crate::parser::LookaheadSymbol) -> (u8, u32, u32) {
    match lookahead {
        crate::parser::LookaheadSymbol::Terminal(id) => (0, id.get(), 0),
        crate::parser::LookaheadSymbol::External(id) => (1, id.get(), 0),
        crate::parser::LookaheadSymbol::Eof => (2, 0, 0),
        crate::parser::LookaheadSymbol::ReservedWord { terminal, context } => {
            (3, terminal.get(), context.get())
        }
        crate::parser::LookaheadSymbol::ErrorRecovery(id) => (4, id.get(), 0),
    }
}

fn encode_action(action: crate::parser::ParseAction) -> (u8, u32, u32, u32, u32, i32) {
    match action {
        crate::parser::ParseAction::Accept {
            production,
            metadata,
            symbol,
            child_count,
            dynamic_precedence,
        } => (
            0,
            production.get(),
            metadata.get(),
            symbol.get(),
            u32::try_from(child_count).expect("child count overflow"),
            dynamic_precedence,
        ),
        crate::parser::ParseAction::Shift { state, repetition } => {
            (1, state.get(), u32::from(repetition), 0, 0, 0)
        }
        crate::parser::ParseAction::ShiftExtra => (2, 0, 0, 0, 0, 0),
        crate::parser::ParseAction::Reduce {
            production,
            metadata,
            symbol,
            child_count,
            dynamic_precedence,
        } => (
            3,
            production.get(),
            metadata.get(),
            symbol.get(),
            u32::try_from(child_count).expect("child count overflow"),
            dynamic_precedence,
        ),
    }
}

impl RuntimeRanges {
    fn from_runtime(
        fingerprint: GrammarFingerprint,
        parser: &ParserGrammar,
        table: &ParseTable,
    ) -> Result<Self, SnarkModuleError> {
        let header_rows = vec![RuntimeHeaderRow {
            fingerprint_0: u64::from_le_bytes(fingerprint[0..8].try_into().expect("length")),
            fingerprint_1: u64::from_le_bytes(fingerprint[8..16].try_into().expect("length")),
            fingerprint_2: u64::from_le_bytes(fingerprint[16..24].try_into().expect("length")),
            fingerprint_3: u64::from_le_bytes(fingerprint[24..32].try_into().expect("length")),
            state_count: u32::try_from(table.states().len())
                .map_err(|_| SnarkModuleError::SizeOverflow)?,
            conflict_count: u32::try_from(table.conflicts().len())
                .map_err(|_| SnarkModuleError::SizeOverflow)?,
            production_count: u32::try_from(parser.productions().len())
                .map_err(|_| SnarkModuleError::SizeOverflow)?,
            metadata_count: u32::try_from(parser.production_metadata().len())
                .map_err(|_| SnarkModuleError::SizeOverflow)?,
        }];
        let mut first_entry = 0u32;
        let mut first_goto = 0u32;
        let states = table
            .states()
            .iter()
            .map(|state| {
                let row = ParseStateRow {
                    lex_mode: state.lex_mode().get(),
                    first_entry,
                    entry_count: u32::try_from(state.entries().len())
                        .expect("state entry overflow"),
                    first_goto,
                    goto_count: u32::try_from(state.gotos().len()).expect("state goto overflow"),
                };
                first_entry += row.entry_count;
                first_goto += row.goto_count;
                row
            })
            .collect::<Vec<_>>();
        let action_entries = table
            .states()
            .iter()
            .flat_map(|state| {
                state
                    .entries()
                    .iter()
                    .enumerate()
                    .map(move |(entry_index, entry)| {
                        let (lookahead_kind, lookahead_a, lookahead_b) =
                            encode_lookahead(entry.lookahead());
                        let (
                            first_action_kind,
                            first_action_a,
                            first_action_b,
                            first_action_c,
                            first_action_d,
                            first_action_e,
                        ) = entry
                            .actions()
                            .first()
                            .copied()
                            .map_or((u8::MAX, 0, 0, 0, 0, 0), encode_action);
                        ActionEntryRow {
                            state: state.id().get(),
                            lookahead_kind,
                            lookahead_a,
                            lookahead_b,
                            entry_index: u32::try_from(entry_index).expect("action entry overflow"),
                            action_count: u32::try_from(entry.actions().len())
                                .expect("action count overflow"),
                            first_action_kind,
                            first_action_a,
                            first_action_b,
                            first_action_c,
                            first_action_d,
                            first_action_e,
                        }
                    })
            })
            .collect::<Vec<_>>();
        let gotos = table
            .states()
            .iter()
            .flat_map(|state| {
                state.gotos().iter().map(move |goto| GotoRow {
                    state: state.id().get(),
                    nonterminal: goto.nonterminal().get(),
                    target: goto.state().get(),
                })
            })
            .collect::<Vec<_>>();
        let mut first_terminal = 0u32;
        let mut first_external = 0u32;
        let lex_modes = table
            .lexical_modes()
            .iter()
            .map(|mode| {
                let row = LexModeRow {
                    first_terminal,
                    terminal_count: u32::try_from(mode.terminals().len())
                        .expect("terminal count overflow"),
                    first_external,
                    external_count: u32::try_from(mode.externals().len())
                        .expect("external count overflow"),
                    reserved_context: mode.reserved_context().map_or(u32::MAX, |id| id.get()),
                    valid_symbols: mode.valid_symbols().map_or(u32::MAX, |id| id.get()),
                    word: mode.word().map_or(u32::MAX, |id| id.get()),
                };
                first_terminal += row.terminal_count;
                first_external += row.external_count;
                row
            })
            .collect::<Vec<_>>();
        let lex_terminals = table
            .lexical_modes()
            .iter()
            .flat_map(|mode| {
                mode.terminals()
                    .iter()
                    .copied()
                    .map(move |terminal| IndexedIdRow {
                        owner: mode.id().get(),
                        value: terminal.get(),
                    })
            })
            .collect::<Vec<_>>();
        let lex_externals = table
            .lexical_modes()
            .iter()
            .flat_map(|mode| {
                mode.externals()
                    .iter()
                    .copied()
                    .map(move |external| IndexedIdRow {
                        owner: mode.id().get(),
                        value: external.get(),
                    })
            })
            .collect::<Vec<_>>();
        let externals = parser
            .symbols()
            .externals()
            .iter()
            .map(|external| ExternalRow {
                ordinal: external.ordinal(),
            })
            .collect::<Vec<_>>();
        let reserved_terminals = parser
            .reserved_contexts()
            .iter()
            .flat_map(|context| {
                context
                    .entries()
                    .iter()
                    .copied()
                    .map(move |terminal| IndexedIdRow {
                        owner: context.id().get(),
                        value: terminal.get(),
                    })
            })
            .collect::<Vec<_>>();
        let valid_symbol_externals = table
            .valid_symbol_sets()
            .iter()
            .flat_map(|set| {
                set.externals()
                    .iter()
                    .copied()
                    .map(move |external| IndexedIdRow {
                        owner: set.id().get(),
                        value: external.get(),
                    })
            })
            .collect::<Vec<_>>();
        let mut first_step = 0u32;
        let productions = parser
            .productions()
            .iter()
            .map(|production| {
                let row = ProductionRow {
                    first_step,
                    step_count: u32::try_from(production.steps().len())
                        .expect("production step overflow"),
                    metadata: production.metadata().get(),
                    dynamic_precedence: production.dynamic_precedence(),
                };
                first_step += row.step_count;
                row
            })
            .collect::<Vec<_>>();
        let production_steps = parser
            .productions()
            .iter()
            .flat_map(|production| production.steps())
            .map(|step| {
                let (symbol_kind, symbol) = match step.symbol() {
                    crate::parser::ParserSymbol::Terminal(id) => (0, id.get()),
                    crate::parser::ParserSymbol::Nonterminal(id) => (1, id.get()),
                    crate::parser::ParserSymbol::External(id) => (2, id.get()),
                    crate::parser::ParserSymbol::Eof => (3, 0),
                    crate::parser::ParserSymbol::Internal(id) => (4, id.get()),
                };
                ProductionStepRow {
                    symbol_kind,
                    symbol,
                    field: step.field().map_or(u32::MAX, |id| id.get()),
                    alias: step.alias().map_or(u32::MAX, |id| id.get()),
                    alias_named: step.alias_named().map_or(2, u8::from),
                }
            })
            .collect::<Vec<_>>();
        let production_metadata = parser
            .production_metadata()
            .iter()
            .map(|metadata| ProductionMetadataRow {
                public_node: metadata.public_node().map_or(u32::MAX, |id| id.get()),
                dynamic_precedence: metadata.dynamic_precedence(),
            })
            .collect::<Vec<_>>();
        let mut schemas = Vec::new();
        let header = dense_range("SnarkRuntimeHeader", &header_rows, &mut schemas)?;
        let states = dense_range("SnarkParseState", &states, &mut schemas)?;
        let action_entries = dense_range("SnarkActionEntry", &action_entries, &mut schemas)?;
        let gotos = dense_range("SnarkGoto", &gotos, &mut schemas)?;
        let lex_modes = dense_range("SnarkLexMode", &lex_modes, &mut schemas)?;
        let lex_terminals = dense_range("SnarkLexTerminal", &lex_terminals, &mut schemas)?;
        let lex_externals = dense_range("SnarkLexExternal", &lex_externals, &mut schemas)?;
        let productions = dense_range("SnarkProduction", &productions, &mut schemas)?;
        let production_steps = dense_range("SnarkProductionStep", &production_steps, &mut schemas)?;
        let production_metadata = dense_range(
            "SnarkProductionMetadata",
            &production_metadata,
            &mut schemas,
        )?;
        let externals = dense_range("SnarkExternal", &externals, &mut schemas)?;
        let reserved_terminals =
            dense_range("SnarkReservedTerminal", &reserved_terminals, &mut schemas)?;
        let valid_symbol_externals = dense_range(
            "SnarkValidSymbolExternal",
            &valid_symbol_externals,
            &mut schemas,
        )?;
        Ok(Self {
            header,
            states,
            action_entries,
            gotos,
            lex_modes,
            lex_terminals,
            lex_externals,
            productions,
            production_steps,
            production_metadata,
            externals,
            reserved_terminals,
            valid_symbol_externals,
        })
    }

    fn references(&self) -> Vec<ConstantRangeReference> {
        self.into_ranges_ref()
            .iter()
            .enumerate()
            .map(|(index, range)| {
                ConstantRangeReference::new(
                    ConstantRangeId::new(index as u32),
                    range.schema_id(),
                    range.profile(),
                )
            })
            .collect()
    }

    fn into_ranges_ref(&self) -> [&ConstantRange; 13] {
        [
            &self.header,
            &self.states,
            &self.action_entries,
            &self.gotos,
            &self.lex_modes,
            &self.lex_terminals,
            &self.lex_externals,
            &self.productions,
            &self.production_steps,
            &self.production_metadata,
            &self.externals,
            &self.reserved_terminals,
            &self.valid_symbol_externals,
        ]
    }

    fn into_ranges(self) -> Vec<ConstantRange> {
        vec![
            self.header,
            self.states,
            self.action_entries,
            self.gotos,
            self.lex_modes,
            self.lex_terminals,
            self.lex_externals,
            self.productions,
            self.production_steps,
            self.production_metadata,
            self.externals,
            self.reserved_terminals,
            self.valid_symbol_externals,
        ]
    }
}

trait DenseRow {
    fn fields() -> Vec<(&'static str, Primitive)>;
    fn value(&self) -> Value;
}

fn dense_range<T: DenseRow>(
    name: &str,
    rows: &[T],
    schemas: &mut Vec<Schema>,
) -> Result<ConstantRange, SnarkModuleError> {
    let row = Schema {
        id: SchemaId::from_raw(1),
        type_params: Vec::new(),
        kind: SchemaKind::Struct {
            name: name.into(),
            fields: T::fields()
                .into_iter()
                .map(|(name, primitive)| Field {
                    name: name.into(),
                    schema: SchemaRef::concrete(primitive_id(primitive)),
                    required: true,
                })
                .collect(),
        },
    };
    let list = Schema {
        id: SchemaId::from_raw(2),
        type_params: Vec::new(),
        kind: SchemaKind::List {
            element: SchemaRef::concrete(row.id),
        },
    };
    let range_schemas = resolve_ids(vec![row, list]);
    let root = range_schemas[1].id;
    let registry = AlignedRegistry::new(range_schemas.clone());
    let values = rows.iter().map(DenseRow::value).collect::<VArray>();
    let bytes = DenseRangeWriter::encode(&values.into(), root, &registry)
        .map_err(|error| SnarkModuleError::Codec(CodecError::Aligned(error)))?;
    let dense = phon_storage::DenseRange::parse(&bytes, root, &registry)
        .map_err(|error| SnarkModuleError::Codec(CodecError::Aligned(error)))?;
    schemas.extend(range_schemas.clone());
    ConstantRange::new(
        range_schemas,
        1,
        StorageProfile::DenseAligned,
        u32::try_from(rows.len()).map_err(|_| SnarkModuleError::SizeOverflow)?,
        u32::try_from(dense.stride()).map_err(|_| SnarkModuleError::SizeOverflow)?,
        bytes,
    )
    .map_err(|error| SnarkModuleError::Codec(CodecError::ConstantRange(error)))
}

fn row_value(fields: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    let mut object = VObject::new();
    for (name, value) in fields {
        object.insert(VString::new(name), value);
    }
    object.into()
}

impl DenseRow for RuntimeHeaderRow {
    fn fields() -> Vec<(&'static str, Primitive)> {
        vec![
            ("fingerprint_0", Primitive::U64),
            ("fingerprint_1", Primitive::U64),
            ("fingerprint_2", Primitive::U64),
            ("fingerprint_3", Primitive::U64),
            ("state_count", Primitive::U32),
            ("conflict_count", Primitive::U32),
            ("production_count", Primitive::U32),
            ("metadata_count", Primitive::U32),
        ]
    }
    fn value(&self) -> Value {
        row_value([
            ("fingerprint_0", Value::from(self.fingerprint_0)),
            ("fingerprint_1", Value::from(self.fingerprint_1)),
            ("fingerprint_2", Value::from(self.fingerprint_2)),
            ("fingerprint_3", Value::from(self.fingerprint_3)),
            ("state_count", Value::from(self.state_count)),
            ("conflict_count", Value::from(self.conflict_count)),
            ("production_count", Value::from(self.production_count)),
            ("metadata_count", Value::from(self.metadata_count)),
        ])
    }
}

macro_rules! dense_row {
    ($type:ty, [$(($field:ident, $primitive:expr)),+ $(,)?]) => {
        impl DenseRow for $type {
            fn fields() -> Vec<(&'static str, Primitive)> {
                vec![$((stringify!($field), $primitive)),+]
            }
            fn value(&self) -> Value {
                row_value([$((stringify!($field), Value::from(self.$field))),+])
            }
        }
    };
}

dense_row!(
    ParseStateRow,
    [
        (lex_mode, Primitive::U32),
        (first_entry, Primitive::U32),
        (entry_count, Primitive::U32),
        (first_goto, Primitive::U32),
        (goto_count, Primitive::U32),
    ]
);
dense_row!(
    ActionEntryRow,
    [
        (state, Primitive::U32),
        (lookahead_kind, Primitive::U8),
        (lookahead_a, Primitive::U32),
        (lookahead_b, Primitive::U32),
        (entry_index, Primitive::U32),
        (action_count, Primitive::U32),
        (first_action_kind, Primitive::U8),
        (first_action_a, Primitive::U32),
        (first_action_b, Primitive::U32),
        (first_action_c, Primitive::U32),
        (first_action_d, Primitive::U32),
        (first_action_e, Primitive::I32),
    ]
);
dense_row!(
    GotoRow,
    [
        (state, Primitive::U32),
        (nonterminal, Primitive::U32),
        (target, Primitive::U32),
    ]
);
dense_row!(
    LexModeRow,
    [
        (first_terminal, Primitive::U32),
        (terminal_count, Primitive::U32),
        (first_external, Primitive::U32),
        (external_count, Primitive::U32),
        (reserved_context, Primitive::U32),
        (valid_symbols, Primitive::U32),
        (word, Primitive::U32),
    ]
);
dense_row!(
    IndexedIdRow,
    [(owner, Primitive::U32), (value, Primitive::U32)]
);
dense_row!(ExternalRow, [(ordinal, Primitive::U32)]);
dense_row!(
    ProductionRow,
    [
        (first_step, Primitive::U32),
        (step_count, Primitive::U32),
        (metadata, Primitive::U32),
        (dynamic_precedence, Primitive::I32),
    ]
);
dense_row!(
    ProductionStepRow,
    [
        (symbol_kind, Primitive::U8),
        (symbol, Primitive::U32),
        (field, Primitive::U32),
        (alias, Primitive::U32),
        (alias_named, Primitive::U8),
    ]
);
dense_row!(
    ProductionMetadataRow,
    [
        (public_node, Primitive::U32),
        (dynamic_precedence, Primitive::I32),
    ]
);

/// Runtime row views use fixed-width copy fields rather than native pointers or `usize`.
pub const fn runtime_fact_rows_are_portable() -> bool {
    std::mem::size_of::<ParseStateRow>() == 20
        && std::mem::size_of::<ProductionRow>() == 16
        && std::mem::size_of::<ProductionMetadataRow>() == 8
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
        let ranges = RuntimeRanges::from_runtime(
            self.grammar_fingerprint,
            &self.parser_grammar,
            &self.parse_table,
        )?;
        let module = WeavyModule::new(
            ModuleManifest::new(
                "snark.parser",
                [DialectRequirement::new("snark", 1, 0)],
                [0],
            ),
            DenseLowered::new(
                vec![WeavyOp::Intrinsic(SnarkModuleIntrinsic::RuntimeRanges(
                    ranges.references(),
                ))],
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
        )
        .with_constant_ranges(ranges.into_ranges());
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

    /// Whether parsing currently consumes runtime facts borrowed from these exact module bytes.
    ///
    /// This remains false until the owned parser/table reconstruction path is removed.
    pub fn runtime_ranges_borrow(&self, _bytes: &[u8]) -> bool {
        false
    }

    /// Number of runtime parse-state rows.
    pub fn runtime_state_count(&self) -> usize {
        self.parse_table.states().len()
    }

    /// Number of retained GLR conflict rows.
    pub fn runtime_conflict_count(&self) -> usize {
        self.parse_table.conflicts().len()
    }

    /// Number of parser fact reads routed through the runtime abstraction.
    pub fn runtime_facts_read_count(&self) -> usize {
        crate::lower::weavy::runtime_fact_read_count()
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
    /// Typed runtime ranges declared by the module.
    pub constant_ranges: Vec<ConstantRangeReport>,
}

impl From<InspectionReport> for SnarkModuleInspection {
    fn from(report: InspectionReport) -> Self {
        Self {
            module_name: report.module_name,
            dialects: report.dialects,
            sections: report.sections,
            constant_count: report.constant_count,
            constant_ranges: report.constant_ranges,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SnarkModuleIntrinsic {
    RuntimeRanges(Vec<ConstantRangeReference>),
}

impl IntrinsicContract for SnarkModuleIntrinsic {
    fn constant_references(&self, _visit: &mut dyn FnMut(ConstantReference)) {}

    fn constant_range_references(&self, visit: &mut dyn FnMut(ConstantRangeReference)) {
        match self {
            Self::RuntimeRanges(ranges) => ranges.iter().copied().for_each(visit),
        }
    }
}

struct SnarkCodec;

impl IntrinsicCodec for SnarkCodec {
    type Intrinsic = SnarkModuleIntrinsic;
    const DIALECT: &'static str = "snark";
    const SCHEMA_ID: u64 = 0x99f3_525f_a240_6d1c;

    fn encode(intrinsic: &Self::Intrinsic, out: &mut Vec<u8>) {
        match intrinsic {
            SnarkModuleIntrinsic::RuntimeRanges(ranges) => {
                out.push(0);
                out.extend_from_slice(&(ranges.len() as u32).to_le_bytes());
                for range in ranges {
                    out.extend_from_slice(&range.id().index().to_le_bytes());
                    out.extend_from_slice(&range.expected_schema().as_u64().to_le_bytes());
                    out.push(match range.expected_profile() {
                        StorageProfile::Compact => 0,
                        StorageProfile::Aligned => 1,
                        StorageProfile::DenseAligned => 2,
                    });
                }
            }
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self::Intrinsic, CodecError> {
        if bytes.len() < 5 || bytes[0] != 0 {
            return Err(CodecError::MalformedIntrinsic);
        }
        let count = u32::from_le_bytes(bytes[1..5].try_into().expect("length")) as usize;
        if bytes.len() != 5 + count * 13 {
            return Err(CodecError::MalformedIntrinsic);
        }
        let mut ranges = Vec::with_capacity(count);
        for chunk in bytes[5..].chunks_exact(13) {
            let id =
                ConstantRangeId::new(u32::from_le_bytes(chunk[..4].try_into().expect("length")));
            let schema =
                SchemaId::from_raw(u64::from_le_bytes(chunk[4..12].try_into().expect("length")));
            let profile = match chunk[12] {
                0 => StorageProfile::Compact,
                1 => StorageProfile::Aligned,
                2 => StorageProfile::DenseAligned,
                _ => return Err(CodecError::MalformedIntrinsic),
            };
            ranges.push(ConstantRangeReference::new(id, schema, profile));
        }
        Ok(SnarkModuleIntrinsic::RuntimeRanges(ranges))
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
    /// A generated runtime table exceeded portable module widths.
    SizeOverflow,
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
