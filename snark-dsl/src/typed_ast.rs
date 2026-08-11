//! Generate a typed AST and resolved-CST lowering from a snark grammar.
//!
//! The grammar fields every AST-relevant child, so structure derives mechanically:
//!   - hidden choice rules (`_expr`, `_item`, …) become enums (names from ast()),
//!   - fielded visible rules become structs; a field's type comes from what the
//!     field can contain, its cardinality from the optional/repeat context around it
//!     (bare -> T, optional -> `Option<T>`, repeat/sepBy -> `Vec<T>`),
//!   - mixed-alternative fields (e.g. array elements: flag | expr) become ad-hoc
//!     enums named by ast() annotations,
//!   - unfielded leaves (identifier, string, …) decode per their annotation.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use snark::grammar::{RawGrammarJson, RawRuleJson};

mod error;
pub use error::GenerateTypedAstError;

/// Inputs and output names for the typed-AST generator.
pub struct TypedAstConfig<'a> {
    /// Path to the Tree-sitter-compatible grammar source.
    pub grammar_js: &'a Path,
    /// Path to the standalone `ast({...})` annotation source.
    pub annotations_js: &'a Path,
    /// Cargo `OUT_DIR`.
    pub out_dir: &'a Path,
    /// File name for the embedded emitted grammar JSON, for example `vix_grammar.json`.
    pub grammar_output: &'a str,
    /// File name for the generated Rust AST/lowering module, for example `vix_ast.rs`.
    pub ast_output: &'a str,
    /// Source name reported while evaluating annotations, for example `vix_ast.snark.js`.
    pub annotation_source_name: &'a str,
    /// Text for the generated header, for example `vix/build.rs`.
    pub generated_by: &'a str,
    /// Human language name for the generated header, for example `vix`.
    pub language_name: &'a str,
}

/// Emit the embedded grammar JSON and generated typed AST files.
pub fn generate_typed_ast(config: &TypedAstConfig<'_>) -> Result<(), GenerateTypedAstError> {
    println!("cargo:rerun-if-changed={}", config.grammar_js.display());
    println!("cargo:rerun-if-changed={}", config.annotations_js.display());

    let grammar_json = crate::emit_with_boa(config.grammar_js)?;
    fs::write(config.out_dir.join(config.grammar_output), &grammar_json)?;

    let ann_src = fs::read_to_string(config.annotations_js)?;
    let ann_json = crate::annotations_from_source(&ann_src, config.annotation_source_name)?;
    let raw = RawGrammarJson::from_tree_sitter_json_str(&grammar_json)?;
    let anns: Annotations = facet_json::from_str(&ann_json)?;

    let generated = Model::build(&raw, &anns)?.generate(config);
    fs::write(config.out_dir.join(config.ast_output), generated)?;
    Ok(())
}

/// One ast() annotation, keyed by node kind. Only enrichment the grammar can't express.
#[derive(facet::Facet, Default, Debug)]
struct NodeAnn {
    /// Variant name when this node appears inside an enum.
    #[facet(rename = "as", default)]
    as_variant: Option<String>,
    /// Enum name for hidden choice rules.
    #[facet(rename = "enum", default)]
    enum_name: Option<String>,
    /// Struct name override (default: CamelCase of the node kind).
    #[facet(rename = "struct", default)]
    struct_name: Option<String>,
    /// Leaf decode choice: "text" | "string" | "path" | "bool".
    #[facet(default)]
    decode: Option<String>,
    /// Per-field enrichment (ad-hoc enum names).
    #[facet(default)]
    fields: BTreeMap<String, FieldAnn>,
}

#[derive(facet::Facet, Default, Debug)]
struct FieldAnn {
    /// Name for the ad-hoc enum generated from a mixed-alternative field.
    #[facet(rename = "enum", default)]
    enum_name: Option<String>,
}

type Annotations = BTreeMap<String, NodeAnn>;

// ---------------------------------------------------------------------------
// Grammar walking: fields + cardinality.
// ---------------------------------------------------------------------------

/// How many times a field can occur in a node.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mult {
    One,
    Opt,
    Many,
}

/// What a field can contain, before shape resolution.
#[derive(Clone, PartialEq, Debug)]
enum Alt {
    /// Reference to another rule (hidden or visible).
    Rule(String),
    /// Anonymous literal token(s).
    Token(String),
}

/// Ordered (by first appearance) field accumulator for one rule.
#[derive(Default, Clone, Debug)]
struct Fields(Vec<(String, Vec<Alt>, Mult)>);

impl Fields {
    fn entry(&mut self, name: &str) -> Option<&mut (String, Vec<Alt>, Mult)> {
        self.0.iter_mut().find(|(n, _, _)| n == name)
    }

    /// Sequential composition: a field seen again in the same sequence repeats.
    fn seq(mut self, other: Fields) -> Fields {
        for (name, alts, _mult) in other.0 {
            if let Some((_, existing, mult)) = self.entry(&name) {
                merge_alts(existing, alts);
                *mult = Mult::Many;
            } else {
                self.0.push((name, alts, _mult));
            }
        }
        self
    }

    /// Alternative composition: a field missing from some arms becomes optional.
    fn choice(arms: Vec<Fields>) -> Fields {
        let mut out = Fields::default();
        for arm in &arms {
            for (name, alts, _) in &arm.0 {
                if let Some((_, existing, _)) = out.entry(name) {
                    merge_alts(existing, alts.clone());
                } else {
                    out.0.push((name.clone(), alts.clone(), Mult::One));
                }
            }
        }
        for (name, _, mult) in &mut out.0 {
            let occurrences: Vec<Option<Mult>> = arms
                .iter()
                .map(|arm| arm.0.iter().find(|(n, _, _)| n == name).map(|(_, _, m)| *m))
                .collect();
            let any_many = occurrences.iter().flatten().any(|m| *m == Mult::Many);
            let everywhere_one = occurrences.iter().all(|m| *m == Some(Mult::One));
            *mult = if any_many {
                Mult::Many
            } else if everywhere_one {
                Mult::One
            } else {
                Mult::Opt
            };
        }
        out
    }

    fn repeated(mut self) -> Fields {
        for (_, _, mult) in &mut self.0 {
            *mult = Mult::Many;
        }
        self
    }
}

fn merge_alts(existing: &mut Vec<Alt>, incoming: Vec<Alt>) {
    for alt in incoming {
        if !existing.contains(&alt) {
            existing.push(alt);
        }
    }
}

/// Walk a rule body collecting its fields. Field contents are NOT walked: nested
/// fields inside field content are out of scope for the current generated grammars.
fn walk(rule_name: &str, rule: &RawRuleJson) -> Result<Fields, GenerateTypedAstError> {
    match rule {
        RawRuleJson::Field { name, content } => Ok(Fields(vec![(
            name.clone(),
            field_alts(rule_name, content)?,
            Mult::One,
        )])),
        RawRuleJson::Seq { members } => {
            members.iter().try_fold(Fields::default(), |acc, member| {
                Ok(acc.seq(walk(rule_name, member)?))
            })
        }
        RawRuleJson::Choice { members } => Ok(Fields::choice(
            members
                .iter()
                .map(|member| walk(rule_name, member))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        RawRuleJson::Repeat { content } | RawRuleJson::Repeat1 { content } => {
            Ok(walk(rule_name, content)?.repeated())
        }
        RawRuleJson::Prec { content, .. }
        | RawRuleJson::PrecLeft { content, .. }
        | RawRuleJson::PrecRight { content, .. }
        | RawRuleJson::PrecDynamic { content, .. }
        | RawRuleJson::Token { content, .. }
        | RawRuleJson::ImmediateToken { content, .. }
        | RawRuleJson::Alias { content, .. }
        | RawRuleJson::Reserved { content, .. } => walk(rule_name, content),
        _ => Ok(Fields::default()),
    }
}

/// The alternatives a field's content can produce.
fn field_alts(rule_name: &str, content: &RawRuleJson) -> Result<Vec<Alt>, GenerateTypedAstError> {
    match unwrap_transparent(content) {
        RawRuleJson::Symbol { name } => Ok(vec![Alt::Rule(name.clone())]),
        RawRuleJson::String { value } => Ok(vec![Alt::Token(value.clone())]),
        RawRuleJson::Choice { members } => {
            let mut out = Vec::new();
            for member in members {
                merge_alts(&mut out, field_alts(rule_name, member)?);
            }
            Ok(out)
        }
        RawRuleJson::Blank => Ok(Vec::new()),
        other => Err(GenerateTypedAstError::unsupported(
            rule_name,
            format!("unsupported field content: {other:?}"),
        )),
    }
}

fn unwrap_transparent(mut r: &RawRuleJson) -> &RawRuleJson {
    loop {
        r = match r {
            RawRuleJson::Prec { content, .. }
            | RawRuleJson::PrecLeft { content, .. }
            | RawRuleJson::PrecRight { content, .. }
            | RawRuleJson::PrecDynamic { content, .. }
            | RawRuleJson::Token { content, .. }
            | RawRuleJson::ImmediateToken { content, .. }
            | RawRuleJson::Reserved { content, .. }
            | RawRuleJson::Alias { content, .. } => content,
            other => return other,
        };
    }
}

// ---------------------------------------------------------------------------
// Model: classify rules, resolve field shapes.
// ---------------------------------------------------------------------------

/// How a leaf node decodes into a Rust value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Decode {
    Text,
    Str,
    Path,
    Bool,
    /// The node is a single fixed literal — a unit variant, nothing to carry.
    Unit,
}

impl Decode {
    fn rust_type(self) -> &'static str {
        match self {
            Decode::Bool => "crate::support::Spanned<bool>",
            // Unit leaves still carry WHERE they were (`_` patterns, hover).
            Decode::Unit => "crate::support::Span",
            _ => "crate::support::Spanned<String>",
        }
    }

    fn lower(self, node: &str) -> String {
        match self {
            Decode::Text => format!("node_text({node})?"),
            Decode::Str => format!("decode_string({node})?"),
            Decode::Path => format!("decode_path({node})?"),
            Decode::Bool => format!("decode_bool({node})?"),
            Decode::Unit => format!("span({node})"),
        }
    }
}

/// Resolved type/lowering shape for one field.
#[derive(Clone, Debug)]
enum Shape {
    /// Anonymous literal token(s).
    TokenSet(Vec<String>),
    /// A hidden choice rule — the generated enum.
    Enum(String),
    /// A fielded visible rule — the generated struct (by node kind).
    Struct(String),
    /// An unfielded visible rule — decoded scalar.
    Leaf(Decode),
    /// Mixed alternatives — a generated ad-hoc enum (by index into Model::adhocs).
    AdHoc(usize),
}

#[derive(Clone, Debug)]
struct AdHocDef {
    name: String,
    /// (variant name, dispatch) per alternative, in grammar order.
    alts: Vec<AdHocAlt>,
}

#[derive(Clone, Debug)]
enum AdHocAlt {
    /// Visible node kind.
    Visible(String),
    /// Hidden enum rule (kind, enum name).
    Hidden(String, String),
}

#[derive(Clone, Debug)]
struct FieldDef {
    grammar_name: String,
    rust_name: String,
    shape: Shape,
    mult: Mult,
    boxed: bool,
}

#[derive(Clone, Debug)]
struct StructDef {
    kind: String,
    name: String,
    fields: Vec<FieldDef>,
}

#[derive(Clone, Debug)]
struct EnumDef {
    /// Canonical hidden rule kind for diagnostics.
    kind: String,
    /// Hidden rule kinds that share this Rust enum name.
    source_kinds: Vec<String>,
    name: String,
    member_kinds: Vec<String>,
}

struct Model<'a> {
    raw: &'a RawGrammarJson,
    anns: &'a Annotations,
    enums: Vec<EnumDef>,
    structs: Vec<StructDef>,
    adhocs: Vec<AdHocDef>,
}

impl<'a> Model<'a> {
    fn build(
        raw: &'a RawGrammarJson,
        anns: &'a Annotations,
    ) -> Result<Self, GenerateTypedAstError> {
        let mut model = Model {
            raw,
            anns,
            enums: Vec::new(),
            structs: Vec::new(),
            adhocs: Vec::new(),
        };

        // Hidden enums first (shape resolution needs them), grouped by Rust enum
        // name. Subset hidden aliases such as `_scrutinee` and `_expr` can share
        // one generated enum; the generated enum is the deterministic union of
        // all same-name hidden rules in grammar order.
        for (name, rule) in raw.rules.iter() {
            let kind = name.as_str();
            if !kind.starts_with('_') {
                continue;
            }
            let enum_name = anns
                .get(kind)
                .and_then(|annotation| annotation.enum_name.clone())
                .ok_or_else(|| {
                    GenerateTypedAstError::unsupported(
                        kind,
                        "hidden rule needs an `enum` annotation",
                    )
                })?;
            let RawRuleJson::Choice { members } = unwrap_transparent(rule) else {
                return Err(GenerateTypedAstError::unsupported(
                    kind,
                    "hidden enum rule must be a choice",
                ));
            };
            let member_kinds = members
                .iter()
                .map(|member| match unwrap_transparent(member) {
                    RawRuleJson::Symbol { name } => Ok(name.clone()),
                    other => Err(GenerateTypedAstError::unsupported(
                        kind,
                        format!("hidden enum member must be a symbol: {other:?}"),
                    )),
                })
                .collect::<Result<Vec<_>, _>>()?;
            if let Some(existing) = model.enums.iter_mut().find(|e| e.name == enum_name) {
                existing.source_kinds.push(kind.to_string());
                for member in member_kinds {
                    if !existing.member_kinds.contains(&member) {
                        existing.member_kinds.push(member);
                    }
                }
            } else {
                model.enums.push(EnumDef {
                    kind: kind.to_string(),
                    source_kinds: vec![kind.to_string()],
                    name: enum_name,
                    member_kinds,
                });
            }
        }

        // Discover every fielded visible rule before resolving any field shape.
        // Shape resolution can therefore recognize forward references as structs.
        let mut struct_kinds = Vec::new();
        for (name, rule) in raw.rules.iter() {
            let kind = name.as_str();
            if kind.starts_with('_') {
                continue;
            }
            let fields = walk(kind, rule)?;
            if !fields.0.is_empty() {
                model.structs.push(StructDef {
                    kind: kind.to_string(),
                    name: model.struct_name(kind),
                    fields: Vec::new(),
                });
                struct_kinds.push((kind.to_string(), fields));
            }
        }
        for (kind, fields) in struct_kinds {
            let fields = fields
                .0
                .into_iter()
                .map(|(fname, alts, mult)| {
                    let shape = model.resolve_shape(&kind, &fname, alts)?;
                    Ok(FieldDef {
                        rust_name: rust_field_name(&fname, mult),
                        grammar_name: fname,
                        shape,
                        mult,
                        boxed: false,
                    })
                })
                .collect::<Result<Vec<_>, GenerateTypedAstError>>()?;
            model
                .structs
                .iter_mut()
                .find(|definition| definition.kind == kind)
                .expect("discovered struct remains registered")
                .fields = fields;
        }
        model.mark_cycle_back_edges();
        Ok(model)
    }

    fn ann(&self, kind: &str) -> Option<&NodeAnn> {
        self.anns.get(kind)
    }

    fn struct_name(&self, kind: &str) -> String {
        self.ann(kind)
            .and_then(|a| a.struct_name.clone())
            .unwrap_or_else(|| camel(kind))
    }

    fn variant_name(&self, kind: &str) -> String {
        self.ann(kind)
            .and_then(|a| a.as_variant.clone())
            .unwrap_or_else(|| camel(kind))
    }

    fn hidden_enum(&self, kind: &str) -> Option<&EnumDef> {
        self.enums
            .iter()
            .find(|e| e.source_kinds.iter().any(|source| source == kind))
    }

    /// The visible node kinds an enum can dispatch on, hidden members expanded.
    fn dispatch_kinds(&self, e: &EnumDef) -> Vec<String> {
        let mut out = Vec::new();
        for kind in &e.member_kinds {
            match self.hidden_enum(kind) {
                Some(inner) => out.extend(self.dispatch_kinds(inner)),
                None => out.push(kind.clone()),
            }
        }
        out
    }

    fn is_struct_kind(&self, kind: &str) -> bool {
        self.structs
            .iter()
            .any(|definition| definition.kind == kind)
    }

    /// Decode for an unfielded (leaf) visible rule.
    fn leaf_decode(&self, kind: &str) -> Result<Decode, GenerateTypedAstError> {
        match self
            .ann(kind)
            .and_then(|annotation| annotation.decode.as_deref())
        {
            Some("text") => Ok(Decode::Text),
            Some("string") => Ok(Decode::Str),
            Some("path") => Ok(Decode::Path),
            Some("bool") => Ok(Decode::Bool),
            Some(other) => Err(GenerateTypedAstError::unsupported(
                kind,
                format!("unknown decode `{other}`"),
            )),
            None => {
                let rule = self.raw.rules.get(kind).ok_or_else(|| {
                    GenerateTypedAstError::unsupported(kind, "referenced rule does not exist")
                })?;
                Ok(match unwrap_transparent(rule) {
                    RawRuleJson::String { .. } => Decode::Unit,
                    _ => Decode::Text,
                })
            }
        }
    }

    fn resolve_shape(
        &mut self,
        kind: &str,
        fname: &str,
        alts: Vec<Alt>,
    ) -> Result<Shape, GenerateTypedAstError> {
        let tokens: Vec<String> = alts
            .iter()
            .filter_map(|alt| match alt {
                Alt::Token(token) => Some(token.clone()),
                Alt::Rule(_) => None,
            })
            .collect();
        let rules: Vec<String> = alts
            .iter()
            .filter_map(|alt| match alt {
                Alt::Rule(rule) => Some(rule.clone()),
                Alt::Token(_) => None,
            })
            .collect();

        if rules.is_empty() {
            if tokens.is_empty() {
                return Err(GenerateTypedAstError::unsupported(
                    kind,
                    format!("field `{fname}` has no alternatives"),
                ));
            }
            return Ok(Shape::TokenSet(tokens));
        }
        if !tokens.is_empty() {
            return Err(GenerateTypedAstError::unsupported(
                kind,
                format!("field `{fname}` mixes tokens and rules"),
            ));
        }
        if rules.len() == 1 {
            let rule = &rules[0];
            return if let Some(definition) = self.hidden_enum(rule) {
                Ok(Shape::Enum(definition.name.clone()))
            } else if self.is_struct_kind(rule) {
                Ok(Shape::Struct(rule.clone()))
            } else {
                Ok(Shape::Leaf(self.leaf_decode(rule)?))
            };
        }

        let name = self
            .ann(kind)
            .and_then(|annotation| annotation.fields.get(fname))
            .and_then(|field| field.enum_name.clone())
            .ok_or_else(|| {
                GenerateTypedAstError::unsupported(
                    kind,
                    format!("field `{fname}` mixes alternatives and needs an `enum` annotation"),
                )
            })?;
        if let Some(idx) = self
            .adhocs
            .iter()
            .position(|definition| definition.name == name)
        {
            return Ok(Shape::AdHoc(idx));
        }
        let alts = rules
            .iter()
            .map(|rule| {
                if let Some(definition) = self.hidden_enum(rule) {
                    AdHocAlt::Hidden(rule.clone(), definition.name.clone())
                } else {
                    AdHocAlt::Visible(rule.clone())
                }
            })
            .collect();
        self.adhocs.push(AdHocDef { name, alts });
        Ok(Shape::AdHoc(self.adhocs.len() - 1))
    }

    fn mark_cycle_back_edges(&mut self) {
        let mut state =
            TypeVisitState::new(self.structs.len(), self.enums.len(), self.adhocs.len());
        for idx in 0..self.structs.len() {
            self.visit_type(TypeNode::Struct(idx), &mut state);
        }
        for idx in 0..self.enums.len() {
            self.visit_type(TypeNode::Enum(idx), &mut state);
        }
        for idx in 0..self.adhocs.len() {
            self.visit_type(TypeNode::AdHoc(idx), &mut state);
        }
    }

    fn visit_type(&mut self, node: TypeNode, state: &mut TypeVisitState) {
        if state.is_done(node) || state.is_visiting(node) {
            return;
        }
        state.set_visiting(node);
        match node {
            TypeNode::Struct(idx) => {
                let field_count = self.structs[idx].fields.len();
                for field_idx in 0..field_count {
                    let Some(target) = self.field_type_node(idx, field_idx) else {
                        continue;
                    };
                    if state.is_visiting(target) {
                        self.structs[idx].fields[field_idx].boxed = true;
                    } else if !state.is_done(target) {
                        self.visit_type(target, state);
                    }
                }
            }
            TypeNode::Enum(idx) => {
                let member_kinds = self.enums[idx].member_kinds.clone();
                for kind in member_kinds {
                    if let Some(target) = self.hidden_enum_type_node(&kind) {
                        self.visit_type(target, state);
                    }
                }
            }
            TypeNode::AdHoc(idx) => {
                let alts = self.adhocs[idx].alts.clone();
                for alt in alts {
                    if let AdHocAlt::Hidden(kind, _) = alt
                        && let Some(target) = self.hidden_enum_type_node(&kind)
                    {
                        self.visit_type(target, state);
                    }
                }
            }
        }
        state.set_done(node);
    }

    fn field_type_node(&self, struct_idx: usize, field_idx: usize) -> Option<TypeNode> {
        let field = &self.structs[struct_idx].fields[field_idx];
        if field.boxed || field.mult == Mult::Many {
            return None;
        }
        match &field.shape {
            Shape::Struct(kind) => self.struct_type_node(kind),
            Shape::Enum(name) => self.enum_type_node(name),
            Shape::AdHoc(idx) => Some(TypeNode::AdHoc(*idx)),
            Shape::TokenSet(_) | Shape::Leaf(_) => None,
        }
    }

    fn struct_type_node(&self, kind: &str) -> Option<TypeNode> {
        self.structs
            .iter()
            .position(|s| s.kind == kind)
            .map(TypeNode::Struct)
    }

    fn enum_type_node(&self, name: &str) -> Option<TypeNode> {
        self.enums
            .iter()
            .position(|e| e.name == name)
            .map(TypeNode::Enum)
    }

    fn hidden_enum_type_node(&self, kind: &str) -> Option<TypeNode> {
        let name = self.hidden_enum(kind).map(|e| e.name.as_str())?;
        self.enum_type_node(name)
    }

    // -----------------------------------------------------------------------
    // Emission.
    // -----------------------------------------------------------------------

    fn generate(&self, config: &TypedAstConfig<'_>) -> String {
        let mut out = String::new();
        writeln!(
            out,
            "// @generated by {} from the {} grammar + {}.",
            config.generated_by, config.language_name, config.annotation_source_name
        )
        .unwrap();
        out.push_str(
            r#"// Structure derived from grammar fields + cardinality; names/decodes from ast().

use snark::parser::ParseNode;

pub use crate::support::{Span, Spanned};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypedAstLowerError {
    UnexpectedKind { expected: &'static str, actual: String },
    MissingField { node_kind: String, field: &'static str },
    InvalidLeaf { node_kind: String, value: String, expected: &'static str },
}

fn token_field_nodes<'a, N: ParseNode>(n: &'a N, name: &str, set: &[&str]) -> Vec<N::Child<'a>> {
    let fielded = n
        .children()
        .filter(|child| child.field() == Some(name) && !child.extra())
        .filter(|child| child.text().is_some_and(|text| set.contains(&text)))
        .collect::<Vec<_>>();
    if !fielded.is_empty() {
        return fielded;
    }
    n.children()
        .filter(|child| !child.named() && !child.extra())
        .filter(|child| child.text().is_some_and(|text| set.contains(&text)))
        .collect()
}

fn field_opt<'a, N: ParseNode>(n: &'a N, name: &str) -> Option<N::Child<'a>> {
    n.children().find(|child| child.field() == Some(name))
}

fn field_one<'a, N: ParseNode>(
    n: &'a N,
    name: &'static str,
) -> Result<N::Child<'a>, TypedAstLowerError> {
    field_opt(n, name).ok_or_else(|| TypedAstLowerError::MissingField {
        node_kind: n.kind().to_owned(),
        field: name,
    })
}

fn fields<'a, N: ParseNode>(
    n: &'a N,
    name: &'static str,
) -> impl Iterator<Item = N::Child<'a>> + 'a {
    n.children().filter(move |child| child.field() == Some(name))
}

fn raw_text<N: ParseNode>(n: &N) -> String {
    fn collect<N: ParseNode>(n: &N, out: &mut String) {
        if let Some(text) = n.text() {
            out.push_str(text);
            return;
        }
        for child in n.children() {
            if !child.extra() {
                collect(&child, out);
            }
        }
    }
    let mut out = String::new();
    collect(n, &mut out);
    out
}

fn span<N: ParseNode>(n: &N) -> crate::support::Span {
    let (start, end) = n.byte_range();
    crate::support::Span {
        start: start as u32,
        end: end as u32,
    }
}

fn node_text<N: ParseNode>(
    n: &N,
) -> Result<crate::support::Spanned<String>, TypedAstLowerError> {
    let value = raw_text(n);
    if value.is_empty() {
        return Err(TypedAstLowerError::InvalidLeaf {
            node_kind: n.kind().to_owned(),
            value,
            expected: "non-empty text",
        });
    }
    Ok(crate::support::Spanned {
        value,
        span: span(n),
    })
}

fn decode_quoted<N: ParseNode>(
    n: &N,
    raw: &str,
    expected: &'static str,
) -> Result<crate::support::Spanned<String>, TypedAstLowerError> {
    let Some(quote) = raw.chars().next() else {
        return Err(TypedAstLowerError::InvalidLeaf {
            node_kind: n.kind().to_owned(),
            value: raw.to_owned(),
            expected,
        });
    };
    let Some(inner) = raw
        .strip_prefix(quote)
        .and_then(|value| value.strip_suffix(quote))
    else {
        return Err(TypedAstLowerError::InvalidLeaf {
            node_kind: n.kind().to_owned(),
            value: raw.to_owned(),
            expected,
        });
    };
    let mut value = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let Some(escaped) = chars.next() else {
                return Err(TypedAstLowerError::InvalidLeaf {
                    node_kind: n.kind().to_owned(),
                    value: raw.to_owned(),
                    expected: "valid string escape",
                });
            };
            value.push(match escaped {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                other => other,
            });
        } else {
            value.push(ch);
        }
    }
    Ok(crate::support::Spanned {
        value,
        span: span(n),
    })
}

fn decode_string<N: ParseNode>(
    n: &N,
) -> Result<crate::support::Spanned<String>, TypedAstLowerError> {
    let raw = raw_text(n);
    decode_quoted(n, &raw, "quoted string")
}

fn decode_path<N: ParseNode>(
    n: &N,
) -> Result<crate::support::Spanned<String>, TypedAstLowerError> {
    let raw = raw_text(n);
    let Some(path) = raw.strip_prefix('p') else {
        return Err(TypedAstLowerError::InvalidLeaf {
            node_kind: n.kind().to_owned(),
            value: raw,
            expected: "p-prefixed quoted path",
        });
    };
    decode_quoted(n, path, "p-prefixed quoted path")
}

fn decode_bool<N: ParseNode>(
    n: &N,
) -> Result<crate::support::Spanned<bool>, TypedAstLowerError> {
    let value = raw_text(n);
    let decoded = match value.as_str() {
        "true" => true,
        "false" => false,
        _ => {
            return Err(TypedAstLowerError::InvalidLeaf {
                node_kind: n.kind().to_owned(),
                value,
                expected: "`true` or `false`",
            });
        }
    };
    Ok(crate::support::Spanned {
        value: decoded,
        span: span(n),
    })
}

"#,
        );
        // Several hidden rules may share one enum (e.g. `_scrutinee` is a
        // syntactic restriction of `_expr`): emit each NAME once, first
        // (broadest) declaration wins for both the type and the lowering fn.
        let mut emitted = Vec::new();
        for e in &self.enums {
            if emitted.contains(&e.name) {
                continue;
            }
            emitted.push(e.name.clone());
            self.emit_enum(&mut out, e);
        }
        for (idx, a) in self.adhocs.iter().enumerate() {
            self.emit_adhoc(&mut out, idx, a);
        }
        for s in &self.structs {
            self.emit_struct(&mut out, s);
        }
        out
    }
    fn variant_payload(&self, kind: &str) -> String {
        if self.is_struct_kind(kind) {
            format!("(Box<{}>)", self.struct_name(kind))
        } else {
            format!("({})", self.leaf_decode(kind).unwrap().rust_type())
        }
    }

    /// The expression lowering node `c` into the variant payload for `kind`.
    fn variant_lower(&self, enum_name: &str, kind: &str, c: &str) -> String {
        let variant = self.variant_name(kind);
        if self.is_struct_kind(kind) {
            format!("{enum_name}::{variant}(Box::new(try_lower_{kind}({c})?))")
        } else {
            format!(
                "{enum_name}::{variant}({})",
                self.leaf_decode(kind).unwrap().lower(c)
            )
        }
    }

    /// Statement zeroing one field's spans, by shape and cardinality.
    fn strip_field(&self, f: &FieldDef) -> Option<String> {
        let name = &f.rust_name;
        let inner = match &f.shape {
            Shape::TokenSet(tokens) if tokens.len() == 1 => {
                "*x = crate::support::Span { start: 0, end: 0 };"
            }
            Shape::TokenSet(_) => "x.span = crate::support::Span { start: 0, end: 0 };",
            Shape::Enum(_) | Shape::Struct(_) | Shape::AdHoc(_) => "x.strip_spans();",
            Shape::Leaf(Decode::Unit) => "*x = crate::support::Span { start: 0, end: 0 };",
            Shape::Leaf(_) => "x.span = crate::support::Span { start: 0, end: 0 };",
        };
        Some(match f.mult {
            Mult::One => format!("{{ let x = &mut self.{name}; {inner} }}"),
            Mult::Opt => format!("if let Some(x) = &mut self.{name} {{ {inner} }}"),
            Mult::Many => format!("for x in &mut self.{name} {{ {inner} }}"),
        })
    }

    /// Match arm body zeroing one enum variant's payload spans.
    fn strip_variant_arm(&self, enum_name: &str, kind: &str, variant: &str) -> String {
        if self.is_struct_kind(kind) {
            format!("{enum_name}::{variant}(x) => x.strip_spans(),")
        } else {
            match self.leaf_decode(kind).unwrap() {
                Decode::Unit => format!(
                    "{enum_name}::{variant}(x) => *x = crate::support::Span {{ start: 0, end: 0 }},"
                ),
                _ => format!(
                    "{enum_name}::{variant}(x) => x.span = crate::support::Span {{ start: 0, end: 0 }},"
                ),
            }
        }
    }

    fn emit_enum(&self, out: &mut String, e: &EnumDef) {
        writeln!(
            out,
            "#[derive(facet::Facet, Debug, Clone, PartialEq)]\n#[repr(u8)]\npub enum {} {{",
            e.name
        )
        .unwrap();
        for kind in &e.member_kinds {
            if let Some(inner) = self.hidden_enum(kind) {
                let variant = self
                    .ann(kind)
                    .and_then(|annotation| annotation.as_variant.clone())
                    .unwrap_or_else(|| inner.name.clone());
                writeln!(out, "    {variant}({}),", inner.name).unwrap();
            } else {
                writeln!(
                    out,
                    "    {}{},",
                    self.variant_name(kind),
                    self.variant_payload(kind)
                )
                .unwrap();
            }
        }
        writeln!(out, "}}\n").unwrap();

        writeln!(
            out,
            "pub fn try_lower_{}<N: ParseNode>(n: &N) -> Result<{}, TypedAstLowerError> {{\n    match n.kind() {{",
            snake(&e.name),
            e.name
        )
        .unwrap();
        for kind in &e.member_kinds {
            if self.hidden_enum(kind).is_none() {
                writeln!(
                    out,
                    "        {kind:?} => Ok({}),",
                    self.variant_lower(&e.name, kind, "n")
                )
                .unwrap();
            }
        }
        for kind in &e.member_kinds {
            if let Some(inner) = self.hidden_enum(kind) {
                let variant = self
                    .ann(kind)
                    .and_then(|annotation| annotation.as_variant.clone())
                    .unwrap_or_else(|| inner.name.clone());
                let kinds = self
                    .dispatch_kinds(inner)
                    .iter()
                    .map(|kind| format!("{kind:?}"))
                    .collect::<Vec<_>>()
                    .join(" | ");
                writeln!(
                    out,
                    "        {kinds} => Ok({}::{variant}(try_lower_{}(n)?)),",
                    e.name,
                    snake(&inner.name)
                )
                .unwrap();
            }
        }
        writeln!(
            out,
            "        other => Err(TypedAstLowerError::UnexpectedKind {{ expected: {:?}, actual: other.to_owned() }}),\n    }}\n}}\n",
            e.kind
        )
        .unwrap();

        writeln!(
            out,
            "impl {} {{\n    pub fn strip_spans(&mut self) {{\n        match self {{",
            e.name
        )
        .unwrap();
        for kind in &e.member_kinds {
            if let Some(inner) = self.hidden_enum(kind) {
                let variant = self
                    .ann(kind)
                    .and_then(|annotation| annotation.as_variant.clone())
                    .unwrap_or_else(|| inner.name.clone());
                writeln!(
                    out,
                    "            {}::{variant}(x) => x.strip_spans(),",
                    e.name
                )
                .unwrap();
            } else {
                writeln!(
                    out,
                    "            {}",
                    self.strip_variant_arm(&e.name, kind, &self.variant_name(kind))
                )
                .unwrap();
            }
        }
        writeln!(out, "        }}\n    }}\n}}\n").unwrap();
    }

    fn emit_adhoc(&self, out: &mut String, _idx: usize, a: &AdHocDef) {
        writeln!(
            out,
            "#[derive(facet::Facet, Debug, Clone, PartialEq)]\n#[repr(u8)]\npub enum {} {{",
            a.name
        )
        .unwrap();
        for alt in &a.alts {
            match alt {
                AdHocAlt::Visible(kind) => writeln!(
                    out,
                    "    {}{},",
                    self.variant_name(kind),
                    self.variant_payload(kind)
                )
                .unwrap(),
                AdHocAlt::Hidden(_, enum_name) => {
                    writeln!(out, "    {enum_name}({enum_name}),").unwrap()
                }
            }
        }
        writeln!(out, "}}\n").unwrap();

        writeln!(
            out,
            "pub fn try_lower_{}<N: ParseNode>(n: &N) -> Result<{}, TypedAstLowerError> {{\n    match n.kind() {{",
            snake(&a.name),
            a.name
        )
        .unwrap();
        for alt in &a.alts {
            if let AdHocAlt::Visible(kind) = alt {
                writeln!(
                    out,
                    "        {kind:?} => Ok({}),",
                    self.variant_lower(&a.name, kind, "n")
                )
                .unwrap();
            }
        }
        for alt in &a.alts {
            if let AdHocAlt::Hidden(hidden_kind, enum_name) = alt {
                let definition = self.hidden_enum(hidden_kind).unwrap();
                let kinds = self
                    .dispatch_kinds(definition)
                    .iter()
                    .map(|kind| format!("{kind:?}"))
                    .collect::<Vec<_>>()
                    .join(" | ");
                writeln!(
                    out,
                    "        {kinds} => Ok({}::{enum_name}(try_lower_{}(n)?)),",
                    a.name,
                    snake(enum_name)
                )
                .unwrap();
            }
        }
        writeln!(
            out,
            "        other => Err(TypedAstLowerError::UnexpectedKind {{ expected: {:?}, actual: other.to_owned() }}),\n    }}\n}}\n",
            a.name
        )
        .unwrap();

        writeln!(
            out,
            "impl {} {{\n    pub fn strip_spans(&mut self) {{\n        match self {{",
            a.name
        )
        .unwrap();
        for alt in &a.alts {
            match alt {
                AdHocAlt::Visible(kind) => writeln!(
                    out,
                    "            {}",
                    self.strip_variant_arm(&a.name, kind, &self.variant_name(kind))
                )
                .unwrap(),
                AdHocAlt::Hidden(_, enum_name) => writeln!(
                    out,
                    "            {}::{enum_name}(x) => x.strip_spans(),",
                    a.name
                )
                .unwrap(),
            }
        }
        writeln!(out, "        }}\n    }}\n}}\n").unwrap();
    }

    fn field_type(&self, f: &FieldDef) -> String {
        let mut base = match &f.shape {
            Shape::TokenSet(tokens) if tokens.len() == 1 => "crate::support::Span".to_string(),
            Shape::TokenSet(_) => "crate::support::Spanned<String>".to_string(),
            Shape::Enum(name) => name.clone(),
            Shape::Struct(kind) => self.struct_name(kind),
            Shape::Leaf(decode) => decode.rust_type().to_string(),
            Shape::AdHoc(idx) => self.adhocs[*idx].name.clone(),
        };
        if f.boxed {
            base = format!("Box<{base}>");
        }
        match f.mult {
            Mult::One => base,
            Mult::Opt => format!("Option<{base}>"),
            Mult::Many => format!("Vec<{base}>"),
        }
    }

    fn token_lower_expr(&self, f: &FieldDef, s: &StructDef, tokens: &[String]) -> String {
        let set = tokens
            .iter()
            .map(|token| format!("{token:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        let lower = if tokens.len() == 1 {
            "span"
        } else {
            "node_text"
        };
        match f.mult {
            Mult::Opt if tokens.len() == 1 => format!(
                "token_field_nodes(n, {:?}, &[{set}]).into_iter().next().map(|node| {lower}(&node))",
                f.grammar_name
            ),
            Mult::Opt => format!(
                "token_field_nodes(n, {:?}, &[{set}]).into_iter().next().map(|node| {lower}(&node)).transpose()?",
                f.grammar_name
            ),
            Mult::One if tokens.len() == 1 => format!(
                "token_field_nodes(n, {:?}, &[{set}]).into_iter().next().map(|node| {lower}(&node)).ok_or_else(|| TypedAstLowerError::MissingField {{ node_kind: {:?}.to_owned(), field: {:?} }})?",
                f.grammar_name, s.kind, f.grammar_name
            ),
            Mult::One => format!(
                "token_field_nodes(n, {:?}, &[{set}]).into_iter().next().map(|node| {lower}(&node)).transpose()?.ok_or_else(|| TypedAstLowerError::MissingField {{ node_kind: {:?}.to_owned(), field: {:?} }})?",
                f.grammar_name, s.kind, f.grammar_name
            ),
            Mult::Many if tokens.len() == 1 => format!(
                "token_field_nodes(n, {:?}, &[{set}]).into_iter().map(|node| {lower}(&node)).collect()",
                f.grammar_name
            ),
            Mult::Many => format!(
                "token_field_nodes(n, {:?}, &[{set}]).into_iter().map(|node| {lower}(&node)).collect::<Result<Vec<_>, _>>()?",
                f.grammar_name
            ),
        }
    }

    fn field_lower_fn(&self, f: &FieldDef) -> String {
        match &f.shape {
            Shape::TokenSet(_) => unreachable!("token fields lower via token_field_nodes"),
            Shape::Enum(name) => format!("try_lower_{}", snake(name)),
            Shape::Struct(kind) => format!("try_lower_{kind}"),
            Shape::Leaf(_) => String::new(),
            Shape::AdHoc(idx) => format!("try_lower_{}", snake(&self.adhocs[*idx].name)),
        }
    }

    fn lower_node_expr(&self, f: &FieldDef, node: &str) -> String {
        match &f.shape {
            Shape::Leaf(decode) => decode.lower(node),
            _ => format!("{}({node})?", self.field_lower_fn(f)),
        }
    }

    fn emit_struct(&self, out: &mut String, s: &StructDef) {
        writeln!(
            out,
            "#[derive(facet::Facet, Debug, Clone, PartialEq)]\npub struct {} {{\n    pub span: crate::support::Span,",
            s.name
        )
        .unwrap();
        for f in &s.fields {
            writeln!(out, "    pub {}: {},", f.rust_name, self.field_type(f)).unwrap();
        }
        writeln!(out, "}}\n").unwrap();

        writeln!(
            out,
            "pub fn try_lower_{}<N: ParseNode>(n: &N) -> Result<{}, TypedAstLowerError> {{\n    Ok({} {{\n        span: span(n),",
            s.kind, s.name, s.name
        )
        .unwrap();
        for f in &s.fields {
            let expr = if let Shape::TokenSet(tokens) = &f.shape {
                self.token_lower_expr(f, s, tokens)
            } else {
                match f.mult {
                    Mult::One if f.boxed => {
                        let lowered = self.lower_node_expr(f, "&field_one(n, FIELD)?");
                        format!(
                            "Box::new({})",
                            lowered.replace("FIELD", &format!("{:?}", f.grammar_name))
                        )
                    }
                    Mult::One => {
                        let lowered = self.lower_node_expr(f, "&field_one(n, FIELD)?");
                        lowered.replace("FIELD", &format!("{:?}", f.grammar_name))
                    }
                    Mult::Opt if f.boxed => {
                        let lowered = self.lower_node_expr(f, "&node");
                        format!(
                            "field_opt(n, {:?}).map(|node| Ok(Box::new({lowered}))).transpose()?",
                            f.grammar_name
                        )
                    }
                    Mult::Opt => {
                        let lowered = self.lower_node_expr(f, "&node");
                        format!(
                            "field_opt(n, {:?}).map(|node| Ok({lowered})).transpose()?",
                            f.grammar_name
                        )
                    }
                    Mult::Many => {
                        let lowered = self.lower_node_expr(f, "&node");
                        format!(
                            "fields(n, {:?}).map(|node| Ok({lowered})).collect::<Result<Vec<_>, _>>()?",
                            f.grammar_name
                        )
                    }
                }
            };
            writeln!(out, "        {}: {expr},", f.rust_name).unwrap();
        }
        writeln!(out, "    }})\n}}\n").unwrap();

        writeln!(
            out,
            "impl {} {{\n    pub fn strip_spans(&mut self) {{\n        self.span = crate::support::Span {{ start: 0, end: 0 }};",
            s.name
        )
        .unwrap();
        for f in &s.fields {
            if let Some(stmt) = self.strip_field(f) {
                writeln!(out, "        {stmt}").unwrap();
            }
        }
        writeln!(out, "    }}\n}}\n").unwrap();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TypeMark {
    Fresh,
    Visiting,
    Done,
}

#[derive(Clone, Copy)]
enum TypeNode {
    Struct(usize),
    Enum(usize),
    AdHoc(usize),
}

struct TypeVisitState {
    structs: Vec<TypeMark>,
    enums: Vec<TypeMark>,
    adhocs: Vec<TypeMark>,
}

impl TypeVisitState {
    fn new(structs: usize, enums: usize, adhocs: usize) -> Self {
        Self {
            structs: vec![TypeMark::Fresh; structs],
            enums: vec![TypeMark::Fresh; enums],
            adhocs: vec![TypeMark::Fresh; adhocs],
        }
    }

    fn mark(&self, node: TypeNode) -> TypeMark {
        match node {
            TypeNode::Struct(idx) => self.structs[idx],
            TypeNode::Enum(idx) => self.enums[idx],
            TypeNode::AdHoc(idx) => self.adhocs[idx],
        }
    }

    fn set(&mut self, node: TypeNode, mark: TypeMark) {
        match node {
            TypeNode::Struct(idx) => self.structs[idx] = mark,
            TypeNode::Enum(idx) => self.enums[idx] = mark,
            TypeNode::AdHoc(idx) => self.adhocs[idx] = mark,
        }
    }

    fn is_visiting(&self, node: TypeNode) -> bool {
        self.mark(node) == TypeMark::Visiting
    }

    fn is_done(&self, node: TypeNode) -> bool {
        self.mark(node) == TypeMark::Done
    }

    fn set_visiting(&mut self, node: TypeNode) {
        self.set(node, TypeMark::Visiting);
    }

    fn set_done(&mut self, node: TypeNode) {
        self.set(node, TypeMark::Done);
    }
}

/// Grammar field names are singular (they label one child each); Vec-shaped fields
/// pluralize (`stmt` -> `stmts`, `entry` -> `entries`, `leaf` -> `leaves`), and a
/// singular `type` dodges the keyword (plural `types` doesn't need to). Any other
/// name that lands on a Rust keyword — directly (`else`) or via pluralization
/// (`a` -> `as`) — is raw-escaped, except the few that reject `r#`, which get a
/// trailing underscore instead.
fn rust_field_name(name: &str, mult: Mult) -> String {
    let name = match (mult, name) {
        (Mult::Many, "leaf") => "leaves".to_string(),
        (Mult::Many, s) if s.ends_with('y') => format!("{}ies", &s[..s.len() - 1]),
        (Mult::Many, s) if !s.ends_with('s') => format!("{s}s"),
        // `ty` predates the escaping below; keep it so existing grammars don't
        // see their generated field renamed to `r#type`.
        (_, "type") => return "ty".to_string(),
        (_, s) => s.to_string(),
    };
    match name.as_str() {
        // The only keywords `r#` can't rescue.
        "crate" | "self" | "super" | "Self" => format!("{name}_"),
        s if RUST_KEYWORDS.contains(&s) => format!("r#{name}"),
        _ => name,
    }
}

/// Rust keywords (strict + reserved, edition 2024) that are valid as raw
/// identifiers. `type` and the un-rescuable `crate`/`self`/`super`/`Self` are
/// handled separately in [`rust_field_name`].
const RUST_KEYWORDS: &[&str] = &[
    "abstract", "as", "async", "await", "become", "box", "break", "const", "continue", "do", "dyn",
    "else", "enum", "extern", "false", "final", "fn", "for", "gen", "if", "impl", "in", "let",
    "loop", "macro", "match", "mod", "move", "mut", "override", "priv", "pub", "ref", "return",
    "static", "struct", "trait", "true", "try", "typeof", "unsafe", "unsized", "use", "virtual",
    "where", "while", "yield",
];

fn camel(kind: &str) -> String {
    kind.split('_')
        .filter(|s| !s.is_empty())
        .map(|s| {
            let mut chars = s.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

fn snake(name: &str) -> String {
    let mut out = String::new();
    for (i, ch) in name.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{Annotations, GenerateTypedAstError, Model, TypedAstConfig};
    use snark::grammar::RawGrammarJson;
    use snark::lexical::LexicalFacts;
    use snark::lower::weavy::{WeavyParsePlan, parse_prepared_weavy_with_report};
    use snark::parser::{ParseTable, ParserGrammar, ResolvedCstNode};
    use snark::validated::ValidatedGrammar;

    fn generate(grammar_source: &str) -> String {
        let (grammar_json, annotations_json) =
            crate::emit_source_with_annotations_boa(grammar_source, "cycle.js").unwrap();
        let raw = RawGrammarJson::from_tree_sitter_json_str(&grammar_json).unwrap();
        let anns: Annotations = facet_json::from_str(&annotations_json).unwrap();
        let config = TypedAstConfig {
            grammar_js: Path::new("cycle/grammar.js"),
            annotations_js: Path::new("cycle/ast.js"),
            out_dir: Path::new("unused"),
            grammar_output: "cycle_grammar.json",
            ast_output: "cycle_ast.rs",
            annotation_source_name: "cycle_ast.snark.js",
            generated_by: "cycle/build.rs",
            language_name: "cycle",
        };
        Model::build(&raw, &anns).unwrap().generate(&config)
    }

    fn parse_resolved(grammar_source: &str, input: &str) -> ResolvedCstNode {
        let (grammar_json, _) =
            crate::emit_source_with_annotations_boa(grammar_source, "fixture.js").unwrap();
        let raw = RawGrammarJson::from_tree_sitter_json_str(&grammar_json).unwrap();
        let validated = ValidatedGrammar::from_raw(&raw).unwrap();
        let lexical = LexicalFacts::from_grammar(&validated);
        let parser = ParserGrammar::normalize_from_validated(&validated, &lexical)
            .unwrap()
            .prepare_productions_for_items()
            .unwrap();
        let table = ParseTable::from_grammar(&parser).unwrap();
        let plan = WeavyParsePlan::new(&validated, &parser, &table).unwrap();
        let report = parse_prepared_weavy_with_report(&plan, &parser, &table, input).unwrap();
        report.accepted_resolved_tree(&parser, input).unwrap()
    }

    fn child<'a>(n: &'a ResolvedCstNode, field: &str) -> &'a ResolvedCstNode {
        n.children()
            .iter()
            .find(|c| c.field() == Some(field))
            .unwrap()
    }

    fn field_count(n: &ResolvedCstNode, field: &str) -> usize {
        n.children()
            .iter()
            .filter(|c| c.field() == Some(field))
            .count()
    }

    fn fixture_token_field_nodes<'a>(
        n: &'a ResolvedCstNode,
        name: &str,
        set: &[&str],
    ) -> Vec<&'a ResolvedCstNode> {
        let fielded = n
            .children()
            .iter()
            .filter(|c| c.field() == Some(name) && !c.extra())
            .filter(|c| c.text().is_some_and(|t| set.contains(&t)))
            .collect::<Vec<_>>();
        if !fielded.is_empty() {
            return fielded;
        }
        n.children()
            .iter()
            .filter(|c| !c.named() && !c.extra())
            .filter(|c| c.text().is_some_and(|t| set.contains(&t)))
            .collect()
    }
    #[test]
    fn generated_lowering_is_generic_and_structured() {
        let generated = generate(
            r#"
module.exports = grammar({
  name: "fallible",
  rules: {
    source_file: $ => field("stmt", $._stmt),
    _stmt: $ => choice($.let_stmt),
    let_stmt: $ => seq("let", field("name", $.ident), "=", field("value", $.bool_lit)),
    ident: $ => /[a-z]+/,
    bool_lit: $ => choice("true", "false"),
  },
});
ast({
  _stmt: { enum: "Stmt" },
  bool_lit: { decode: "bool" },
});
"#,
        );

        assert!(generated.contains("pub enum TypedAstLowerError"));
        assert!(generated.contains("pub fn try_lower_source_file<N: ParseNode>"));
        assert!(generated.contains("TypedAstLowerError::UnexpectedKind"));
        assert!(generated.contains("TypedAstLowerError::MissingField"));
        assert!(generated.contains("TypedAstLowerError::InvalidLeaf"));
        assert!(generated.contains("expected: \"`true` or `false`\""));
        assert!(generated.contains("field_one(n, \"stmt\")?"));
        assert!(!generated.contains("panic!(\"unexpected"));
        assert!(!generated.contains("panic!(\"missing"));
    }

    #[test]
    fn unsupported_generator_shape_returns_structured_error() {
        let (grammar_json, annotations_json) = crate::emit_source_with_annotations_boa(
            r#"
module.exports = grammar({
  name: "unsupported",
  rules: {
    source_file: $ => field("part", choice("...", $.splice)),
    splice: $ => /[a-z]+/,
  },
});
"#,
            "unsupported.js",
        )
        .unwrap();
        let raw = RawGrammarJson::from_tree_sitter_json_str(&grammar_json).unwrap();
        let anns: Annotations = facet_json::from_str(&annotations_json).unwrap();

        let error = match Model::build(&raw, &anns) {
            Ok(_) => panic!("unsupported shape unexpectedly generated"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            GenerateTypedAstError::UnsupportedShape { rule, detail }
                if rule == "source_file" && detail.contains("mixes tokens and rules")
        ));
    }

    #[test]
    fn forward_referenced_fielded_rule_is_a_struct() {
        let generated = generate(
            r#"
module.exports = grammar({
  name: "forward",
  rules: {
    source_file: $ => field("function", $.function_decl),
    function_decl: $ => seq(
      "fn",
      field("params", $.param_list),
      field("body", $.block),
    ),
    param_list: $ => seq("(", field("param", $.ident), ")"),
    block: $ => seq("{", field("stmt", $.ident), "}"),
    ident: $ => /[a-z]+/,
  },
});
"#,
        );

        assert!(generated.contains("pub params: ParamList,"));
        assert!(generated.contains("pub body: Block,"));
        assert!(generated.contains("try_lower_param_list"));
        assert!(generated.contains("try_lower_block"));
    }

    #[test]
    fn boxes_struct_field_that_closes_type_cycle() {
        let generated = generate(
            r#"
module.exports = grammar({
  name: "cycle",
  rules: {
    source_file: $ => field("stmt", $.if_statement),
    if_statement: $ => seq(
      "if",
      field("then", $.block),
      optional(field("else_clause", $.else_clause)),
    ),
    else_clause: $ => seq(
      "else",
      choice(field("if_stmt", $.if_statement), field("block", $.block)),
    ),
    block: $ => seq("{", "}"),
  },
});
"#,
        );

        assert!(generated.contains("pub else_clause: Option<ElseClause>,"));
        assert!(generated.contains("pub if_stmt: Option<Box<IfStatement>>,"));
        assert!(generated.contains(
            r#"if_stmt: field_opt(n, "if_stmt").map(|node| Ok(Box::new(try_lower_if_statement(&node)?))).transpose()?"#
        ));
    }

    #[test]
    fn keyword_field_names_are_escaped() {
        let generated = generate(
            r#"
module.exports = grammar({
  name: "keywords",
  rules: {
    source_file: $ => seq(field("expr", $.ternary), field("list", $.list)),
    ternary: $ => seq(
      field("cond", $.ident),
      "?",
      field("then", $.ident),
      ":",
      field("else", $.ident),
    ),
    list: $ => seq("[", repeat(field("a", $.ident)), "]", field("self", $.ident)),
    ident: $ => /[a-z]+/,
  },
});
"#,
        );

        // `else` is a keyword: the Rust field is raw-escaped, but the CST lookup
        // keeps the grammar's spelling.
        assert!(generated.contains("pub r#else:"));
        assert!(!generated.contains("pub else:"));
        assert!(generated.contains(r#"field_one(n, "else""#));
        // pluralization can land on a keyword too (`a` -> `as`)
        assert!(generated.contains("pub r#as: Vec<"));
        // `r#` can't rescue `self`
        assert!(generated.contains("pub self_:"));
    }

    #[test]
    fn anonymous_token_fields_generate_spanned_text_or_unit_markers() {
        let grammar = r#"
module.exports = grammar({
  name: "tokens",
  rules: {
    source_file: $ => seq(field("expr", $.binary), repeat(field("mark", "!"))),
    binary: $ => seq(field("lhs", $.ident), field("op", choice("+", "-")), field("rhs", $.ident)),
    ident: $ => /[a-z]+/,
  },
});
"#;
        let generated = generate(grammar);

        assert!(generated.contains("pub op: crate::support::Spanned<String>,"));
        assert!(generated.contains("pub marks: Vec<crate::support::Span>,"));
        assert!(generated.contains(
            r#"op: token_field_nodes(n, "op", &["+", "-"]).into_iter().next().map(|node| node_text(&node)).transpose()?"#
        ));
        assert!(generated.contains(
            r#"marks: token_field_nodes(n, "mark", &["!"]).into_iter().map(|node| span(&node)).collect()"#
        ));

        let root = parse_resolved(grammar, "a + b!!!");
        let binary = child(&root, "expr");
        let ops = fixture_token_field_nodes(binary, "op", &["+", "-"]);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].text(), Some("+"));
        let marks = fixture_token_field_nodes(&root, "mark", &["!"]);
        assert_eq!(marks.len(), 3);
        assert!(marks.iter().all(|mark| mark.text() == Some("!")));
    }

    #[test]
    fn hidden_enum_aliases_generate_deterministic_union() {
        let grammar = r#"
module.exports = grammar({
  name: "aliases",
  rules: {
    source_file: $ => field("expr", $._expr),
    _small: $ => choice($.ident),
    _expr: $ => choice($.ident, $.call),
    call: $ => seq(field("callee", $._small), "(", field("arg", $.ident), ")"),
    ident: $ => /[a-z]+/,
  },
});
ast({
  _small: { enum: "Expr" },
  _expr: { enum: "Expr" },
});
"#;

        let first = generate(grammar);
        let second = generate(grammar);
        assert_eq!(first, second);
        assert_eq!(first.matches("pub enum Expr").count(), 1);
        assert!(first.contains("    Ident(crate::support::Spanned<String>),"));
        assert!(first.contains("    Call(Box<Call>),"));
        assert!(first.contains(r#""call" => Ok(Expr::Call(Box::new(try_lower_call(n)?))),"#));
    }

    #[test]
    fn repeat_and_sep_by_fields_generate_collections_and_parse() {
        let grammar = r#"
function sepBy(sep, rule) {
  return optional(seq(rule, repeat(seq(sep, rule)), optional(sep)));
}

module.exports = grammar({
  name: "collections",
  rules: {
    source_file: $ => seq(
      field("many", $.many),
      field("one_or_more", $.one_or_more),
      field("list", $.list),
      field("trail", $.trail),
    ),
    many: $ => seq("{", repeat(field("item", $.ident)), "}"),
    one_or_more: $ => seq("<", repeat1(field("item", $.ident)), ">"),
    list: $ => seq("[", sepBy(",", field("elem", $.ident)), "]"),
    trail: $ => seq("(", sepBy(";", field("entry", $.ident)), ")"),
    ident: $ => /[a-z]+/,
  },
});
"#;
        let generated = generate(grammar);

        assert!(generated.contains("pub items: Vec<crate::support::Spanned<String>>"));
        assert!(generated.contains("pub elems: Vec<crate::support::Spanned<String>>"));
        assert!(generated.contains("pub entries: Vec<crate::support::Spanned<String>>"));
        assert!(generated.contains(
            r#"items: fields(n, "item").map(|node| Ok(node_text(&node)?)).collect::<Result<Vec<_>, _>>()?"#
        ));
        assert!(generated.contains(
            r#"elems: fields(n, "elem").map(|node| Ok(node_text(&node)?)).collect::<Result<Vec<_>, _>>()?"#
        ));
        assert!(generated.contains(r#"entries: fields(n, "entry").map(|node| Ok(node_text(&node)?)).collect::<Result<Vec<_>, _>>()?"#));

        let root = parse_resolved(grammar, "{a b}<c>[d,e,](f;g;)");
        assert_eq!(field_count(child(&root, "many"), "item"), 2);
        assert_eq!(field_count(child(&root, "one_or_more"), "item"), 1);
        assert_eq!(field_count(child(&root, "list"), "elem"), 2);
        assert_eq!(field_count(child(&root, "trail"), "entry"), 2);

        let empty = parse_resolved(grammar, "{}<c>[]()");
        assert_eq!(field_count(child(&empty, "many"), "item"), 0);
        assert_eq!(field_count(child(&empty, "list"), "elem"), 0);
        assert_eq!(field_count(child(&empty, "trail"), "entry"), 0);
    }
}
