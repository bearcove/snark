use std::fmt;

/// Error produced while generating a typed AST module.
#[derive(Debug)]
pub enum GenerateTypedAstError {
    /// Grammar or annotation JavaScript evaluation failed.
    Dsl(crate::Error),
    /// A generator input or output could not be read or written.
    Io(std::io::Error),
    /// Emitted grammar JSON could not be imported.
    Grammar(snark::diagnostic::ImportError),
    /// AST annotations could not be decoded.
    Annotation(facet_json::DeserializeError),
    /// The grammar used a shape the typed-AST generator cannot represent.
    UnsupportedShape {
        /// Grammar rule whose shape was unsupported.
        rule: String,
        /// Human-readable explanation of the unsupported shape.
        detail: String,
    },
}

impl GenerateTypedAstError {
    pub(crate) fn unsupported(rule: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::UnsupportedShape {
            rule: rule.into(),
            detail: detail.into(),
        }
    }
}

impl fmt::Display for GenerateTypedAstError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dsl(error) => error.fmt(f),
            Self::Io(error) => error.fmt(f),
            Self::Grammar(error) => error.fmt(f),
            Self::Annotation(error) => error.fmt(f),
            Self::UnsupportedShape { rule, detail } => {
                write!(f, "unsupported typed-AST shape in rule `{rule}`: {detail}")
            }
        }
    }
}

impl std::error::Error for GenerateTypedAstError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Dsl(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Grammar(error) => Some(error),
            Self::Annotation(error) => Some(error),
            Self::UnsupportedShape { .. } => None,
        }
    }
}

impl From<crate::Error> for GenerateTypedAstError {
    fn from(error: crate::Error) -> Self {
        Self::Dsl(error)
    }
}

impl From<std::io::Error> for GenerateTypedAstError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<snark::diagnostic::ImportError> for GenerateTypedAstError {
    fn from(error: snark::diagnostic::ImportError) -> Self {
        Self::Grammar(error)
    }
}

impl From<facet_json::DeserializeError> for GenerateTypedAstError {
    fn from(error: facet_json::DeserializeError) -> Self {
        Self::Annotation(error)
    }
}
