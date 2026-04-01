use std::{error::Error as StdError, fmt};

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct TokenizerError {
    pub context: String,
}

impl TokenizerError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            context: msg.into(),
        }
    }
}

impl fmt::Display for TokenizerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "tokenizer error: {}", self.context)
    }
}

impl StdError for TokenizerError {}

impl<S: Into<String>, T: fmt::Display> From<(S, T)> for TokenizerError {
    fn from(tuple: (S, T)) -> Self {
        Self {
            context: format!("failed to tokenize {}: {}", tuple.0.into(), tuple.1),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Error {
    MissingHeader(String),
    InvalidParam(String),
    ParseError(String),
    TokenizeError(String),
    Utf8Error(String),
    Unexpected(String),
}

impl Error {
    pub fn missing_header(header: &'static str) -> Self {
        Self::MissingHeader(header.into())
    }

    pub fn tokenizer<S: Into<String>, T: fmt::Display>(tuple: (S, T)) -> Self {
        Self::TokenizeError(format!(
            "failed to tokenize {}: {}",
            tuple.0.into(),
            tuple.1
        ))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MissingHeader(inner) => write!(f, "rsip error: missing header: {}", inner),
            Self::InvalidParam(inner) => write!(f, "rsip error: invalid header param: {}", inner),
            Self::ParseError(inner) => write!(f, "rsip error: could not parse part: {}", inner),
            Self::TokenizeError(inner) => write!(f, "Tokenizer error: {}", inner),
            Self::Unexpected(inner) => write!(f, "rsip quite unexpected error: {}", inner),
            Self::Utf8Error(inner) => write!(f, "rsip error: invalid utf8 ({})", inner),
        }
    }
}

impl StdError for Error {}

impl From<TokenizerError> for Error {
    fn from(e: TokenizerError) -> Self {
        Self::TokenizeError(e.context)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Self::Utf8Error(e.to_string())
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        Self::ParseError(e.to_string())
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(e: std::net::AddrParseError) -> Self {
        Self::ParseError(e.to_string())
    }
}
