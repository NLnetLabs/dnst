use std::{error, fmt, io};

//------------ Error ---------------------------------------------------------

/// A program error.
///
/// Such errors are highly likely to halt the program.
#[derive(Clone)]
pub struct Error(Box<Information>);

/// Information about an error.
#[derive(Clone)]
struct Information {
    /// The primary error message.
    primary: Box<str>,

    /// Layers of context to the error.
    ///
    /// Ordered from innermost to outermost.
    context: Vec<Box<str>>,
}

//--- Interaction

impl Error {
    /// Construct a new error from a string.
    pub fn new(error: &str) -> Self {
        Self(Box::new(Information {
            primary: error.into(),
            context: Vec::new(),
        }))
    }

    /// Add context to this error.
    pub fn context(mut self, context: &str) -> Self {
        self.0.context.push(context.into());
        self
    }

    /// Pretty-print this error.
    pub fn pretty_print(self) {
        use std::io::IsTerminal;

        // NOTE: This is a multicall binary, so argv[0] is necessary for
        // program operation.  We would fail very early if it didn't exist.
        let prog = std::env::args().next().unwrap();
        let term = std::io::stderr().is_terminal();

        let error_marker = if term {
            "\x1B[31mERROR:\x1B[0m"
        } else {
            "ERROR:"
        };

        eprint!("[{prog}] {error_marker} {}", self.0.primary);
        for context in &self.0.context {
            eprint!("\n... while {context}");
        }
    }
}

//--- Conversions for '?'

impl From<&str> for Error {
    fn from(error: &str) -> Self {
        Self::new(error)
    }
}

impl From<String> for Error {
    fn from(error: String) -> Self {
        Self::new(&error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::new(&error.to_string())
    }
}

impl From<lexopt::Error> for Error {
    fn from(value: lexopt::Error) -> Self {
        value.to_string().into()
    }
}

//--- Display, Debug

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0.primary)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Error")
            .field("primary", &self.0.primary)
            .field("context", &self.0.context)
            .finish()
    }
}

//--- Error

impl error::Error for Error {}

//------------ Result --------------------------------------------------------

/// A program result.
pub type Result<T> = core::result::Result<T, Error>;

/// An extension trait for [`Result`]s using [`Error`].
pub trait Context: Sized {
    /// Add context for an error.
    fn context(self, context: &str) -> Self;

    /// Add context for an error, lazily.
    fn with_context(self, context: impl FnOnce() -> String) -> Self;
}

impl<T> Context for Result<T> {
    fn context(self, context: &str) -> Self {
        self.map_err(|err| err.context(context))
    }

    fn with_context(self, context: impl FnOnce() -> String) -> Self {
        self.map_err(|err| err.context(&(context)()))
    }
}
