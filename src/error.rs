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
    ///
    /// This is the innermost error to occur.
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

//--- Display, Debug

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("\x1E[31mERROR:\x1E[0m ")?;
        f.write_str(&self.0.primary)?;
        self.0.context.iter().try_for_each(|c| {
            f.write_str("\n... while ")?;
            f.write_str(c)
        })
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
