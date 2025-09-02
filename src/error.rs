use std::fmt;
use std::io;

use domain::base::wire::ParseError;
use tracing::error;

use crate::env::Env;

//------------ Error ---------------------------------------------------------

/// A program error.
///
/// Such errors are highly likely to halt the program.
pub struct Error(Box<Information>);

/// Information about an error.
struct Information {
    /// The primary error message.
    primary: PrimaryError,

    /// Layers of context to the error.
    ///
    /// Ordered from innermost to outermost.
    context: Vec<Box<str>>,
}

#[derive(Debug)]
enum PrimaryError {
    Clap(clap::Error),
    Other(Box<str>),
}

impl fmt::Display for PrimaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrimaryError::Clap(e) => e.fmt(f),
            PrimaryError::Other(e) => e.fmt(f),
        }
    }
}

//--- Interaction

impl Error {
    pub const RED: u8 = 31;
    pub const YELLOW: u8 = 33;

    /// Construct a new error from a string.
    pub fn new(error: &str) -> Self {
        Self(Box::new(Information {
            primary: PrimaryError::Other(error.into()),
            context: Vec::new(),
        }))
    }

    /// Add context to this error.
    pub fn context(mut self, context: &str) -> Self {
        self.0.context.push(context.into());
        self
    }

    /// Pretty-print this error.
    pub fn pretty_print(&self, env: impl Env) {
        let msg = match &self.0.primary {
            // Clap errors are already styled. We don't want our own pretty
            // styling around that and context does not make sense for command
            // line arguments either. So we just print the styled string that
            // clap produces and return.
            PrimaryError::Clap(e) => {
                let mut err = env.stderr();
                writeln!(err, "{}", e.render().ansi());
                return;
            }
            PrimaryError::Other(error) => error,
        };

        let mut buf = String::new();
        for context in &self.0.context {
            buf.push_str(&format!("... while {context}\n"));
        }
        error!("{msg}\n{buf}");
    }

    pub fn exit_code(&self) -> u8 {
        // Clap uses the exit code 2 and we want to keep that, but we aren't
        // actually returning the clap error, so we replicate that behaviour
        // here.
        //
        // Argument parsing errors from the ldns-xxx commands will not be clap
        // errors and therefore be printed with an exit code of 1. This is
        // expected because ldns also exits with 1.
        if let PrimaryError::Clap(e) = &self.0.primary {
            e.exit_code() as u8
        } else {
            1
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

impl From<fmt::Error> for Error {
    fn from(error: fmt::Error) -> Self {
        Self::new(&error.to_string())
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::new(&error.to_string())
    }
}

impl From<ParseError> for Error {
    fn from(error: ParseError) -> Self {
        Self::new(&error.to_string())
    }
}

impl From<lexopt::Error> for Error {
    fn from(value: lexopt::Error) -> Self {
        value.to_string().into()
    }
}

impl From<clap::Error> for Error {
    fn from(value: clap::Error) -> Self {
        Self(Box::new(Information {
            primary: PrimaryError::Clap(value),
            context: Vec::new(),
        }))
    }
}

//--- Display, Debug

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.primary.fmt(f)
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

impl std::error::Error for Error {}

//------------ Macros --------------------------------------------------------

// NOTE: Exported macros are placed in the crate root by default.  We hide
// them using 'doc(hidden)' and then manually re-export them here, forcing
// documentation to appear using 'doc(inline)'.

#[doc(inline)]
pub use crate::bail;

#[doc(inline)]
pub use crate::ensure;

/// Return an [`Error`] from the current function.
#[doc(hidden)]
#[macro_export]
macro_rules! bail {
    ($fmt:expr) => {
        return Err($crate::error::Error::new(&format!($fmt)));
    };

    ($fmt:expr, $($args:tt)*) => {
        return Err($crate::error::Error::new(&format!($fmt, $($args)*)));
    };
}

/// Return an [`Error`] if the given condition does not hold.
#[doc(hidden)]
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $fmt:expr) => {
        if !$cond { $crate::error::bail!($fmt); }
    };

    ($cond:expr, $fmt:expr, $($args:tt)*) => {
        if !$cond { $crate::error::bail!($fmt, $($args)*); }
    };
}

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

/// Execute the given operation under the given context.
pub fn in_context<R>(
    context: impl FnOnce() -> String,
    function: impl FnOnce() -> Result<R>,
) -> Result<R> {
    (function)().with_context(context)
}
