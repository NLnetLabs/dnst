use std::fmt;
use std::{error, io};

use crate::env::{Env, RED, YELLOW};

//------------ Error ---------------------------------------------------------

/// A program error.
///
/// Such errors are highly likely to halt the program.
pub struct Error {
    info: Box<Information>,
    is_warning: bool,
}

/// Information about an error.
struct Information {
    /// The primary error message.
    primary: PrimaryError,

    /// Layers of context to the error.
    ///
    /// Ordered from innermost to outermost.
    context: Vec<Box<str>>,
}

impl Information {
    fn other(info: &str) -> Self {
        Information {
            primary: PrimaryError::Other(info.into()),
            context: Vec::new(),
        }
    }

    fn clap(info: clap::Error) -> Self {
        Information {
            primary: PrimaryError::Clap(info),
            context: Vec::new(),
        }
    }
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
    /// Construct a new error from a string.
    #[allow(clippy::self_named_constructors)]
    pub fn error(error: &str) -> Self {
        Self {
            info: Box::new(Information::other(error)),
            is_warning: false,
        }
    }

    /// Construct a new warning from a string.
    pub fn warn(warning: &str) -> Self {
        Self {
            info: Box::new(Information::other(warning)),
            is_warning: true,
        }
    }

    /// Add context to this error.
    pub fn context(mut self, context: &str) -> Self {
        self.info.context.push(context.into());
        self
    }

    /// Pretty-print this error.
    pub fn pretty_print(&self, env: impl Env) {
        let mut err = env.stderr();

        let info = match &self.info.primary {
            // Clap errors are already styled. We don't want our own pretty
            // styling around that and context does not make sense for command
            // line arguments either. So we just print the styled string that
            // clap produces and return.
            PrimaryError::Clap(e) => {
                writeln!(err, "{}", e.render().ansi());
                return;
            }
            PrimaryError::Other(error) => error,
        };

        // NOTE: This is a multicall binary, so argv[0] is necessary for
        // program operation.  We would fail very early if it didn't exist.
        let prog = std::env::args().next().unwrap();
        let colour = match self.is_warning {
            true => YELLOW,
            false => RED,
        };
        let marker = err.colourize(colour, "ERROR:");
        writeln!(err, "[{prog}] {marker} {info}");
        for context in &self.info.context {
            writeln!(err, "\n... while {context}");
        }
    }

    pub fn exit_code(&self) -> u8 {
        // Clap uses the exit code 2 and we want to keep that, but we aren't
        // actually returning the clap error, so we replicate that behaviour
        // here.
        //
        // Argument parsing errors from the ldns-xxx commands will not be clap
        // errors and therefore be printed with an exit code of 1. This is
        // expected because ldns also exits with 1.
        if let PrimaryError::Clap(e) = &self.info.primary {
            e.exit_code() as u8
        } else {
            1
        }
    }
}

//--- Conversions for '?'

impl From<&str> for Error {
    fn from(error: &str) -> Self {
        Self::error(error)
    }
}

impl From<String> for Error {
    fn from(error: String) -> Self {
        Self::error(&error)
    }
}

impl From<fmt::Error> for Error {
    fn from(error: fmt::Error) -> Self {
        Self::error(&error.to_string())
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::error(&error.to_string())
    }
}

impl From<lexopt::Error> for Error {
    fn from(value: lexopt::Error) -> Self {
        value.to_string().into()
    }
}

impl From<clap::Error> for Error {
    fn from(value: clap::Error) -> Self {
        Error {
            info: Box::new(Information::clap(value)),
            is_warning: false,
        }
    }
}

//--- Display, Debug

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.info.primary.fmt(f)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Error")
            .field("primary", &self.info.primary)
            .field("context", &self.info.context)
            .finish()
    }
}

//--- Error

impl error::Error for Error {}

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
