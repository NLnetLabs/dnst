use std::fmt;
use std::{error, io};

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
        use std::io::IsTerminal;
        let mut err = env.stderr();

        let error = match &self.0.primary {
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
        let term = std::io::stderr().is_terminal();

        // 1B is the ASCII C0 ESC control code that introduces an ANSI escape
        // sequence, 31 is the ANSI escape sequence for setting the terminal
        // foreground colour to red, and 0 resets all attributes to their
        // defaults.
        //
        // See:
        //   - https://en.wikipedia.org/wiki/ANSI_escape_code#C0_control_codes
        //   - https://en.wikipedia.org/wiki/ANSI_escape_code#Colors
        let error_marker = if term {
            &Self::colourize(Self::RED, "ERROR:")
        } else {
            "ERROR:"
        };

        write!(err, "[{prog}] {error_marker} {error}");
        for context in &self.0.context {
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
        if let PrimaryError::Clap(e) = &self.0.primary {
            e.exit_code() as u8
        } else {
            1
        }
    }

    pub fn colourize(colour_code: u8, text: &str) -> String {
        // 1B is the ASCII C0 ESC control code that introduces an ANSI escape
        // sequence, 31 is the ANSI escape sequence for setting the terminal
        // foreground colour to red, and 0 resets all attributes to their
        // defaults.
        //
        // See:
        //   - https://en.wikipedia.org/wiki/ANSI_escape_code#C0_control_codes
        //   - https://en.wikipedia.org/wiki/ANSI_escape_code#Colors
        format!("\x1B[{colour_code}m{text}\x1B[0m")
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
