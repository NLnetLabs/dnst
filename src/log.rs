use std::fmt::Display;

use crate::env::Env;

mod color {
    pub const BLUE: u8 = 34;
    pub const YELLOW: u8 = 33;
    pub const RED: u8 = 31;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warning,
    Error,
}

impl LogLevel {
    fn color(self) -> u8 {
        match self {
            Self::Info => color::BLUE,
            Self::Warning => color::YELLOW,
            Self::Error => color::RED,
        }
    }

    fn text(self) -> &'static str {
        match self {
            LogLevel::Info => "INFO",
            LogLevel::Warning => "WARNING",
            LogLevel::Error => "ERROR",
        }
    }
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.text())
    }
}

struct Logger(&'static Env);

pub fn log(env: impl Env, level: LogLevel, text: impl Display) {
    let mut err = env.stderr();
    let prog = std::env::args().next().unwrap();

    if err.is_terminal() {
        let color = level.color();
        writeln!(err, "[{prog}] \x1B[{color}m{level}\x1B[0m: {text}");
    } else {
        writeln!(err, "[{prog}] {level}: {text}");
    }
}
