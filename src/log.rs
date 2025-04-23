use std::fmt;

use tracing::{Event, Level, Subscriber};
use tracing_subscriber::{
    fmt::{format, FmtContext, FormatEvent, FormatFields},
    registry::LookupSpan,
};

mod color {
    pub const RED: u8 = 31;
    pub const GREEN: u8 = 32;
    pub const YELLOW: u8 = 33;
    pub const BLUE: u8 = 34;
    pub const PURPLE: u8 = 35;
}

pub struct LogFormatter {
    pub program: String,
}

impl<S, N> FormatEvent<S, N> for LogFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: format::Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        // Format values from the event's's metadata:
        let metadata = event.metadata();

        write!(&mut writer, "[{}] ", &self.program)?;

        let level = *metadata.level();
        if writer.has_ansi_escapes() {
            let color = match level {
                Level::ERROR => color::RED,
                Level::WARN => color::YELLOW,
                Level::INFO => color::BLUE,
                Level::DEBUG => color::GREEN,
                Level::TRACE => color::PURPLE,
            };
            write!(&mut writer, "\x1B[{color}m{level}\x1B[0m: ",)?;
        } else {
            write!(&mut writer, "{level}: ")?;
        }

        // Write fields on the event
        ctx.field_format().format_fields(writer.by_ref(), event)?;

        writeln!(writer)
    }
}
