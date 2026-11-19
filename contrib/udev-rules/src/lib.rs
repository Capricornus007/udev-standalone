//! Parse and lint `udev(7)` rules files.
//!
//! ```
//! use udev_rules::check;
//! let diags = check(r#"SUBSYSTEM=="net", ACTION=="add", NAME="eth0""#);
//! assert!(diags.is_empty());
//! ```

pub mod lint;
pub mod parse;

pub use lint::lint;
pub use parse::{parse, Diag, Op, ParseOutput, Rule, Severity, Token};

/// Parse and lint in one pass, returning all diagnostics.
pub fn check(text: &str) -> Vec<Diag> {
    let out = parse(text);
    let mut diags = out.diags;
    diags.extend(lint(&out.rules));
    diags
}
