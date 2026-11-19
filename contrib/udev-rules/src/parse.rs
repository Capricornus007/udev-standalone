//! Tokenizer for udev rules files (see `udev(7)`).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Diag {
    pub severity: Severity,
    pub code: String,
    pub message: String,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Match,    // ==
    NotMatch, // !=
    Assign,   // =
    Add,      // +=
    Remove,   // -=
    Final,    // :=
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Match => "==",
            Op::NotMatch => "!=",
            Op::Assign => "=",
            Op::Add => "+=",
            Op::Remove => "-=",
            Op::Final => ":=",
        }
    }
    pub fn is_match(self) -> bool {
        matches!(self, Op::Match | Op::NotMatch)
    }
}

#[derive(Debug, Clone)]
pub struct Token {
    pub key: String,
    pub subkey: Option<String>,
    pub op: Op,
    pub value: String,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub tokens: Vec<Token>,
    pub line: usize,
}

#[derive(Debug, Default)]
pub struct ParseOutput {
    pub rules: Vec<Rule>,
    pub diags: Vec<Diag>,
}

fn strip_comment(raw: &str) -> (String, bool) {
    let mut out = String::new();
    let mut in_quote = false;
    let mut escape = false;
    for c in raw.chars() {
        if escape {
            out.push(c);
            escape = false;
            continue;
        }
        match c {
            '\\' if in_quote => {
                out.push(c);
                escape = true;
            }
            '"' => {
                in_quote = !in_quote;
                out.push(c);
            }
            '#' if !in_quote => break,
            _ => out.push(c),
        }
    }
    let trimmed = out.trim_end();
    let cont = !in_quote && trimmed.ends_with('\\');
    let body = if cont {
        trimmed[..trimmed.len() - 1].trim_end().to_string()
    } else {
        trimmed.to_string()
    };
    (body, cont)
}

pub fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut start = 0;
    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        let (clean, cont) = strip_comment(raw);
        if buf.is_empty() {
            start = line_no;
        }
        if !clean.is_empty() {
            if !buf.is_empty() {
                buf.push(' ');
            }
            buf.push_str(clean.trim());
        }
        if cont {
            continue;
        }
        if !buf.is_empty() {
            out.push((start, buf.clone()));
        }
        buf.clear();
    }
    if !buf.is_empty() {
        out.push((start, buf));
    }
    out
}

fn split_segments(line: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut start = 0;
    let mut in_quote = false;
    let mut escape = false;
    for (i, c) in line.chars().enumerate() {
        if escape {
            cur.push(c);
            escape = false;
            continue;
        }
        match c {
            '\\' if in_quote => {
                cur.push(c);
                escape = true;
            }
            '"' => {
                in_quote = !in_quote;
                cur.push(c);
            }
            ',' if !in_quote => {
                out.push((start + 1, cur.clone()));
                cur.clear();
                start = i + 1;
            }
            _ => cur.push(c),
        }
    }
    out.push((start + 1, cur));
    out
}

fn parse_value(s: &str, line: usize, column: usize, diags: &mut Vec<Diag>) -> Option<String> {
    let t = s.trim();
    if !t.starts_with('"') {
        diags.push(Diag {
            severity: Severity::Error,
            code: "U105".into(),
            message: "value must be a double-quoted string".into(),
            line,
            column,
        });
        return None;
    }
    let mut out = String::new();
    let mut escape = false;
    let mut closed = false;
    for c in t[1..].chars() {
        if escape {
            out.push(c);
            escape = false;
            continue;
        }
        match c {
            '\\' => escape = true,
            '"' => {
                closed = true;
                break;
            }
            _ => out.push(c),
        }
    }
    if !closed {
        diags.push(Diag {
            severity: Severity::Error,
            code: "U100".into(),
            message: "unbalanced double quote in value".into(),
            line,
            column,
        });
        return None;
    }
    Some(out)
}

fn parse_token(seg: &str, line: usize, col: usize, diags: &mut Vec<Diag>) -> Option<Token> {
    let t = seg.trim();
    if t.is_empty() {
        diags.push(Diag {
            severity: Severity::Warning,
            code: "U102".into(),
            message: "empty token (stray comma)".into(),
            line,
            column: col,
        });
        return None;
    }
    let mut rest = t;
    let key_len = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .count();
    if key_len == 0 {
        diags.push(Diag {
            severity: Severity::Error,
            code: "U101".into(),
            message: format!("token '{t}' does not start with a key"),
            line,
            column: col,
        });
        return None;
    }
    let key: String = rest.chars().take(key_len).collect();
    rest = &rest[key_len..];
    let mut subkey = None;
    if rest.starts_with('{') {
        if let Some(end) = rest.find('}') {
            subkey = Some(rest[1..end].to_string());
            rest = &rest[end + 1..];
        } else {
            diags.push(Diag {
                severity: Severity::Error,
                code: "U100".into(),
                message: format!("unbalanced '{{' in key '{key}'"),
                line,
                column: col,
            });
            return None;
        }
    }
    let rest_trim = rest.trim_start();
    let op = if rest_trim.starts_with("==") {
        Op::Match
    } else if rest_trim.starts_with("!=") {
        Op::NotMatch
    } else if rest_trim.starts_with(":=") {
        Op::Final
    } else if rest_trim.starts_with("+=") {
        Op::Add
    } else if rest_trim.starts_with("-=") {
        Op::Remove
    } else if rest_trim.starts_with('=') {
        Op::Assign
    } else {
        diags.push(Diag {
            severity: Severity::Error,
            code: "U104".into(),
            message: format!("missing or unknown operator after key '{key}'"),
            line,
            column: col,
        });
        return None;
    };
    let op_len = if op == Op::Assign { 1 } else { 2 };
    let value_src = &rest_trim[op_len..];
    let value = parse_value(value_src, line, col, diags)?;
    Some(Token {
        key,
        subkey,
        op,
        value,
        line,
        column: col,
    })
}

pub fn parse(text: &str) -> ParseOutput {
    let mut out = ParseOutput::default();
    for (line_no, line) in logical_lines(text) {
        let mut tokens = Vec::new();
        for (col, seg) in split_segments(&line) {
            if let Some(tok) = parse_token(&seg, line_no, col, &mut out.diags) {
                tokens.push(tok);
            }
        }
        if !tokens.is_empty() {
            out.rules.push(Rule {
                tokens,
                line: line_no,
            });
        }
    }
    out
}
