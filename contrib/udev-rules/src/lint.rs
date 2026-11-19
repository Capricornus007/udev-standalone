//! Semantic checks over parsed udev rules.

use crate::parse::{Diag, Op, Rule, Severity, Token};
use std::collections::HashMap;

const MATCH_ONLY: &[&str] = &[
    "ACTION",
    "DEVPATH",
    "KERNEL",
    "KERNELS",
    "SUBSYSTEM",
    "SUBSYSTEMS",
    "DRIVER",
    "DRIVERS",
    "ATTRS",
    "TAGS",
    "RESULT",
    "TEST",
    "CONST",
];
const ASSIGN_ONLY: &[&str] = &["LABEL", "GOTO", "IMPORT", "RUN", "PROGRAM"];
const BOTH: &[&str] = &[
    "ATTR", "ENV", "TAG", "NAME", "SYMLINK", "OWNER", "GROUP", "MODE", "OPTIONS",
];
const REQUIRES_SUBKEY: &[&str] = &["ENV", "ATTR", "ATTRS", "IMPORT", "CONST"];
const KNOWN_OPTIONS: &[&str] = &[
    "link_priority",
    "string_escape",
    "nowatch",
    "watch",
    "db_persist",
    "static_node",
    "log_level",
    "event_timeout",
    "last_rule",
];

fn is_assign(op: Op) -> bool {
    !op.is_match()
}

fn push(diags: &mut Vec<Diag>, severity: Severity, code: &str, message: String, t: &Token) {
    diags.push(Diag {
        severity,
        code: code.into(),
        message,
        line: t.line,
        column: t.column,
    });
}

pub fn lint(rules: &[Rule]) -> Vec<Diag> {
    let mut diags = Vec::new();
    let mut labels: HashMap<String, usize> = HashMap::new();

    for rule in rules {
        for t in &rule.tokens {
            let key = t.key.as_str();
            let known =
                MATCH_ONLY.contains(&key) || ASSIGN_ONLY.contains(&key) || BOTH.contains(&key);
            if !known {
                push(
                    &mut diags,
                    Severity::Error,
                    "U001",
                    format!("unknown key '{key}'"),
                    t,
                );
                continue;
            }
            if MATCH_ONLY.contains(&key) && is_assign(t.op) {
                push(
                    &mut diags,
                    Severity::Error,
                    "U002",
                    format!("key '{key}' is match-only, cannot use '{}'", t.op.as_str()),
                    t,
                );
            }
            if ASSIGN_ONLY.contains(&key) && t.op.is_match() {
                push(
                    &mut diags,
                    Severity::Error,
                    "U002",
                    format!("key '{key}' is assign-only, cannot use '{}'", t.op.as_str()),
                    t,
                );
            }
            if REQUIRES_SUBKEY.contains(&key) && t.subkey.is_none() {
                push(
                    &mut diags,
                    Severity::Error,
                    "U003",
                    format!("key '{key}' requires a {{name}}"),
                    t,
                );
            }
            if (key == "LABEL" || key == "GOTO") && t.subkey.is_some() {
                push(
                    &mut diags,
                    Severity::Error,
                    "U010",
                    format!("key '{key}' does not take a {{name}}"),
                    t,
                );
            }
            if key == "LABEL" && is_assign(t.op) {
                if let Some(prev) = labels.insert(t.value.clone(), t.line) {
                    push(
                        &mut diags,
                        Severity::Error,
                        "U005",
                        format!("duplicate LABEL '{}' (first at line {prev})", t.value),
                        t,
                    );
                }
            }
            if key == "MODE"
                && is_assign(t.op)
                && !t.value.is_empty()
                && !t.value.contains('$')
                && !t.value.contains('%')
                && !(t.value.len() <= 4 && t.value.chars().all(|c| ('0'..='7').contains(&c)))
            {
                push(
                    &mut diags,
                    Severity::Warning,
                    "U006",
                    format!("MODE '{}' is not an octal permission", t.value),
                    t,
                );
            }
            if (key == "RUN" || key == "PROGRAM" || key == "IMPORT")
                && is_assign(t.op)
                && t.value.trim().is_empty()
            {
                push(
                    &mut diags,
                    Severity::Warning,
                    "U007",
                    format!("{key} has an empty value"),
                    t,
                );
            }
            if key == "OPTIONS" && is_assign(t.op) {
                for opt in t.value.split(',') {
                    let name = opt.trim().split('=').next().unwrap_or("");
                    if !name.is_empty() && !KNOWN_OPTIONS.contains(&name) {
                        push(
                            &mut diags,
                            Severity::Warning,
                            "U008",
                            format!("unknown OPTIONS '{name}'"),
                            t,
                        );
                    }
                }
            }
        }

        let removes = rule
            .tokens
            .iter()
            .any(|t| t.key == "ACTION" && t.op == Op::Match && t.value == "remove");
        if removes {
            for t in &rule.tokens {
                if (t.key == "NAME" || t.key == "SYMLINK") && is_assign(t.op) {
                    push(
                        &mut diags,
                        Severity::Warning,
                        "U009",
                        format!("{} assigned on ACTION==\"remove\" has no effect", t.key),
                        t,
                    );
                }
            }
        }
    }

    for rule in rules {
        for t in &rule.tokens {
            if t.key == "GOTO" && is_assign(t.op) && !labels.contains_key(&t.value) {
                push(
                    &mut diags,
                    Severity::Error,
                    "U004",
                    format!("GOTO target '{}' is not defined by any LABEL", t.value),
                    t,
                );
            }
        }
    }

    diags
}
