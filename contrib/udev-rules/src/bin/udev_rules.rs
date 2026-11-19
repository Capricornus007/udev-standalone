use std::env;
use std::fs;
use std::process::exit;
use udev_rules::{check, parse, Diag, Severity};

fn usage() -> ! {
    eprintln!("usage: udev-rules lint [--json] [--strict] [-q] FILE...\n       udev-rules parse --json FILE...");
    exit(2);
}

fn json_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn diag_json(d: &Diag) -> String {
    format!(
        "{{\"severity\":\"{}\",\"code\":\"{}\",\"message\":\"{}\",\"line\":{},\"column\":{}}}",
        d.severity.as_str(),
        d.code,
        json_escape(&d.message),
        d.line,
        d.column
    )
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    let cmd = args[0].as_str();
    let mut json = false;
    let mut strict = false;
    let mut quiet = false;
    let mut files: Vec<String> = Vec::new();
    for a in &args[1..] {
        match a.as_str() {
            "--json" => json = true,
            "--strict" => strict = true,
            "-q" | "--quiet" => quiet = true,
            "-h" | "--help" => {
                println!("udev-rules: parse and lint udev(7) rules files");
                exit(0);
            }
            s if s.starts_with('-') => usage(),
            _ => files.push(a.clone()),
        }
    }
    if files.is_empty() {
        usage();
    }
    match cmd {
        "lint" => lint_cmd(&files, json, strict, quiet),
        "parse" => parse_cmd(&files, json),
        _ => usage(),
    }
}

fn lint_cmd(files: &[String], json: bool, strict: bool, quiet: bool) -> ! {
    let mut failed = false;
    let mut report: Vec<String> = Vec::new();
    for file in files {
        let text = match fs::read_to_string(file) {
            Ok(t) => t,
            Err(_) => {
                eprintln!("udev-rules: cannot read {file}");
                failed = true;
                continue;
            }
        };
        let diags: Vec<Diag> = check(&text)
            .into_iter()
            .filter(|d| !(quiet && d.severity == Severity::Warning))
            .collect();
        let errors = diags
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .count();
        let warnings = diags.len() - errors;
        if errors > 0 || (strict && warnings > 0) {
            failed = true;
        }
        if json {
            let items: Vec<String> = diags.iter().map(diag_json).collect();
            report.push(format!(
                "{{\"file\":\"{}\",\"errors\":{},\"warnings\":{},\"diags\":[{}]}}",
                json_escape(file),
                errors,
                warnings,
                items.join(",")
            ));
        } else {
            for d in &diags {
                println!(
                    "{}:{}:{}: {}: [{}] {}",
                    file,
                    d.line,
                    d.column,
                    d.severity.as_str(),
                    d.code,
                    d.message
                );
            }
            println!("{file}: {errors} error(s), {warnings} warning(s)");
        }
    }
    if json {
        println!("[{}]", report.join(","));
    }
    exit(if failed { 1 } else { 0 });
}

fn parse_cmd(files: &[String], json: bool) -> ! {
    if !json {
        eprintln!("udev-rules: parse requires --json");
        exit(2);
    }
    let mut failed = false;
    let mut report: Vec<String> = Vec::new();
    for file in files {
        let text = match fs::read_to_string(file) {
            Ok(t) => t,
            Err(_) => {
                eprintln!("udev-rules: cannot read {file}");
                failed = true;
                continue;
            }
        };
        let out = parse(&text);
        if out.diags.iter().any(|d| d.severity == Severity::Error) {
            failed = true;
        }
        let rules: Vec<String> = out
            .rules
            .iter()
            .map(|r| {
                let toks: Vec<String> = r
                    .tokens
                    .iter()
                    .map(|t| {
                        format!(
                            "{{\"key\":\"{}\",\"subkey\":{},\"op\":\"{}\",\"value\":\"{}\",\"line\":{},\"column\":{}}}",
                            json_escape(&t.key),
                            match &t.subkey {
                                Some(s) => format!("\"{}\"", json_escape(s)),
                                None => "null".into(),
                            },
                            t.op.as_str(),
                            json_escape(&t.value),
                            t.line,
                            t.column
                        )
                    })
                    .collect();
                format!("{{\"line\":{},\"tokens\":[{}]}}", r.line, toks.join(","))
            })
            .collect();
        let diags: Vec<String> = out.diags.iter().map(diag_json).collect();
        report.push(format!(
            "{{\"file\":\"{}\",\"rules\":[{}],\"diags\":[{}]}}",
            json_escape(file),
            rules.join(","),
            diags.join(",")
        ));
    }
    println!("[{}]", report.join(","));
    exit(if failed { 1 } else { 0 });
}
