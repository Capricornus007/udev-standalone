use udev_rules::{check, parse, Op, Severity};

fn codes(text: &str) -> Vec<String> {
    check(text).into_iter().map(|d| d.code).collect()
}

#[test]
fn clean_rule_has_no_diags() {
    assert!(codes(r#"SUBSYSTEM=="net", ACTION=="add", NAME="eth0""#).is_empty());
    assert!(codes("LABEL=\"end\"\nACTION==\"remove\", GOTO=\"end\"\n").is_empty());
}

#[test]
fn continuation_and_comments() {
    let text =
        "# comment\nSUBSYSTEM==\"net\", \\\n  ACTION==\"add\", \\\n  NAME=\"eth0\" # trailing\n";
    let out = parse(text);
    assert!(out.diags.is_empty());
    assert_eq!(out.rules.len(), 1);
    assert_eq!(out.rules[0].tokens.len(), 3);
    assert_eq!(out.rules[0].line, 2);
}

#[test]
fn token_structure() {
    let out = parse(r#"ENV{ID_FS_USAGE}=="filesystem", MODE="0660", RUN+="/bin/x""#);
    let t = &out.rules[0].tokens;
    assert_eq!(t[0].key, "ENV");
    assert_eq!(t[0].subkey.as_deref(), Some("ID_FS_USAGE"));
    assert_eq!(t[0].op, Op::Match);
    assert_eq!(t[1].key, "MODE");
    assert_eq!(t[1].op, Op::Assign);
    assert_eq!(t[2].op, Op::Add);
}

#[test]
fn unknown_key() {
    assert!(codes(r#"BOGUS=="x""#).contains(&"U001".to_string()));
}

#[test]
fn operator_key_compatibility() {
    assert!(codes(r#"ACTION="add""#).contains(&"U002".to_string()));
    assert!(codes(r#"LABEL=="x""#).contains(&"U002".to_string()));
    assert!(codes(r#"KERNEL="sda""#).contains(&"U002".to_string()));
}

#[test]
fn required_subkey() {
    assert!(codes(r#"ENV="x""#).contains(&"U003".to_string()));
    assert!(codes(r#"IMPORT="x""#).contains(&"U003".to_string()));
    // TEST and RUN subkeys are optional
    assert!(!codes(r#"TEST=="state""#).contains(&"U003".to_string()));
    assert!(!codes(r#"RUN+="/bin/x""#).contains(&"U003".to_string()));
}

#[test]
fn goto_label_resolution() {
    assert!(codes(r#"GOTO="missing""#).contains(&"U004".to_string()));
    let ok = "LABEL=\"here\"\nGOTO=\"here\"\n";
    assert!(!codes(ok).contains(&"U004".to_string()));
}

#[test]
fn duplicate_label() {
    let text = "LABEL=\"dup\"\nLABEL=\"dup\"\n";
    assert!(codes(text).contains(&"U005".to_string()));
}

#[test]
fn mode_octal() {
    assert!(codes(r#"MODE="0660""#).is_empty());
    assert!(codes(r#"MODE="0999""#).contains(&"U006".to_string()));
    assert!(codes(r#"MODE="$env{M}""#).is_empty());
}

#[test]
fn empty_run_and_unknown_options() {
    assert!(codes("RUN+=\"\"").contains(&"U007".to_string()));
    assert!(codes(r#"OPTIONS+="bogus_option""#).contains(&"U008".to_string()));
    assert!(!codes(r#"OPTIONS+="link_priority=-100""#).contains(&"U008".to_string()));
}

#[test]
fn name_on_remove_only_for_positive_match() {
    assert!(codes(r#"ACTION=="remove", SYMLINK+="x""#).contains(&"U009".to_string()));
    assert!(!codes(r#"ACTION!="remove", SYMLINK+="x""#).contains(&"U009".to_string()));
}

#[test]
fn parse_errors() {
    assert!(codes("SUBSYSTEM==\"net").contains(&"U100".to_string()));
    assert!(codes("SUBSYSTEM==net").contains(&"U105".to_string()));
    assert!(codes("SUBSYSTEM").contains(&"U104".to_string()));
}

#[test]
fn stray_comma_is_style_warning() {
    let d = check("SUBSYSTEM==\"usb\",, GOTO=\"x\"");
    assert!(d
        .iter()
        .any(|x| x.code == "U102" && x.severity == Severity::Warning));
    assert!(!d
        .iter()
        .any(|x| x.severity == Severity::Error && x.code == "U102"));
}

#[test]
fn oracle_system_rules_have_no_errors() {
    let dir = std::path::Path::new("/usr/lib/udev/rules.d");
    if !dir.exists() {
        eprintln!("skip: no system udev rules");
        return;
    }
    let mut checked = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rules") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let errs: Vec<_> = check(&text)
            .into_iter()
            .filter(|d| d.severity == Severity::Error)
            .collect();
        assert!(errs.is_empty(), "{}: {errs:?}", path.display());
        checked += 1;
    }
    assert!(checked > 0);

    if std::process::Command::new("udevadm")
        .arg("--version")
        .output()
        .is_ok()
    {
        let status = std::process::Command::new("udevadm")
            .arg("verify")
            .arg("--no-style")
            .arg(dir)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "udevadm verify --no-style should accept system rules"
        );
    }
}
