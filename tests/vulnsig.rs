use vulnsig::{
    calculate_score, detect_cvss_version, is_version3, parse_cvss, render_glyph, score_to_hue,
    CvssVersion, RenderOptions,
};

const LOG4SHELL: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H";

// CVSS 3.1 test vectors
const CVSS31_LOG4SHELL: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
const CVSS31_HEARTBLEED: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";
const CVSS31_DIRTY_COW: &str = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N";
const CVSS31_XSS: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";

// CVSS 3.0 test vectors
const CVSS30_LOG4SHELL: &str = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
const CVSS30_HEARTBLEED: &str = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";
const CVSS30_XSS: &str = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";

// CVSS 4.0 vectors with E (Exploit Maturity)
fn log4shell_e_a() -> String {
    format!("{LOG4SHELL}/E:A")
}
fn log4shell_e_p() -> String {
    format!("{LOG4SHELL}/E:P")
}
fn log4shell_e_u() -> String {
    format!("{LOG4SHELL}/E:U")
}
fn log4shell_e_x() -> String {
    format!("{LOG4SHELL}/E:X")
}

// Test vectors loaded from JSON
#[derive(serde::Deserialize)]
struct TestVector {
    #[allow(dead_code)]
    name: String,
    vector: String,
    score: f64,
}

fn load_test_vectors() -> Vec<TestVector> {
    let data = include_str!("test-vectors.json");
    serde_json::from_str(data).unwrap()
}

// --- parseCVSS tests ---

#[test]
fn parse_cvss_full_vector() {
    let m = parse_cvss(LOG4SHELL);
    assert_eq!(m.get("AV").map(|s| s.as_str()), Some("N"));
    assert_eq!(m.get("AC").map(|s| s.as_str()), Some("L"));
    assert_eq!(m.get("SC").map(|s| s.as_str()), Some("H"));
}

#[test]
fn parse_cvss_e_metric() {
    let m = parse_cvss(&log4shell_e_a());
    assert_eq!(m.get("AV").map(|s| s.as_str()), Some("N"));
    assert_eq!(m.get("E").map(|s| s.as_str()), Some("A"));

    let m2 = parse_cvss(&log4shell_e_p());
    assert_eq!(m2.get("E").map(|s| s.as_str()), Some("P"));

    let m3 = parse_cvss(&log4shell_e_u());
    assert_eq!(m3.get("E").map(|s| s.as_str()), Some("U"));

    let m4 = parse_cvss(&log4shell_e_x());
    assert_eq!(m4.get("E").map(|s| s.as_str()), Some("X"));
}

#[test]
fn parse_cvss_missing_optional_metrics() {
    let m = parse_cvss("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H");
    assert_eq!(m.get("AV").map(|s| s.as_str()), Some("N"));
    assert!(m.get("SC").is_none());
}

#[test]
fn parse_cvss_31_vector() {
    let m = parse_cvss(CVSS31_LOG4SHELL);
    assert_eq!(m.get("AV").map(|s| s.as_str()), Some("N"));
    assert_eq!(m.get("AC").map(|s| s.as_str()), Some("L"));
    assert_eq!(m.get("C").map(|s| s.as_str()), Some("H"));
    assert_eq!(m.get("I").map(|s| s.as_str()), Some("H"));
    assert_eq!(m.get("A").map(|s| s.as_str()), Some("H"));
    assert_eq!(m.get("S").map(|s| s.as_str()), Some("C"));
}

#[test]
fn parse_cvss_30_vector() {
    let m = parse_cvss(CVSS30_LOG4SHELL);
    assert_eq!(m.get("AV").map(|s| s.as_str()), Some("N"));
    assert_eq!(m.get("AC").map(|s| s.as_str()), Some("L"));
    assert_eq!(m.get("C").map(|s| s.as_str()), Some("H"));
    assert_eq!(m.get("I").map(|s| s.as_str()), Some("H"));
    assert_eq!(m.get("A").map(|s| s.as_str()), Some("H"));
    assert_eq!(m.get("S").map(|s| s.as_str()), Some("C"));
}

// --- detectCVSSVersion tests ---

#[test]
fn detect_cvss_30() {
    assert_eq!(
        detect_cvss_version(CVSS30_LOG4SHELL).unwrap(),
        CvssVersion::V3_0
    );
}

#[test]
fn detect_cvss_31() {
    assert_eq!(
        detect_cvss_version(CVSS31_LOG4SHELL).unwrap(),
        CvssVersion::V3_1
    );
}

#[test]
fn detect_cvss_40() {
    assert_eq!(detect_cvss_version(LOG4SHELL).unwrap(), CvssVersion::V4_0);
}

#[test]
fn detect_cvss_unsupported_version() {
    let result = detect_cvss_version("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Unsupported CVSS version"));
}

#[test]
fn detect_cvss_no_prefix() {
    let result = detect_cvss_version("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Unsupported CVSS version"));
}

// --- isVersion3 tests ---

#[test]
fn is_version3_for_30() {
    assert!(is_version3(CvssVersion::V3_0));
}

#[test]
fn is_version3_for_31() {
    assert!(is_version3(CvssVersion::V3_1));
}

#[test]
fn is_version3_for_40() {
    assert!(!is_version3(CvssVersion::V4_0));
}

// --- scoreToHue tests ---

#[test]
fn score_to_hue_yellow_for_0() {
    assert_eq!(score_to_hue(0.0).hue, 55.0);
}

#[test]
fn score_to_hue_red_for_10() {
    assert_eq!(score_to_hue(10.0).hue, 0.0);
}

#[test]
fn score_to_hue_decreases_with_score() {
    assert!(score_to_hue(0.0).hue > score_to_hue(10.0).hue);
}

// --- calculateScore tests ---

#[test]
fn calculate_score_log4shell_10() {
    assert_eq!(calculate_score(LOG4SHELL), 10.0);
}

#[test]
fn calculate_score_invalid_returns_5() {
    assert_eq!(calculate_score("garbage"), 5.0);
}

#[test]
fn calculate_score_cvss31_log4shell() {
    assert_eq!(calculate_score(CVSS31_LOG4SHELL), 10.0);
}

#[test]
fn calculate_score_cvss31_heartbleed() {
    assert_eq!(calculate_score(CVSS31_HEARTBLEED), 7.5);
}

#[test]
fn calculate_score_cvss31_dirty_cow() {
    let score = calculate_score(CVSS31_DIRTY_COW);
    assert!((score - 7.1).abs() < 0.05, "Expected ~7.1, got {score}");
}

#[test]
fn calculate_score_cvss31_xss() {
    assert_eq!(calculate_score(CVSS31_XSS), 6.1);
}

#[test]
fn calculate_score_cvss30_log4shell() {
    assert_eq!(calculate_score(CVSS30_LOG4SHELL), 10.0);
}

#[test]
fn calculate_score_cvss30_heartbleed() {
    assert_eq!(calculate_score(CVSS30_HEARTBLEED), 7.5);
}

#[test]
fn calculate_score_cvss30_xss() {
    assert_eq!(calculate_score(CVSS30_XSS), 6.1);
}

// --- renderGlyph tests ---

#[test]
fn render_glyph_valid_svg() {
    let svg = render_glyph(&RenderOptions {
        vector: LOG4SHELL,
        score: Some(10.0),
        size: None,
    });
    assert!(svg.starts_with("<svg "));
    assert!(svg.ends_with("</svg>"));
}

#[test]
fn render_glyph_respects_size() {
    let svg = render_glyph(&RenderOptions {
        vector: LOG4SHELL,
        score: Some(10.0),
        size: Some(64),
    });
    assert!(svg.contains("width=\"64\""));
    assert!(svg.contains("height=\"64\""));
}

#[test]
fn render_glyph_all_test_vectors() {
    let vectors = load_test_vectors();
    for tv in &vectors {
        let svg = render_glyph(&RenderOptions {
            vector: &tv.vector,
            score: Some(tv.score),
            size: None,
        });
        assert!(
            svg.starts_with("<svg "),
            "Failed for {}: {}",
            tv.name,
            &svg[..50.min(svg.len())]
        );
        assert!(svg.ends_with("</svg>"), "Failed for {}", tv.name);
    }
}

#[test]
fn render_glyph_cvss31_vectors() {
    for vector in [
        CVSS31_LOG4SHELL,
        CVSS31_HEARTBLEED,
        CVSS31_DIRTY_COW,
        CVSS31_XSS,
    ] {
        let svg = render_glyph(&RenderOptions {
            vector,
            score: None,
            size: None,
        });
        assert!(svg.starts_with("<svg "));
        assert!(svg.ends_with("</svg>"));
    }
}

#[test]
fn render_glyph_cvss31_scope_changed() {
    let svg = render_glyph(&RenderOptions {
        vector: CVSS31_LOG4SHELL,
        score: None,
        size: None,
    });
    assert!(svg.contains("<svg"));
    assert!(svg.contains("</svg>"));
}

#[test]
fn render_glyph_cvss31_scope_unchanged() {
    let svg = render_glyph(&RenderOptions {
        vector: CVSS31_HEARTBLEED,
        score: None,
        size: None,
    });
    assert!(svg.contains("<svg"));
    assert!(svg.contains("</svg>"));
}

#[test]
fn render_glyph_cvss31_ui_r() {
    let svg = render_glyph(&RenderOptions {
        vector: CVSS31_XSS,
        score: None,
        size: None,
    });
    assert!(svg.contains("<svg"));
    assert!(svg.contains("</svg>"));
}

#[test]
fn render_glyph_cvss30_vectors() {
    for vector in [CVSS30_LOG4SHELL, CVSS30_HEARTBLEED, CVSS30_XSS] {
        let svg = render_glyph(&RenderOptions {
            vector,
            score: None,
            size: None,
        });
        assert!(svg.starts_with("<svg "));
        assert!(svg.ends_with("</svg>"));
    }
}

#[test]
fn render_glyph_cvss30_scope_changed() {
    let svg = render_glyph(&RenderOptions {
        vector: CVSS30_LOG4SHELL,
        score: None,
        size: None,
    });
    assert!(svg.contains("<svg"));
    assert!(svg.contains("</svg>"));
}

#[test]
fn render_glyph_cvss30_scope_unchanged() {
    let svg = render_glyph(&RenderOptions {
        vector: CVSS30_HEARTBLEED,
        score: None,
        size: None,
    });
    assert!(svg.contains("<svg"));
    assert!(svg.contains("</svg>"));
}

#[test]
fn render_glyph_e_a_concentric_rings() {
    let vector = log4shell_e_a();
    let svg = render_glyph(&RenderOptions {
        vector: &vector,
        score: Some(10.0),
        size: None,
    });
    assert!(svg.contains("<svg"));
    // E:A renders concentric ring strokes with hsla
    assert!(svg.contains(r#"stroke="hsla("#));
}

#[test]
fn render_glyph_e_p_solid_circle() {
    let vector = log4shell_e_p();
    let svg = render_glyph(&RenderOptions {
        vector: &vector,
        score: Some(10.0),
        size: None,
    });
    assert!(svg.contains("<svg"));
    // E:P renders solid filled circle with hsla
    assert!(svg.contains(r#"fill="hsla("#));
}

#[test]
fn render_glyph_e_u_no_marker() {
    let vector = log4shell_e_u();
    let svg = render_glyph(&RenderOptions {
        vector: &vector,
        score: Some(10.0),
        size: None,
    });
    assert!(svg.contains("<svg"));
    assert!(!svg.contains(r#"fill="hsla("#));
    assert!(!svg.contains(r#"stroke="hsla("#));
}

#[test]
fn render_glyph_e_x_no_marker() {
    let vector = log4shell_e_x();
    let svg = render_glyph(&RenderOptions {
        vector: &vector,
        score: Some(10.0),
        size: None,
    });
    assert!(svg.contains("<svg"));
    assert!(!svg.contains(r#"fill="hsla("#));
    assert!(!svg.contains(r#"stroke="hsla("#));
}

#[test]
fn render_glyph_cvss3x_no_e_marker() {
    let svg = render_glyph(&RenderOptions {
        vector: CVSS31_LOG4SHELL,
        score: None,
        size: None,
    });
    assert!(!svg.contains(r#"fill="hsla("#));
    assert!(!svg.contains(r#"stroke="hsla("#));
}
