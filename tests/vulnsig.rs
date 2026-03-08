use vulnsig::{calculate_score, render_glyph, score_to_hue};

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
    let svg = render_glyph(LOG4SHELL, Some(10.0), None);
    assert!(svg.starts_with("<svg "));
    assert!(svg.ends_with("</svg>"));
}

#[test]
fn render_glyph_respects_size() {
    let svg = render_glyph(LOG4SHELL, Some(10.0), Some(64));
    assert!(svg.contains("width=\"64\""));
    assert!(svg.contains("height=\"64\""));
}

#[test]
fn render_glyph_all_test_vectors() {
    let vectors = load_test_vectors();
    for tv in &vectors {
        let svg = render_glyph(&tv.vector, Some(tv.score), None);
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
        let svg = render_glyph(vector, None, None);
        assert!(svg.starts_with("<svg "));
        assert!(svg.ends_with("</svg>"));
    }
}

#[test]
fn render_glyph_cvss31_scope_changed() {
    let svg = render_glyph(CVSS31_LOG4SHELL, None, None);
    assert!(svg.contains("<svg"));
    assert!(svg.contains("</svg>"));
}

#[test]
fn render_glyph_cvss31_scope_unchanged() {
    let svg = render_glyph(CVSS31_HEARTBLEED, None, None);
    assert!(svg.contains("<svg"));
    assert!(svg.contains("</svg>"));
}

#[test]
fn render_glyph_cvss31_ui_r() {
    let svg = render_glyph(CVSS31_XSS, None, None);
    assert!(svg.contains("<svg"));
    assert!(svg.contains("</svg>"));
}

#[test]
fn render_glyph_cvss30_vectors() {
    for vector in [CVSS30_LOG4SHELL, CVSS30_HEARTBLEED, CVSS30_XSS] {
        let svg = render_glyph(vector, None, None);
        assert!(svg.starts_with("<svg "));
        assert!(svg.ends_with("</svg>"));
    }
}

#[test]
fn render_glyph_cvss30_scope_changed() {
    let svg = render_glyph(CVSS30_LOG4SHELL, None, None);
    assert!(svg.contains("<svg"));
    assert!(svg.contains("</svg>"));
}

#[test]
fn render_glyph_cvss30_scope_unchanged() {
    let svg = render_glyph(CVSS30_HEARTBLEED, None, None);
    assert!(svg.contains("<svg"));
    assert!(svg.contains("</svg>"));
}

#[test]
fn render_glyph_e_a_concentric_rings() {
    let vector = log4shell_e_a();
    let svg = render_glyph(&vector, Some(10.0), None);
    assert!(svg.contains("<svg"));
    // E:A renders concentric ring strokes with hsla
    assert!(svg.contains(r#"stroke="hsla("#));
}

#[test]
fn render_glyph_e_p_solid_circle() {
    let vector = log4shell_e_p();
    let svg = render_glyph(&vector, Some(10.0), None);
    assert!(svg.contains("<svg"));
    // E:P renders solid filled circle with hsla
    assert!(svg.contains(r#"fill="hsla("#));
}

#[test]
fn render_glyph_e_u_no_marker() {
    let vector = log4shell_e_u();
    let svg = render_glyph(&vector, Some(10.0), None);
    assert!(svg.contains("<svg"));
    assert!(!svg.contains(r#"fill="hsla("#));
    assert!(!svg.contains(r#"stroke="hsla("#));
}

#[test]
fn render_glyph_e_x_no_marker() {
    let vector = log4shell_e_x();
    let svg = render_glyph(&vector, Some(10.0), None);
    assert!(svg.contains("<svg"));
    assert!(!svg.contains(r#"fill="hsla("#));
    assert!(!svg.contains(r#"stroke="hsla("#));
}

#[test]
fn render_glyph_cvss3x_no_e_marker() {
    let svg = render_glyph(CVSS31_LOG4SHELL, None, None);
    assert!(!svg.contains(r#"fill="hsla("#));
    assert!(!svg.contains(r#"stroke="hsla("#));
}
