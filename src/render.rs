use std::f64::consts::PI;

use crate::color::score_to_hue;
use crate::geometry::{arc_path, radial_cuts, ring_fill, star_path};
use crate::parse::{detect_cvss_version, get_severity, is_version3, parse_cvss};
use crate::score::calculate_score;

/// Render a CVSS vector as an SVG glyph string.
///
/// - `vector`: CVSS 4.0, 3.1, or 3.0 vector string.
/// - `score`: Explicit score override (0-10). Auto-calculated when `None`.
/// - `size`: Rendered size in pixels. Default: 120.
pub fn render_glyph(vector: &str, score: Option<f64>, size: Option<u32>) -> String {
    let size = size.unwrap_or(120);
    let metrics = parse_cvss(vector);
    let version = detect_cvss_version(vector).unwrap_or(crate::parse::CvssVersion::V4_0);

    let score = score.unwrap_or_else(|| calculate_score(vector));

    let hr = score_to_hue(score);
    let hue = hr.hue;
    let sat = hr.sat;
    let light = hr.light;

    let ac = get_severity(&metrics, "AC");
    let at = if is_version3(version) {
        1.0
    } else {
        get_severity(&metrics, "AT")
    };

    let vc = if is_version3(version) {
        get_severity(&metrics, "C")
    } else {
        get_severity(&metrics, "VC")
    };
    let vi = if is_version3(version) {
        get_severity(&metrics, "I")
    } else {
        get_severity(&metrics, "VI")
    };
    let va = if is_version3(version) {
        get_severity(&metrics, "A")
    } else {
        get_severity(&metrics, "VA")
    };

    let (sc, si, sa) = if is_version3(version) {
        let scope_changed = get_severity(&metrics, "S") > 0.5;
        if scope_changed {
            (vc, vi, va)
        } else {
            (0.0, 0.0, 0.0)
        }
    } else {
        (
            get_severity(&metrics, "SC"),
            get_severity(&metrics, "SI"),
            get_severity(&metrics, "SA"),
        )
    };

    let has_any_sub = sc > 0.0 || si > 0.0 || sa > 0.0;
    let at_present = at < 0.5;

    let cx = 60.0_f64;
    let cy = 60.0_f64;
    let av_raw = metrics.get("AV").map(|s| s.as_str()).unwrap_or("N");
    let petal_count: usize = match av_raw {
        "N" => 8,
        "A" => 6,
        "L" => 4,
        "P" => 3,
        _ => 8,
    };

    // Geometry constants
    let ring_width = 4.375;
    let ring_gap = 1.5;
    let outer_r = 44.0;
    let hue_ring_r = outer_r + ring_gap + ring_width / 2.0;

    let sub_inner_r = outer_r - ring_width;
    let vuln_outer_r = sub_inner_r - ring_gap;
    let vuln_inner_r = vuln_outer_r - ring_width;
    let inner_r = vuln_inner_r;

    let gap_deg = 3.0;
    let cut_gap_deg = 4.0;
    let cut_width_deg = 3.0;

    let star_outer_r = inner_r - 2.0;
    let star_inner_r = star_outer_r * (0.55 - ac * 0.35);

    // PR stroke
    let pr_raw = metrics.get("PR").map(|s| s.as_str()).unwrap_or("N");
    let pr_stroke_width: f64 = match pr_raw {
        "H" => 3.5,
        "L" => 1.5,
        _ => 0.0,
    };

    // UI spikes/bumps
    let ui_raw = metrics.get("UI").map(|s| s.as_str()).unwrap_or("N");
    let spike_base = hue_ring_r + ring_width / 2.0 - 0.5;

    // Star fill
    let sf_sat = sat;
    let sf_light = 52.0 * light;

    // Deterministic gradient ID from vector hash
    let grad_id = format!("sg-{}", simple_hash(vector));

    // Sectors
    struct Sector {
        s: f64,
        e: f64,
        vuln: f64,
        sub: f64,
    }
    let sectors = [
        Sector {
            s: -150.0 + gap_deg / 2.0,
            e: -30.0 - gap_deg / 2.0,
            vuln: vc,
            sub: sc,
        },
        Sector {
            s: -30.0 + gap_deg / 2.0,
            e: 90.0 - gap_deg / 2.0,
            vuln: vi,
            sub: si,
        },
        Sector {
            s: 90.0 + gap_deg / 2.0,
            e: 210.0 - gap_deg / 2.0,
            vuln: va,
            sub: sa,
        },
    ];

    let mut parts = Vec::new();

    // Defs
    parts.push(format!(
        "<defs><radialGradient id=\"{grad_id}\" gradientUnits=\"userSpaceOnUse\" cx=\"{cx}\" cy=\"{cy}\" r=\"{star_outer_r}\">"
    ));
    parts.push(format!(
        "<stop offset=\"0%\" stop-color=\"hsla({hue}, {}%, {}%, 1)\"/>",
        sf_sat * 1.1,
        sf_light + 10.0
    ));
    parts.push(format!(
        "<stop offset=\"100%\" stop-color=\"hsla({hue}, {sf_sat}%, {sf_light}%, 1)\"/>"
    ));
    parts.push("</radialGradient></defs>".to_string());

    // Z-order 1: UI:N Spikes
    if ui_raw == "N" {
        for i in 0..petal_count {
            let a = (2.0 * PI * i as f64) / petal_count as f64 - PI / 2.0;
            let x1 = cx + a.cos() * spike_base;
            let y1 = cy + a.sin() * spike_base;
            let x2 = cx + a.cos() * (spike_base + 3.4);
            let y2 = cy + a.sin() * (spike_base + 3.4);
            parts.push(format!(
                "<line x1=\"{x1}\" y1=\"{y1}\" x2=\"{x2}\" y2=\"{y2}\" stroke=\"hsl({hue}, {sat}%, {sf_light}%)\" stroke-width=\"3.0\" stroke-linecap=\"round\"/>"
            ));
        }
    }

    // Z-order 2: UI:P Bumps
    if ui_raw == "P" {
        let bump_r = 4.6;
        for i in 0..petal_count {
            let a = (2.0 * PI * i as f64) / petal_count as f64 - PI / 2.0;
            let bx = cx + a.cos() * spike_base;
            let by = cy + a.sin() * spike_base;
            let perp_l = a - PI / 2.0;
            let perp_r = a + PI / 2.0;
            let x1 = bx + perp_l.cos() * bump_r;
            let y1 = by + perp_l.sin() * bump_r;
            let x2 = bx + perp_r.cos() * bump_r;
            let y2 = by + perp_r.sin() * bump_r;
            parts.push(format!(
                "<path d=\"M{x1},{y1} A{bump_r},{bump_r} 0 0,1 {x2},{y2} Z\" fill=\"hsl({hue}, {sat}%, {sf_light}%)\"/>"
            ));
        }
    }

    // Z-order 3: Background circle (transparent)
    parts.push(format!(
        "<circle cx=\"{cx}\" cy=\"{cy}\" r=\"{inner_r}\" fill=\"none\"/>"
    ));

    // Z-order 3.5: E (Exploit Maturity) marker — CVSS 4.0 only
    let e_raw = if is_version3(version) {
        None
    } else {
        metrics.get("E").map(|s| s.as_str())
    };
    if e_raw == Some("A") || e_raw == Some("P") {
        let e_circle_r = inner_r - ring_gap;
        let e_ring_gap = ring_gap * 3.0;
        if e_raw == Some("A") {
            let e_color = format!("hsla({hue}, {sat}%, {sf_light}%, 0.5)");
            let sw = ring_width;
            let step = sw + e_ring_gap;
            let mut r = e_circle_r - sw / 2.0;
            while r - sw / 2.0 > 0.0 {
                parts.push(format!(
                    "<circle cx=\"{cx}\" cy=\"{cy}\" r=\"{r}\" fill=\"none\" stroke=\"{e_color}\" stroke-width=\"{sw}\"/>"
                ));
                r -= step;
            }
        } else {
            // E:P -> solid filled circle
            parts.push(format!(
                "<circle cx=\"{cx}\" cy=\"{cy}\" r=\"{e_circle_r}\" fill=\"hsla({hue}, {sat}%, {sf_light}%, 0.375)\"/>"
            ));
        }
    }

    // Z-order 4: Star fill
    let star_d = star_path(cx, cy, petal_count, star_outer_r, star_inner_r);
    parts.push(format!(
        "<path d=\"{star_d}\" fill=\"url(#{grad_id})\" stroke=\"none\"/>"
    ));

    // Z-order 5: Star stroke (PR:N = no stroke)
    if pr_stroke_width > 0.0 {
        parts.push(format!(
            "<path d=\"{star_d}\" fill=\"none\" stroke=\"hsl({}, {}%, {}%)\" stroke-width=\"{pr_stroke_width}\" stroke-linejoin=\"round\"/>",
            (hue + 10.0) % 360.0,
            sat * 0.8,
            sf_light + 10.0
        ));
    }

    // Z-order 6 & 7: CIA ring sectors (with AT:P clip-path if segmented)
    if at_present {
        let clip_id = format!("at-{}", simple_hash(vector));
        let mut clip_paths = String::new();
        for sec in &sectors {
            let cuts = radial_cuts(sec.s, sec.e, cut_width_deg, cut_gap_deg);
            let mut prev_end = sec.s;
            for cut in &cuts {
                if cut.start_deg > prev_end {
                    clip_paths.push_str(&format!(
                        "<path d=\"{}\"/>",
                        arc_path(
                            cx,
                            cy,
                            vuln_inner_r - 1.0,
                            outer_r + 1.0,
                            prev_end,
                            cut.start_deg
                        )
                    ));
                }
                prev_end = cut.end_deg;
            }
            if prev_end < sec.e {
                clip_paths.push_str(&format!(
                    "<path d=\"{}\"/>",
                    arc_path(cx, cy, vuln_inner_r - 1.0, outer_r + 1.0, prev_end, sec.e)
                ));
            }
        }
        parts.push(format!(
            "<clipPath id=\"{clip_id}\">{clip_paths}</clipPath>"
        ));
        parts.push(format!("<g clip-path=\"url(#{clip_id})\">"));
    }

    for sec in &sectors {
        let vuln_band_outer = if has_any_sub { vuln_outer_r } else { outer_r };
        parts.push(format!(
            "<path d=\"{}\" fill=\"{}\"/>",
            arc_path(cx, cy, vuln_inner_r, vuln_band_outer, sec.s, sec.e),
            ring_fill(sec.vuln, hue, sat, light)
        ));

        if has_any_sub {
            parts.push(format!(
                "<path d=\"{}\" fill=\"{}\"/>",
                arc_path(cx, cy, sub_inner_r, outer_r, sec.s, sec.e),
                ring_fill(sec.sub, hue, sat, light)
            ));
        }
    }

    if at_present {
        parts.push("</g>".to_string());
    }

    // Z-order 9: Outer hue ring
    parts.push(format!(
        "<circle cx=\"{cx}\" cy=\"{cy}\" r=\"{hue_ring_r}\" fill=\"none\" stroke=\"hsl({hue}, {sat}%, {sf_light}%)\" stroke-width=\"{ring_width}\"/>"
    ));

    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{size}\" height=\"{size}\" viewBox=\"0 0 120 120\" style=\"overflow:visible\">{}</svg>",
        parts.join("")
    )
}

fn simple_hash(s: &str) -> String {
    let mut h: i32 = 0;
    for b in s.bytes() {
        h = ((h << 5).wrapping_sub(h)).wrapping_add(b as i32);
    }
    to_base36(h.unsigned_abs())
}

fn to_base36(mut n: u32) -> String {
    if n == 0 {
        return "0".to_string();
    }
    const CHARS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut result = Vec::new();
    while n > 0 {
        result.push(CHARS[(n % 36) as usize]);
        n /= 36;
    }
    result.reverse();
    String::from_utf8(result).unwrap()
}
