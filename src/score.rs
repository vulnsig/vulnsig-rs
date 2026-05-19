use crate::parse::{detect_cvss_version, normalize_v2_vector, CvssVersion};

/// Calculate the CVSS base score from a vector string.
///
/// Returns 5.0 as fallback for invalid vectors.
pub fn calculate_score(vector: &str) -> f64 {
    calculate_score_inner(vector).unwrap_or(5.0)
}

fn calculate_score_inner(vector: &str) -> Option<f64> {
    let version = detect_cvss_version(vector).ok()?;
    match version {
        CvssVersion::V3_0 | CvssVersion::V3_1 => {
            let base: cvss::v3::Base = vector.parse().ok()?;
            Some(base.score().value())
        }
        CvssVersion::V4_0 => {
            let v: cvss::v4::Vector = vector.parse().ok()?;
            Some(v.score().value())
        }
        CvssVersion::V2_0 => calculate_cvss2_score(&normalize_v2_vector(vector)),
    }
}

// --- CVSS 2.0 scoring (FIRST CVSS v2 Specification §3) -------------------
//
// Implemented inline because the `cvss` crate dependency does not cover v2.
// Returns the "overall" score: environmental if any env metric is set,
// otherwise temporal if any temporal metric is set, otherwise base.

fn calculate_cvss2_score(body: &str) -> Option<f64> {
    let mut av = None;
    let mut ac = None;
    let mut au = None;
    let mut c = None;
    let mut i_imp = None;
    let mut a_imp = None;
    let mut e = 1.0;
    let mut rl = 1.0;
    let mut rc = 1.0;
    let mut cdp = 0.0;
    let mut td = 1.0;
    let mut cr = 1.0;
    let mut ir = 1.0;
    let mut ar = 1.0;
    let mut any_temporal = false;
    let mut any_env = false;

    for part in body.split('/') {
        let (key, val) = part.split_once(':')?;
        match key {
            "AV" => av = av_weight(val),
            "AC" => ac = ac_weight(val),
            "Au" => au = au_weight(val),
            "C" => c = cia_weight(val),
            "I" => i_imp = cia_weight(val),
            "A" => a_imp = cia_weight(val),
            "E" => {
                if let Some(w) = e_weight(val) {
                    e = w;
                    any_temporal = true;
                }
            }
            "RL" => {
                if let Some(w) = rl_weight(val) {
                    rl = w;
                    any_temporal = true;
                }
            }
            "RC" => {
                if let Some(w) = rc_weight(val) {
                    rc = w;
                    any_temporal = true;
                }
            }
            "CDP" => {
                if let Some(w) = cdp_weight(val) {
                    cdp = w;
                    any_env = true;
                }
            }
            "TD" => {
                if let Some(w) = td_weight(val) {
                    td = w;
                    any_env = true;
                }
            }
            "CR" => {
                if let Some(w) = req_weight(val) {
                    cr = w;
                    any_env = true;
                }
            }
            "IR" => {
                if let Some(w) = req_weight(val) {
                    ir = w;
                    any_env = true;
                }
            }
            "AR" => {
                if let Some(w) = req_weight(val) {
                    ar = w;
                    any_env = true;
                }
            }
            _ => {}
        }
    }

    let av = av?;
    let ac = ac?;
    let au = au?;
    let c = c?;
    let i_imp = i_imp?;
    let a_imp = a_imp?;

    let impact = 10.41 * (1.0 - (1.0 - c) * (1.0 - i_imp) * (1.0 - a_imp));
    let exploitability = 20.0 * av * ac * au;
    let f_impact = if impact == 0.0 { 0.0 } else { 1.176 };
    let base = round1((0.6 * impact + 0.4 * exploitability - 1.5) * f_impact);

    if !any_temporal && !any_env {
        return Some(base);
    }

    let temporal = round1(base * e * rl * rc);
    if !any_env {
        return Some(temporal);
    }

    let adj_impact =
        (10.41 * (1.0 - (1.0 - c * cr) * (1.0 - i_imp * ir) * (1.0 - a_imp * ar))).min(10.0);
    let adj_f = if adj_impact == 0.0 { 0.0 } else { 1.176 };
    let adj_base = round1((0.6 * adj_impact + 0.4 * exploitability - 1.5) * adj_f);
    let adj_temporal = round1(adj_base * e * rl * rc);
    let env = round1((adj_temporal + (10.0 - adj_temporal) * cdp) * td);
    Some(env)
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

fn av_weight(v: &str) -> Option<f64> {
    match v {
        "N" => Some(1.0),
        "A" => Some(0.646),
        "L" => Some(0.395),
        _ => None,
    }
}

fn ac_weight(v: &str) -> Option<f64> {
    match v {
        "H" => Some(0.35),
        "M" => Some(0.61),
        "L" => Some(0.71),
        _ => None,
    }
}

fn au_weight(v: &str) -> Option<f64> {
    match v {
        "M" => Some(0.45),
        "S" => Some(0.56),
        "N" => Some(0.704),
        _ => None,
    }
}

fn cia_weight(v: &str) -> Option<f64> {
    match v {
        "N" => Some(0.0),
        "P" => Some(0.275),
        "C" => Some(0.660),
        _ => None,
    }
}

fn e_weight(v: &str) -> Option<f64> {
    match v {
        "U" => Some(0.85),
        "POC" => Some(0.9),
        "F" => Some(0.95),
        "H" | "ND" => Some(1.0),
        _ => None,
    }
}

fn rl_weight(v: &str) -> Option<f64> {
    match v {
        "OF" => Some(0.87),
        "TF" => Some(0.90),
        "W" => Some(0.95),
        "U" | "ND" => Some(1.0),
        _ => None,
    }
}

fn rc_weight(v: &str) -> Option<f64> {
    match v {
        "UC" => Some(0.90),
        "UR" => Some(0.95),
        "C" | "ND" => Some(1.0),
        _ => None,
    }
}

fn cdp_weight(v: &str) -> Option<f64> {
    match v {
        "N" | "ND" => Some(0.0),
        "L" => Some(0.1),
        "LM" => Some(0.3),
        "MH" => Some(0.4),
        "H" => Some(0.5),
        _ => None,
    }
}

fn td_weight(v: &str) -> Option<f64> {
    match v {
        "N" => Some(0.0),
        "L" => Some(0.25),
        "M" => Some(0.75),
        "H" | "ND" => Some(1.0),
        _ => None,
    }
}

fn req_weight(v: &str) -> Option<f64> {
    match v {
        "L" => Some(0.5),
        "M" | "ND" => Some(1.0),
        "H" => Some(1.51),
        _ => None,
    }
}
