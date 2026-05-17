use std::collections::HashMap;

/// Parsed CVSS metrics as key-value pairs.
pub type ParsedMetrics = HashMap<String, String>;

/// CVSS version detected from a vector string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CvssVersion {
    V2_0,
    V3_0,
    V3_1,
    V4_0,
}

/// Returns whether a metric key is known across any supported CVSS version.
fn is_known_metric(key: &str) -> bool {
    matches!(
        key,
        "AV" | "AC"
            | "AT"
            | "PR"
            | "UI"
            | "Au"
            | "VC"
            | "VI"
            | "VA"
            | "SC"
            | "SI"
            | "SA"
            | "C"
            | "I"
            | "A"
            | "S"
            | "E"
            | "RL"
            | "RC"
            | "CDP"
            | "TD"
            | "CR"
            | "IR"
            | "AR"
    )
}

/// Look up the severity value for a given metric key and value.
fn metric_severity(key: &str, val: &str) -> Option<f64> {
    match key {
        "AV" => match val {
            "N" => Some(1.0),
            "A" => Some(0.7),
            "L" => Some(0.4),
            "P" => Some(0.15),
            _ => None,
        },
        // M is a CVSS 2.0 value (Medium).
        "AC" => match val {
            "L" => Some(1.0),
            "M" => Some(0.7),
            "H" => Some(0.4),
            _ => None,
        },
        "AT" => match val {
            "N" => Some(1.0),
            "P" => Some(0.4),
            _ => None,
        },
        "PR" => match val {
            "N" => Some(1.0),
            "L" => Some(0.6),
            "H" => Some(0.2),
            _ => None,
        },
        "UI" => match val {
            "N" => Some(1.0),
            "P" => Some(0.6),
            "A" | "R" => Some(0.2),
            _ => None,
        },
        // CVSS 2.0 Authentication — mirrors the PR shape so the stroke-width
        // branch in render.rs can reuse the same width function.
        "Au" => match val {
            "N" => Some(1.0),
            "S" => Some(0.6),
            "M" => Some(0.2),
            _ => None,
        },
        // CVSS 3.x C/I/A use H/L/N; CVSS 2.0 uses C/P/N — both resolve here.
        "VC" | "VI" | "VA" | "SC" | "SI" | "SA" | "C" | "I" | "A" => match val {
            "H" | "C" => Some(1.0),
            "L" | "P" => Some(0.5),
            "N" => Some(0.0),
            _ => None,
        },
        "S" => match val {
            "C" => Some(1.0),
            "U" => Some(0.0),
            _ => None,
        },
        // Exploit Maturity — superset of CVSS 4.0 (A/P/U/X) and CVSS 2.0 (U/POC/F/H/ND).
        "E" => match val {
            "A" | "H" => Some(1.0),
            "F" => Some(0.8),
            "P" | "POC" => Some(0.6),
            "U" => Some(0.2),
            "X" | "ND" => Some(0.0),
            _ => None,
        },
        // CVSS 2.0 temporal / environmental — included so parse_cvss retains them
        // for downstream scoring; render.rs ignores them.
        "RL" => match val {
            "OF" => Some(0.0),
            "TF" => Some(0.4),
            "W" => Some(0.7),
            "U" | "ND" => Some(1.0),
            _ => None,
        },
        "RC" => match val {
            "UC" => Some(0.3),
            "UR" => Some(0.6),
            "C" | "ND" => Some(1.0),
            _ => None,
        },
        "CDP" => match val {
            "N" | "ND" => Some(0.0),
            "L" => Some(0.2),
            "LM" => Some(0.4),
            "MH" => Some(0.6),
            "H" => Some(1.0),
            _ => None,
        },
        "TD" => match val {
            "N" => Some(0.0),
            "L" => Some(0.3),
            "M" => Some(0.6),
            "H" | "ND" => Some(1.0),
            _ => None,
        },
        "CR" | "IR" | "AR" => match val {
            "L" => Some(0.4),
            "M" | "ND" => Some(1.0),
            "H" => Some(1.51),
            _ => None,
        },
        _ => None,
    }
}

/// CVSS 2.0 is commonly written bare (no prefix), occasionally in parens,
/// sometimes with a non-spec `CVSS:2.0/` prefix. Strip all of that to a
/// canonical form so the slash-splitting parser works uniformly.
pub fn normalize_v2_vector(vector: &str) -> String {
    let mut s = vector.trim();
    if let Some(rest) = s.strip_prefix('(') {
        s = rest;
    }
    if let Some(rest) = s.strip_suffix(')') {
        s = rest;
    }
    if let Some(rest) = s.strip_prefix("CVSS:2.0/") {
        s = rest;
    }
    s.trim_matches('/').to_string()
}

/// Parse a CVSS vector string into metric key-value pairs.
pub fn parse_cvss(vector: &str) -> ParsedMetrics {
    let body_owned;
    let body: &str = match detect_cvss_version(vector) {
        Ok(CvssVersion::V2_0) => {
            body_owned = normalize_v2_vector(vector);
            &body_owned
        }
        _ => vector,
    };
    let mut m = ParsedMetrics::new();
    for part in body.split('/') {
        if let Some((key, val)) = part.split_once(':') {
            if is_known_metric(key) {
                m.insert(key.to_string(), val.to_string());
            }
        }
    }
    m
}

/// Detect the CVSS version from a vector string prefix (or shape, for v2).
pub fn detect_cvss_version(vector: &str) -> Result<CvssVersion, String> {
    if vector.starts_with("CVSS:3.1/") {
        Ok(CvssVersion::V3_1)
    } else if vector.starts_with("CVSS:3.0/") {
        Ok(CvssVersion::V3_0)
    } else if vector.starts_with("CVSS:4.0/") {
        Ok(CvssVersion::V4_0)
    } else if vector.starts_with("CVSS:2.0/")
        || (!vector.starts_with("CVSS:") && looks_like_cvss2(vector))
    {
        Ok(CvssVersion::V2_0)
    } else {
        Err("Unsupported CVSS version. Vector must start with 'CVSS:2.0/', 'CVSS:3.0/', 'CVSS:3.1/', or 'CVSS:4.0/', or be a bare CVSS 2.0 vector.".to_string())
    }
}

/// CVSS 2.0 base vectors always include AV, AC, Au, C, I, A. Require at least
/// the v2-distinctive Au token plus AV/AC so random strings still error out.
fn looks_like_cvss2(vector: &str) -> bool {
    let body = normalize_v2_vector(vector);
    let mut has_au = false;
    let mut has_av = false;
    let mut has_ac = false;
    for part in body.split('/') {
        match part.split_once(':').map(|(k, _)| k) {
            Some("Au") => has_au = true,
            Some("AV") => has_av = true,
            Some("AC") => has_ac = true,
            _ => {}
        }
    }
    has_au && has_av && has_ac
}

/// Returns `true` if the version is CVSS 3.0 or 3.1.
pub fn is_version3(version: CvssVersion) -> bool {
    matches!(version, CvssVersion::V3_0 | CvssVersion::V3_1)
}

/// Returns `true` if the version is CVSS 2.0.
pub fn is_version2(version: CvssVersion) -> bool {
    matches!(version, CvssVersion::V2_0)
}

/// Look up the severity value for a metric key in parsed metrics.
pub fn get_severity(metrics: &ParsedMetrics, key: &str) -> f64 {
    let val = match metrics.get(key) {
        Some(v) => v.as_str(),
        None => return 0.0,
    };
    metric_severity(key, val).unwrap_or(0.0)
}
