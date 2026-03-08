use std::collections::HashMap;

/// Parsed CVSS metrics as key-value pairs.
pub type ParsedMetrics = HashMap<String, String>;

/// CVSS version detected from a vector string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CvssVersion {
    V3_0,
    V3_1,
    V4_0,
}

/// Returns whether a metric key is known.
fn is_known_metric(key: &str) -> bool {
    matches!(
        key,
        "AV" | "AC"
            | "AT"
            | "PR"
            | "UI"
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
        "AC" => match val {
            "L" => Some(1.0),
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
        "VC" | "VI" | "VA" | "SC" | "SI" | "SA" | "C" | "I" | "A" => match val {
            "H" => Some(1.0),
            "L" => Some(0.5),
            "N" => Some(0.0),
            _ => None,
        },
        "S" => match val {
            "C" => Some(1.0),
            "U" => Some(0.0),
            _ => None,
        },
        "E" => match val {
            "A" => Some(1.0),
            "P" => Some(0.6),
            "U" => Some(0.2),
            "X" => Some(0.0),
            _ => None,
        },
        _ => None,
    }
}

/// Parse a CVSS vector string into metric key-value pairs.
pub fn parse_cvss(vector: &str) -> ParsedMetrics {
    let mut m = ParsedMetrics::new();
    for part in vector.split('/') {
        if let Some((key, val)) = part.split_once(':') {
            if is_known_metric(key) {
                m.insert(key.to_string(), val.to_string());
            }
        }
    }
    m
}

/// Detect the CVSS version from a vector string prefix.
pub fn detect_cvss_version(vector: &str) -> Result<CvssVersion, String> {
    if vector.starts_with("CVSS:3.1/") {
        Ok(CvssVersion::V3_1)
    } else if vector.starts_with("CVSS:3.0/") {
        Ok(CvssVersion::V3_0)
    } else if vector.starts_with("CVSS:4.0/") {
        Ok(CvssVersion::V4_0)
    } else {
        Err("Unsupported CVSS version. Vector must start with 'CVSS:3.0/', 'CVSS:3.1/', or 'CVSS:4.0/'".to_string())
    }
}

/// Returns `true` if the version is CVSS 3.0 or 3.1.
pub fn is_version3(version: CvssVersion) -> bool {
    matches!(version, CvssVersion::V3_0 | CvssVersion::V3_1)
}

/// Look up the severity value for a metric key in parsed metrics.
pub fn get_severity(metrics: &ParsedMetrics, key: &str) -> f64 {
    let val = match metrics.get(key) {
        Some(v) => v.as_str(),
        None => return 0.0,
    };
    metric_severity(key, val).unwrap_or(0.0)
}
