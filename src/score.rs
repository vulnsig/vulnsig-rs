use crate::parse::{detect_cvss_version, CvssVersion};

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
    }
}
