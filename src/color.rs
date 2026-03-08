/// Result of mapping a CVSS score to HSL color values.
#[derive(Debug, Clone, Copy)]
pub struct HueResult {
    /// HSL hue (0-360).
    pub hue: f64,
    /// Saturation percentage.
    pub sat: f64,
    /// Lightness multiplier: >1 lighter (low scores), <1 darker (high scores).
    pub light: f64,
}

/// Map a CVSS score (0-10) to HSL color values.
///
/// Light yellow (low) -> orange (mid) -> dark red (high).
pub fn score_to_hue(score: f64) -> HueResult {
    let w = score.clamp(0.0, 10.0) / 10.0;

    let hue = if w <= 0.5 {
        // light yellow -> orange: hue 55 -> 25
        55.0 - (w / 0.5) * 30.0
    } else {
        // orange -> dark red: hue 25 -> 0
        25.0 - ((w - 0.5) / 0.5) * 25.0
    };

    let sat = 85.0 + (1.0 - w) * 10.0; // 95% at low -> 85% at high

    // Lightness multiplier: asymmetric
    //   score 0: 1.15, score 5: 1.0, score 10: 0.55
    let light = if w <= 0.5 {
        1.0 + (0.5 - w) * 0.3 // low end: 1.0 -> 1.15
    } else {
        1.0 - (w - 0.5) * 0.9 // high end: 1.0 -> 0.55
    };

    HueResult { hue, sat, light }
}
