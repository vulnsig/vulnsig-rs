mod color;
mod geometry;
mod parse;
mod render;
mod score;

pub use color::{score_to_hue, HueResult};
pub use parse::{detect_cvss_version, is_version3, parse_cvss, CvssVersion, ParsedMetrics};
pub use render::render_glyph;
pub use score::calculate_score;

/// Options for rendering a CVSS glyph.
pub struct RenderOptions<'a> {
    /// CVSS 4.0, CVSS 3.1, or CVSS 3.0 vector string.
    pub vector: &'a str,
    /// Explicit score override (0-10). Auto-calculated when `None`.
    pub score: Option<f64>,
    /// Rendered size in pixels. Default: 120.
    pub size: Option<u32>,
}
