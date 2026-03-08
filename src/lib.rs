mod color;
mod geometry;
mod parse;
mod render;
mod score;

pub use color::{score_to_hue, HueResult};
pub use parse::{detect_cvss_version, is_version3, parse_cvss, CvssVersion, ParsedMetrics};
pub use render::render_glyph;
pub use score::calculate_score;
