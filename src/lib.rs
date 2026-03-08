mod color;
mod geometry;
mod parse;
mod render;
mod score;

pub use color::{score_to_hue, HueResult};
pub use render::render_glyph;
pub use score::calculate_score;
