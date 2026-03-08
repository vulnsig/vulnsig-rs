use std::f64::consts::PI;

const DEG2RAD: f64 = PI / 180.0;

/// Generate an SVG path for an annular sector (ring segment).
pub fn arc_path(
    cx: f64,
    cy: f64,
    inner_r: f64,
    outer_r: f64,
    start_deg: f64,
    end_deg: f64,
) -> String {
    let s = start_deg * DEG2RAD;
    let e = end_deg * DEG2RAD;
    let la = if end_deg - start_deg > 180.0 { 1 } else { 0 };
    let osx = cx + s.cos() * outer_r;
    let osy = cy + s.sin() * outer_r;
    let oex = cx + e.cos() * outer_r;
    let oey = cy + e.sin() * outer_r;
    let iex = cx + e.cos() * inner_r;
    let iey = cy + e.sin() * inner_r;
    let isx = cx + s.cos() * inner_r;
    let isy = cy + s.sin() * inner_r;
    format!(
        "M{osx},{osy} A{outer_r},{outer_r} 0 {la},1 {oex},{oey} L{iex},{iey} A{inner_r},{inner_r} 0 {la},0 {isx},{isy} Z"
    )
}

/// Generate an SVG star/polygon path with alternating outer/inner vertices.
pub fn star_path(cx: f64, cy: f64, points: usize, outer_r: f64, inner_r: f64) -> String {
    let mut d = String::new();
    for i in 0..points {
        let oa = (2.0 * PI * i as f64) / points as f64 - PI / 2.0;
        let ia = (2.0 * PI * (i as f64 + 0.5)) / points as f64 - PI / 2.0;
        let ox = cx + oa.cos() * outer_r;
        let oy = cy + oa.sin() * outer_r;
        let ix = cx + ia.cos() * inner_r;
        let iy = cy + ia.sin() * inner_r;
        if i == 0 {
            d.push_str(&format!("M{ox},{oy}"));
        } else {
            d.push_str(&format!("L{ox},{oy}"));
        }
        d.push_str(&format!("L{ix},{iy}"));
    }
    d.push('Z');
    d
}

/// A radial cut defined by start and end angles in degrees.
pub struct Cut {
    pub start_deg: f64,
    pub end_deg: f64,
}

/// Calculate cut positions for AT:P segmentation.
pub fn radial_cuts(start_deg: f64, end_deg: f64, cut_width: f64, gap_deg: f64) -> Vec<Cut> {
    let sector_span = end_deg - start_deg;
    let step = cut_width + gap_deg;
    let num_cuts = ((sector_span - gap_deg) / step).floor() as usize;
    let pattern_span = num_cuts as f64 * cut_width + (num_cuts as f64 + 1.0) * gap_deg;
    let offset = (sector_span - pattern_span) / 2.0;
    let mut cuts = Vec::new();
    for i in 0..num_cuts {
        let cut_start = start_deg + offset + (i as f64 + 1.0) * gap_deg + i as f64 * cut_width;
        let cut_end = cut_start + cut_width;
        cuts.push(Cut {
            start_deg: cut_start,
            end_deg: cut_end,
        });
    }
    cuts
}

/// Return an HSL(A) color string based on metric magnitude.
pub fn ring_fill(magnitude: f64, hue: f64, sat: f64, light: f64) -> String {
    let l = 52.0 * light;
    if magnitude <= 0.01 {
        format!("hsla({hue}, {sat}%, {l}%, 0.125)")
    } else if magnitude <= 0.5 {
        format!("hsla({hue}, {sat}%, {l}%, 0.5)")
    } else {
        format!("hsl({hue}, {sat}%, {l}%)")
    }
}
