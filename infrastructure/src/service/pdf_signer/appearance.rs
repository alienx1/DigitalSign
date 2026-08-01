/// Content stream that draws an image XObject named `/{name}` scaled to fill
/// the `(width, height)` box, translated to `(x, y)`.
pub fn content_stream_for_image(x: f32, y: f32, width: f32, height: f32, name: &str) -> Vec<u8> {
    format!("q {width} 0 0 {height} {x} {y} cm /{name} Do Q").into_bytes()
}

/// Content stream fallback when no signature image was supplied: a border
/// rectangle plus "Signed by <signer_name>" text using the font named
/// `/{font_name}`, inside the `(width, height)` box translated to `(x, y)`.
pub fn content_stream_for_text(
    x: f32,
    y: f32,
    width: f32,
    height: f32,
    font_name: &str,
    signer_name: &str,
) -> Vec<u8> {
    let text = escape_pdf_literal(&format!("Signed by: {signer_name}"));
    let font_size = (height * 0.25).clamp(6.0, 12.0);
    format!(
        "q 0.5 w {x} {y} {width} {height} re S Q\n\
         BT /{font_name} {font_size} Tf {text_x} {text_y} Td ({text}) Tj ET",
        text_x = x + 4.0,
        text_y = y + (height / 2.0 - font_size / 2.0).max(2.0),
    )
    .into_bytes()
}

fn escape_pdf_literal(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)")
}
