use application_core::CoreError;

pub struct DecodedImage {
    pub width: u32,
    pub height: u32,
    pub rgb: Vec<u8>,
    pub alpha: Option<Vec<u8>>,
}

/// Decodes a PNG into 8-bit RGB samples (+ optional 8-bit alpha channel for
/// an SMask). Only 8-bit Grayscale/RGB/(Gray+Alpha)/RGBA PNGs are supported —
/// palette images and other bit depths are rejected with a clear error
/// rather than silently mis-rendered.
pub fn decode_png(bytes: &[u8]) -> Result<DecodedImage, CoreError> {
    let decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    let mut reader = decoder
        .read_info()
        .map_err(|e| CoreError::Signing(format!("invalid signature image: {e}")))?;

    if reader.info().bit_depth != png::BitDepth::Eight {
        return Err(CoreError::Signing(
            "signature image must be 8-bit PNG".into(),
        ));
    }

    let buffer_size = reader
        .output_buffer_size()
        .ok_or_else(|| CoreError::Signing("signature image too large to decode".into()))?;
    let mut buf = vec![0u8; buffer_size];
    let output_info = reader
        .next_frame(&mut buf)
        .map_err(|e| CoreError::Signing(format!("invalid signature image: {e}")))?;
    let samples = &buf[..output_info.buffer_size()];

    let width = output_info.width;
    let height = output_info.height;

    let (rgb, alpha) = match output_info.color_type {
        png::ColorType::Rgb => (samples.to_vec(), None),
        png::ColorType::Rgba => {
            let pixels = (width * height) as usize;
            let mut rgb = Vec::with_capacity(pixels * 3);
            let mut alpha = Vec::with_capacity(pixels);
            for chunk in samples.chunks_exact(4) {
                rgb.extend_from_slice(&chunk[..3]);
                alpha.push(chunk[3]);
            }
            (rgb, Some(alpha))
        }
        png::ColorType::Grayscale => {
            let mut rgb = Vec::with_capacity(samples.len() * 3);
            for &g in samples {
                rgb.extend_from_slice(&[g, g, g]);
            }
            (rgb, None)
        }
        png::ColorType::GrayscaleAlpha => {
            let pixels = (width * height) as usize;
            let mut rgb = Vec::with_capacity(pixels * 3);
            let mut alpha = Vec::with_capacity(pixels);
            for chunk in samples.chunks_exact(2) {
                rgb.extend_from_slice(&[chunk[0], chunk[0], chunk[0]]);
                alpha.push(chunk[1]);
            }
            (rgb, Some(alpha))
        }
        other => {
            return Err(CoreError::Signing(format!(
                "unsupported signature image color type: {other:?}"
            )))
        }
    };

    Ok(DecodedImage {
        width,
        height,
        rgb,
        alpha,
    })
}
