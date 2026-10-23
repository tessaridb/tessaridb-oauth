//! A company's logo, kept only as a PNG this server wrote itself. An upload is refused unless it is a PNG; it is
//! decoded under a memory ceiling, its dimensions checked against the header before any pixel is read, expanded to
//! 8 bits per channel, and written again as a new PNG carrying only its pixels. Nothing else from the upload
//! survives: no text, profile or other ancillary chunk, no second frame, and no byte the decoder did not produce.
//! Decoding is CPU work proportional to the image, so async callers run it off the runtime.

use std::io::Cursor;

use png::{BitDepth, Decoder, Encoder, Limits, Transformations};
use tessari_oauth_constants::{LOGO_DECODE_MAX_BYTES, LOGO_MAX_BYTES, LOGO_MAX_SIDE};

use crate::branding::BrandRefusal;

/// The eight bytes every PNG starts with (PNG specification, section 5.2).
const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

/// A PNG this server wrote: made only by [`reencode`], so storage that takes one never holds an upload as sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Png(Vec<u8>);

impl Png {
    /// The PNG's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// `upload` re-encoded as a new PNG of the same pixels.
///
/// # Errors
///
/// [`BrandRefusal::LogoTooLarge`] past the byte ceiling, [`BrandRefusal::LogoNotPng`] without the PNG signature,
/// [`BrandRefusal::LogoTooWide`] past the side ceiling, and [`BrandRefusal::LogoUnreadable`] for anything the
/// decoder refuses.
pub fn reencode(upload: &[u8]) -> Result<Png, BrandRefusal> {
    if upload.len() > LOGO_MAX_BYTES {
        return Err(BrandRefusal::LogoTooLarge);
    }
    if !upload.starts_with(&SIGNATURE) {
        return Err(BrandRefusal::LogoNotPng);
    }
    let mut decoder = Decoder::new_with_limits(
        Cursor::new(upload),
        Limits {
            bytes: LOGO_DECODE_MAX_BYTES,
        },
    );
    decoder.set_transformations(Transformations::normalize_to_color8());
    let mut reader = decoder
        .read_info()
        .map_err(|_| BrandRefusal::LogoUnreadable)?;
    let (width, height) = {
        let header = reader.info();
        (header.width, header.height)
    };
    if width > LOGO_MAX_SIDE || height > LOGO_MAX_SIDE {
        return Err(BrandRefusal::LogoTooWide);
    }
    let size = reader
        .output_buffer_size()
        .ok_or(BrandRefusal::LogoUnreadable)?;
    let mut pixels = vec![0; size];
    let frame = reader
        .next_frame(&mut pixels)
        .map_err(|_| BrandRefusal::LogoUnreadable)?;
    pixels.truncate(frame.buffer_size());
    let (color, depth) = reader.output_color_type();
    if depth != BitDepth::Eight {
        return Err(BrandRefusal::LogoUnreadable);
    }
    let mut written = Vec::new();
    {
        let mut encoder = Encoder::new(&mut written, frame.width, frame.height);
        encoder.set_color(color);
        encoder.set_depth(BitDepth::Eight);
        let mut writer = encoder
            .write_header()
            .map_err(|_| BrandRefusal::LogoUnreadable)?;
        writer
            .write_image_data(&pixels)
            .map_err(|_| BrandRefusal::LogoUnreadable)?;
        writer.finish().map_err(|_| BrandRefusal::LogoUnreadable)?;
    }
    Ok(Png(written))
}

#[cfg(test)]
#[path = "logo_tests.rs"]
mod tests;
