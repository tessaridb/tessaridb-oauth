use png::{BitDepth, ColorType};

use super::reencode;
use crate::branding::BrandRefusal;

/// A PNG of `width` x `height` RGBA pixels, each byte its index modulo 251, with `text` as a tEXt chunk when given.
fn png_of(width: u32, height: u32, text: Option<&str>) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, width, height);
        encoder.set_color(ColorType::Rgba);
        encoder.set_depth(BitDepth::Eight);
        if let Some(text) = text {
            encoder
                .add_text_chunk("Comment".to_owned(), text.to_owned())
                .expect("a text chunk");
        }
        let mut writer = encoder.write_header().expect("a header");
        let count = width
            .checked_mul(height)
            .and_then(|area| area.checked_mul(4))
            .expect("a small test image");
        let pixels: Vec<u8> = (0..count)
            .map(|index| {
                u8::try_from(index.checked_rem(251).expect("not zero")).expect("below 251")
            })
            .collect();
        writer.write_image_data(&pixels).expect("the pixels");
    }
    out
}

/// The pixels of `bytes` decoded as 8-bit RGBA.
fn pixels(bytes: &[u8]) -> (u32, u32, Vec<u8>) {
    let mut reader = png::Decoder::new(std::io::Cursor::new(bytes))
        .read_info()
        .expect("a png");
    let mut buffer = vec![0; reader.output_buffer_size().expect("a size")];
    let frame = reader.next_frame(&mut buffer).expect("a frame");
    buffer.truncate(frame.buffer_size());
    (frame.width, frame.height, buffer)
}

/// The CRC-32 a PNG chunk carries over its type and data (ISO 3309, as the PNG specification defines it).
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn a_png_comes_back_as_a_new_png_with_the_same_pixels_and_none_of_its_text() {
    let sent = png_of(8, 4, Some("<script>alert(1)</script>"));
    assert!(contains(&sent, b"tEXt"));
    let kept = reencode(&sent).expect("re-encoded");
    let kept = kept.as_bytes();
    assert!(
        !contains(kept, b"tEXt"),
        "ancillary text is not carried over"
    );
    assert!(!contains(kept, b"<script>"));
    assert_eq!(pixels(kept), pixels(&sent));
}

#[test]
fn anything_that_is_not_a_png_is_refused_before_it_is_decoded() {
    for sent in [
        &b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>"[..],
        b"<!doctype html><html><body>hi</body></html>",
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00",
        b"GIF89a\x01\x00\x01\x00",
        b"body { background: url(javascript:alert(1)) }",
        b"",
    ] {
        assert_eq!(reencode(sent), Err(BrandRefusal::LogoNotPng), "{sent:?}");
    }
}

#[test]
fn a_damaged_png_is_unreadable() {
    let mut sent = png_of(8, 8, None);
    sent.truncate(sent.len() / 2);
    assert_eq!(reencode(&sent), Err(BrandRefusal::LogoUnreadable));
}

#[test]
fn a_logo_wider_or_taller_than_the_ceiling_is_refused_and_at_the_ceiling_is_kept() {
    assert_eq!(
        reencode(&png_of(513, 1, None)),
        Err(BrandRefusal::LogoTooWide)
    );
    assert_eq!(
        reencode(&png_of(1, 513, None)),
        Err(BrandRefusal::LogoTooWide)
    );
    assert!(reencode(&png_of(512, 2, None)).is_ok());
}

#[test]
fn a_header_claiming_huge_dimensions_is_refused_without_decoding_the_image() {
    let mut sent = png_of(1, 1, None);
    // IHDR starts after the 8-byte signature, a 4-byte length and the 4-byte type; claim 60000 x 60000.
    sent[16..20].copy_from_slice(&60_000_u32.to_be_bytes());
    sent[20..24].copy_from_slice(&60_000_u32.to_be_bytes());
    // The header's CRC covers its type and its 13 data bytes; recompute it so only the dimensions are wrong.
    let crc = crc32(&sent[12..29]);
    sent[29..33].copy_from_slice(&crc.to_be_bytes());
    assert_eq!(reencode(&sent), Err(BrandRefusal::LogoTooWide));
}

#[test]
fn more_bytes_than_a_logo_may_hold_are_refused_unread() {
    let mut sent = png_of(1, 1, None);
    sent.resize(256 * 1024 + 1, 0);
    assert_eq!(reencode(&sent), Err(BrandRefusal::LogoTooLarge));
}
