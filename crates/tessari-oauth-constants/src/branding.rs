//! What a company's brand may hold on the public pages.

/// Characters a company's display name may hold, after trimming.
pub const BRAND_NAME_MAX_CHARS: usize = 64;

/// Bytes a support or privacy link may hold.
pub const BRAND_LINK_MAX_LEN: usize = 2048;

/// The contrast white button text needs on the accent colour: WCAG 2 success criterion 1.4.3, normal text.
pub const ACCENT_MIN_CONTRAST: f64 = 4.5;

/// Bytes an uploaded logo may hold before it is decoded.
pub const LOGO_MAX_BYTES: usize = 256 * 1024;

/// Pixels a logo may measure on its longer side.
pub const LOGO_MAX_SIDE: u32 = 512;

/// Bytes the decoder may allocate for one logo: 512 x 512 RGBA at 16 bits per channel, with room for its rows.
pub const LOGO_DECODE_MAX_BYTES: usize = 4 * 1024 * 1024;
