//! A company's brand on its public pages: a display name, an accent colour, support and privacy links, and a logo
//! (see [`crate::logo`]). Each is a typed value read once here, so nothing a company supplies reaches a page except
//! as one of these shapes: a name is text with no control or direction characters, a colour is six hex digits white
//! text can be read on, and a link is an https address with a host and no credentials.

use tessari_oauth_constants::{ACCENT_MIN_CONTRAST, BRAND_LINK_MAX_LEN, BRAND_NAME_MAX_CHARS};
use unicode_normalization::UnicodeNormalization;
use url::Url;

/// Why a brand value was refused, each with the code an API answers with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrandRefusal {
    /// A name empty after trimming, longer than the ceiling, or holding a control or direction character.
    NameInvalid,
    /// A colour that is not `#` and six hex digits.
    AccentInvalid,
    /// A colour white text cannot be read on.
    AccentLowContrast,
    /// A link that is not an https address with a host and no credentials, or is too long.
    LinkInvalid,
    /// A logo holding more bytes than one may.
    LogoTooLarge,
    /// A logo that is not a PNG.
    LogoNotPng,
    /// A PNG that does not decode.
    LogoUnreadable,
    /// A logo wider or taller than one may be.
    LogoTooWide,
}

impl BrandRefusal {
    /// The stable code naming this refusal.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NameInvalid => "brand_name_invalid",
            Self::AccentInvalid => "accent_invalid",
            Self::AccentLowContrast => "accent_low_contrast",
            Self::LinkInvalid => "link_invalid",
            Self::LogoTooLarge => "logo_too_large",
            Self::LogoNotPng => "logo_not_png",
            Self::LogoUnreadable => "logo_unreadable",
            Self::LogoTooWide => "logo_too_wide",
        }
    }
}

/// A company's display name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrandName(String);

/// Characters that reorder text around them, which on a sign-in page could make one name read as another.
fn redirects_text(character: char) -> bool {
    matches!(character, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

impl BrandName {
    /// `raw` normalized (NFC) and trimmed, refused when empty, too long, or holding a control or direction character.
    ///
    /// # Errors
    ///
    /// [`BrandRefusal::NameInvalid`].
    pub fn parse(raw: impl AsRef<str>) -> Result<Self, BrandRefusal> {
        let normalized: String = raw.as_ref().nfc().collect();
        let name = normalized.trim();
        let count = name.chars().count();
        if count == 0
            || count > BRAND_NAME_MAX_CHARS
            || name
                .chars()
                .any(|character| character.is_control() || redirects_text(character))
        {
            return Err(BrandRefusal::NameInvalid);
        }
        Ok(Self(name.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A company's accent colour, `#` and six lowercase hex digits, on which white text meets the contrast floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accent(String);

/// The contrast of white text on the colour `red`, `green`, `blue` (WCAG 2 relative luminance, sRGB).
fn contrast_with_white(red: u8, green: u8, blue: u8) -> f64 {
    let linear = |channel: u8| {
        let value = f64::from(channel) / 255.0;
        if value <= 0.040_45 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    };
    let luminance = 0.2126 * linear(red) + 0.7152 * linear(green) + 0.0722 * linear(blue);
    1.05 / (luminance + 0.05)
}

impl Accent {
    /// `raw` as a colour, refused when it is not `#rrggbb` or white text cannot be read on it.
    ///
    /// # Errors
    ///
    /// [`BrandRefusal::AccentInvalid`] for the shape, [`BrandRefusal::AccentLowContrast`] for the contrast.
    pub fn parse(raw: &str) -> Result<Self, BrandRefusal> {
        let digits = raw.strip_prefix('#').ok_or(BrandRefusal::AccentInvalid)?;
        if digits.len() != 6 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(BrandRefusal::AccentInvalid);
        }
        let channel = |pair: std::ops::Range<usize>| {
            digits
                .get(pair)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or(BrandRefusal::AccentInvalid)
        };
        if contrast_with_white(channel(0..2)?, channel(2..4)?, channel(4..6)?) < ACCENT_MIN_CONTRAST
        {
            return Err(BrandRefusal::AccentLowContrast);
        }
        Ok(Self(format!("#{}", digits.to_ascii_lowercase())))
    }

    /// The colour as `#rrggbb`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A support or privacy link: an https address with a host and no credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrandLink(String);

impl BrandLink {
    /// `raw` as a link, in its serialized form.
    ///
    /// # Errors
    ///
    /// [`BrandRefusal::LinkInvalid`].
    pub fn parse(raw: &str) -> Result<Self, BrandRefusal> {
        if raw.len() > BRAND_LINK_MAX_LEN {
            return Err(BrandRefusal::LinkInvalid);
        }
        let link = Url::parse(raw).map_err(|_| BrandRefusal::LinkInvalid)?;
        if link.scheme() != "https"
            || link.host_str().is_none_or(str::is_empty)
            || !link.username().is_empty()
            || link.password().is_some()
            || link.as_str().len() > BRAND_LINK_MAX_LEN
        {
            return Err(BrandRefusal::LinkInvalid);
        }
        Ok(Self(link.as_str().to_owned()))
    }

    /// The link.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
#[path = "branding_tests.rs"]
mod tests;
