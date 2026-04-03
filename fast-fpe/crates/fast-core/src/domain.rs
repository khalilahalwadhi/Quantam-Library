/// Domain types defining the alphabet for format-preserving encryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Domain {
    /// Decimal digits (0-9), radix = 10.
    Decimal,
    /// Lowercase letters (a-z), radix = 26.
    LowerAlpha,
    /// Digits + lowercase letters (0-9, a-z), radix = 36.
    Alphanumeric,
    /// Digits + lowercase + uppercase (0-9, a-z, A-Z), radix = 62.
    AlphanumericCase,
    /// Custom radix (must be >= 4).
    Custom {
        /// The alphabet size.
        radix: u32,
    },
}

impl Domain {
    /// Returns the radix (alphabet size) for this domain.
    #[must_use]
    pub fn radix(&self) -> u32 {
        match self {
            Self::Decimal => 10,
            Self::LowerAlpha => 26,
            Self::Alphanumeric => 36,
            Self::AlphanumericCase => 62,
            Self::Custom { radix } => *radix,
        }
    }

    /// Returns the character mapping for this domain.
    #[must_use]
    pub fn mapping(&self) -> Box<dyn CharMapping> {
        match self {
            Self::Decimal => Box::new(DecimalMapping),
            Self::LowerAlpha => Box::new(LowerAlphaMapping),
            Self::Alphanumeric => Box::new(AlphanumericMapping),
            Self::AlphanumericCase => Box::new(AlphanumericCaseMapping),
            Self::Custom { radix } => Box::new(CustomMapping { radix: *radix }),
        }
    }
}

/// Trait for bidirectional character-to-digit mapping.
///
/// The mapping must be bijective (one-to-one and onto) between
/// the character set and `{0, 1, ..., radix-1}`.
pub trait CharMapping {
    /// Convert a character to its digit value.
    fn char_to_digit(&self, c: char) -> Option<u32>;

    /// Convert a digit value to its character representation.
    fn digit_to_char(&self, d: u32) -> Option<char>;

    /// The radix (alphabet size).
    fn radix(&self) -> u32;
}

/// Decimal mapping: '0'→0, '1'→1, ..., '9'→9.
pub struct DecimalMapping;

impl CharMapping for DecimalMapping {
    fn char_to_digit(&self, c: char) -> Option<u32> {
        c.to_digit(10)
    }

    fn digit_to_char(&self, d: u32) -> Option<char> {
        if d < 10 {
            char::from_digit(d, 10)
        } else {
            None
        }
    }

    fn radix(&self) -> u32 {
        10
    }
}

/// Lowercase alpha mapping: 'a'→0, 'b'→1, ..., 'z'→25.
pub struct LowerAlphaMapping;

impl CharMapping for LowerAlphaMapping {
    fn char_to_digit(&self, c: char) -> Option<u32> {
        if c.is_ascii_lowercase() {
            Some(u32::from(c as u8 - b'a'))
        } else {
            None
        }
    }

    fn digit_to_char(&self, d: u32) -> Option<char> {
        if d < 26 {
            Some((b'a' + d as u8) as char)
        } else {
            None
        }
    }

    fn radix(&self) -> u32 {
        26
    }
}

/// Alphanumeric mapping: '0'→0, ..., '9'→9, 'a'→10, ..., 'z'→35.
pub struct AlphanumericMapping;

impl CharMapping for AlphanumericMapping {
    fn char_to_digit(&self, c: char) -> Option<u32> {
        match c {
            '0'..='9' => Some(u32::from(c as u8 - b'0')),
            'a'..='z' => Some(u32::from(c as u8 - b'a') + 10),
            _ => None,
        }
    }

    fn digit_to_char(&self, d: u32) -> Option<char> {
        match d {
            0..=9 => Some((b'0' + d as u8) as char),
            10..=35 => Some((b'a' + (d - 10) as u8) as char),
            _ => None,
        }
    }

    fn radix(&self) -> u32 {
        36
    }
}

/// Case-sensitive alphanumeric: '0'→0, ..., '9'→9, 'a'→10, ..., 'z'→35, 'A'→36, ..., 'Z'→61.
pub struct AlphanumericCaseMapping;

impl CharMapping for AlphanumericCaseMapping {
    fn char_to_digit(&self, c: char) -> Option<u32> {
        match c {
            '0'..='9' => Some(u32::from(c as u8 - b'0')),
            'a'..='z' => Some(u32::from(c as u8 - b'a') + 10),
            'A'..='Z' => Some(u32::from(c as u8 - b'A') + 36),
            _ => None,
        }
    }

    fn digit_to_char(&self, d: u32) -> Option<char> {
        match d {
            0..=9 => Some((b'0' + d as u8) as char),
            10..=35 => Some((b'a' + (d - 10) as u8) as char),
            36..=61 => Some((b'A' + (d - 36) as u8) as char),
            _ => None,
        }
    }

    fn radix(&self) -> u32 {
        62
    }
}

/// Custom mapping for arbitrary radixes. Uses digits then lowercase letters.
/// For radix > 36, uses digits + lowercase + uppercase.
/// For radix > 62, only digit values are supported (no char mapping).
pub struct CustomMapping {
    radix: u32,
}

impl CharMapping for CustomMapping {
    fn char_to_digit(&self, c: char) -> Option<u32> {
        let d = match c {
            '0'..='9' => u32::from(c as u8 - b'0'),
            'a'..='z' => u32::from(c as u8 - b'a') + 10,
            'A'..='Z' => u32::from(c as u8 - b'A') + 36,
            _ => return None,
        };
        if d < self.radix {
            Some(d)
        } else {
            None
        }
    }

    fn digit_to_char(&self, d: u32) -> Option<char> {
        if d >= self.radix {
            return None;
        }
        match d {
            0..=9 => Some((b'0' + d as u8) as char),
            10..=35 => Some((b'a' + (d - 10) as u8) as char),
            36..=61 => Some((b'A' + (d - 36) as u8) as char),
            _ => None,
        }
    }

    fn radix(&self) -> u32 {
        self.radix
    }
}
