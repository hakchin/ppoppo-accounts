/// Validates a ppnum (Ppoppo Number) format.
///
/// A valid ppnum is:
/// - Exactly 11 digits
/// - Starts with "777" prefix
/// - All characters are ASCII digits
#[must_use]
pub fn is_valid_ppnum(s: &str) -> bool {
    s.len() == 11 && s.starts_with("777") && s.chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ppnum() {
        assert!(is_valid_ppnum("77712345678"));
        assert!(is_valid_ppnum("77700000000"));
        assert!(is_valid_ppnum("77799999999"));
    }

    #[test]
    fn test_invalid_ppnum_wrong_prefix() {
        assert!(!is_valid_ppnum("12345678901"));
        assert!(!is_valid_ppnum("77812345678"));
    }

    #[test]
    fn test_invalid_ppnum_wrong_length() {
        assert!(!is_valid_ppnum("7771234567")); // 10 chars
        assert!(!is_valid_ppnum("777123456789")); // 12 chars
        assert!(!is_valid_ppnum(""));
    }

    #[test]
    fn test_invalid_ppnum_non_digits() {
        assert!(!is_valid_ppnum("777abcdefgh"));
        assert!(!is_valid_ppnum("7771234567a"));
    }
}
