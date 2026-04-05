//! Terminal sizing and text-width helpers for adaptive CLI rendering.

/// Best-effort terminal column detection with fallback.
pub fn terminal_columns(fallback: usize) -> usize {
    crossterm::terminal::size()
        .map(|(cols, _)| cols as usize)
        .ok()
        .unwrap_or(fallback)
}

/// Width available for rendered content after left padding.
pub fn content_width(fallback: usize, left_padding: usize, min_width: usize) -> usize {
    terminal_columns(fallback)
        .saturating_sub(left_padding)
        .max(min_width)
}

/// Returns a horizontal separator line sized to current terminal width.
pub fn separator_line(fallback: usize, left_padding: usize, min_width: usize) -> String {
    "─".repeat(content_width(fallback, left_padding, min_width))
}

/// Truncate string to max visible chars with ellipsis.
pub fn truncate_ellipsis(value: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let mut chars = value.chars();
    let head: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        if max_chars <= 3 {
            ".".repeat(max_chars)
        } else {
            format!(
                "{}...",
                head.chars().take(max_chars - 3).collect::<String>()
            )
        }
    } else {
        head
    }
}

#[cfg(test)]
mod tests {
    use super::truncate_ellipsis;

    #[test]
    fn truncate_ellipsis_behaves_for_short_values() {
        assert_eq!(truncate_ellipsis("abc", 5), "abc");
        assert_eq!(truncate_ellipsis("abcdef", 5), "ab...");
        assert_eq!(truncate_ellipsis("abcdef", 2), "..");
    }
}
