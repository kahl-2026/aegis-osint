//! Scope validation types

use serde::{Deserialize, Serialize};

/// Result of scope validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the scope is valid
    pub is_valid: bool,

    /// Validation errors (blocking)
    pub errors: Vec<String>,

    /// Validation warnings (non-blocking)
    pub warnings: Vec<String>,
}

impl ValidationResult {
    /// Create a valid result
    pub fn valid() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Create a valid result with warnings
    pub fn valid_with_warnings(warnings: Vec<String>) -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings,
        }
    }

    /// Create an invalid result
    pub fn invalid(errors: Vec<String>) -> Self {
        Self {
            is_valid: false,
            errors,
            warnings: Vec::new(),
        }
    }

    /// Add an error
    pub fn add_error(&mut self, error: String) {
        self.errors.push(error);
        self.is_valid = false;
    }

    /// Add a warning
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    /// Merge another validation result
    pub fn merge(&mut self, other: ValidationResult) {
        if !other.is_valid {
            self.is_valid = false;
        }
        self.errors.extend(other.errors);
        self.warnings.extend(other.warnings);
    }
}

impl Default for ValidationResult {
    fn default() -> Self {
        Self::valid()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_result() {
        let result = ValidationResult::valid();
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_invalid_result() {
        let result = ValidationResult::invalid(vec!["Error 1".to_string()]);
        assert!(!result.is_valid);
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn test_merge() {
        let mut result1 = ValidationResult::valid();
        result1.add_warning("Warning 1".to_string());

        let mut result2 = ValidationResult::valid();
        result2.add_error("Error 1".to_string());

        result1.merge(result2);
        assert!(!result1.is_valid);
        assert_eq!(result1.errors.len(), 1);
        assert_eq!(result1.warnings.len(), 1);
    }
}
