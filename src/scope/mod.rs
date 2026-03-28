//! Scope management module
//!
//! Handles scope definition, validation, and in-scope checking for all operations.

mod definition;
mod engine;
mod validation;

pub use definition::{Scope, ScopeDefinition, ScopeItem, ScopeItemType};
pub use engine::ScopeEngine;
pub use validation::ValidationResult;
