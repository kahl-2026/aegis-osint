# Contributing to AegisOSINT

Thank you for your interest in contributing to AegisOSINT! This document provides guidelines for contributions.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Prioritize security and user safety
- Follow responsible disclosure practices

## Getting Started

1. Fork the repository
2. Clone your fork
3. Create a feature branch
4. Make your changes
5. Submit a pull request

## Development Setup

```bash
# Clone
git clone https://github.com/yourusername/aegis-osint.git
cd aegis-osint

# Install dependencies
./setup.sh

# Build
make build

# Run tests
make test
```

## Pull Request Process

### Before Submitting

1. **Test your changes**: Run the full test suite
   ```bash
   make test
   make lint
   ```

2. **Check coverage**: Ensure coverage thresholds are met
   ```bash
   make coverage
   ```

3. **Update documentation**: If adding features, update relevant docs

4. **Follow style guidelines**: Run clippy and rustfmt
   ```bash
   cargo clippy
   cargo fmt
   ```

### PR Requirements

- [ ] Tests pass
- [ ] Coverage maintained (>= 85%)
- [ ] No clippy warnings
- [ ] Code formatted with rustfmt
- [ ] Documentation updated
- [ ] Commit messages are clear and descriptive

### Commit Messages

Follow conventional commits:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions/changes
- `refactor`: Code refactoring
- `security`: Security improvements
- `perf`: Performance improvements

Examples:
```
feat(offensive): add subdomain takeover detection
fix(scope): handle wildcard edge cases
docs(readme): update installation instructions
security(policy): strengthen rate limiting
```

## Architecture Guidelines

### Module Structure

- Keep modules focused and single-purpose
- Use clear, descriptive names
- Document public APIs
- Write unit tests for all public functions

### Safety Requirements

**Non-negotiable rules:**

1. **Scope validation**: Every network operation MUST validate scope
2. **No exploitation**: No payload generation, no exploit code
3. **Rate limiting**: Respect rate limits in all modules
4. **Audit logging**: Log significant operations
5. **Error handling**: Never panic in library code

### Code Style

```rust
// Good: Clear, documented, handles errors
/// Checks if a target is within authorized scope.
///
/// # Errors
/// Returns error if target validation fails.
pub fn is_in_scope(&self, target: &str) -> Result<bool, ScopeError> {
    // Validate input
    let target = target.trim().to_lowercase();
    if target.is_empty() {
        return Err(ScopeError::EmptyTarget);
    }
    
    // Check against scope items
    self.check_scope_items(&target)
}
```

### Testing Guidelines

1. **Unit tests**: Test individual functions
2. **Integration tests**: Test module interactions
3. **Policy tests**: Verify safety guardrails work
4. **Regression tests**: Prevent fixed bugs from recurring

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_validation_blocks_out_of_scope() {
        let scope = create_test_scope();
        assert!(!scope.is_in_scope("out-of-scope.com"));
    }

    #[test]
    fn test_scope_validation_allows_in_scope() {
        let scope = create_test_scope();
        assert!(scope.is_in_scope("target.example.com"));
    }
}
```

## Security Contributions

Special guidelines for security-related changes:

1. **Do not add exploitation capabilities**
2. **Strengthen safety guardrails, not weaken them**
3. **Consider abuse potential of new features**
4. **Add tests proving safety mechanisms work**

## Feature Requests

Open an issue with:
- Clear description of the feature
- Use case / motivation
- Potential security implications
- Willingness to implement

## Bug Reports

Include:
- AegisOSINT version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs (sanitized)

## Questions?

- Open a GitHub Discussion
- Check existing issues

Thank you for helping make AegisOSINT better!
