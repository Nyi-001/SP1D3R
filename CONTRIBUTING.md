# Contributing to Automated Penetration Testing Tool

Thank you for your interest in contributing to this project! This document provides guidelines for contributing.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in Issues
2. If not, create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, etc.)

### Suggesting Enhancements

1. Check if the enhancement has been suggested
2. Create a new issue with:
   - Clear description of the enhancement
   - Use cases and benefits
   - Potential implementation approach

### Pull Requests

1. Fork the repository
2. Create a new branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Add or update tests as needed
5. Update documentation
6. Commit with clear messages
7. Push to your fork
8. Create a Pull Request

#### PR Guidelines

- Follow existing code style
- Add docstrings to new functions/classes
- Include tests for new features
- Update README.md if needed
- Keep PRs focused on a single feature/fix

## Development Setup

```bash
# Clone the repository
git clone https://github.com/pangerlkr/automated-pentest-tool.git
cd automated-pentest-tool

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run tests (when available)
pytest tests/
```

## Code Style

- Follow PEP 8 guidelines
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and small
- Use type hints where appropriate

## Testing

- Write tests for new features
- Ensure all tests pass before submitting PR
- Test on multiple Python versions if possible

## Security

- Never commit sensitive data (API keys, passwords, etc.)
- Use environment variables for secrets
- Test security features thoroughly
- Report security issues privately

## Module Development

When adding a new scanning module:

1. Create module in appropriate directory (`core/` or `modules/`)
2. Follow existing module structure
3. Include proper error handling
4. Add logging throughout
5. Return results in standard format
6. Update scanner.py to integrate module
7. Add configuration options to config.yaml
8. Document in README.md

## Questions?

Feel free to:
- Open an issue for discussion
- Reach out to maintainers
- Check existing documentation

Thank you for contributing! 🎉
