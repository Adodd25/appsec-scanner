# Contributing to Application Security Scanner

Thank you for your interest in contributing! This document provides guidelines for contributing to the Application Security Scanner skill.

## Ways to Contribute

- 🐛 Report bugs and issues
- 💡 Suggest new features or improvements
- 📝 Improve documentation
- 🔧 Add support for new languages or tools
- 🧪 Add tests
- 🎨 Improve code quality

## Getting Started

1. **Fork the repository**
   ```bash
   git clone https://github.com/yourusername/appsec-scanner-skill.git
   cd appsec-scanner-skill
   ```

2. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow the existing code style
   - Update documentation as needed
   - Test your changes

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "Description of your changes"
   ```

5. **Push and create a pull request**
   ```bash
   git push origin feature/your-feature-name
   ```

## Development Guidelines

### Code Style

**Python:**
- Follow PEP 8 style guidelines
- Use descriptive variable names
- Add docstrings to functions and classes
- Keep functions focused and single-purpose

**JavaScript:**
- Use ES6+ features
- Follow standard JavaScript style guide
- Add JSDoc comments for functions

**Markdown:**
- Use clear headings and structure
- Include code examples where relevant
- Keep lines under 100 characters when possible

### Adding New Security Scanners

To add support for a new language or tool:

1. **Create a scanner script** in `scripts/`
   ```python
   # scripts/scan_newlang.py
   def scan_newlang_code(target_path):
       """Scan code for vulnerabilities"""
       # Implementation
       pass
   ```

2. **Update the orchestrator** in `scripts/run_security_scan.py`
   - Add language detection
   - Integrate the new scanner
   - Update result formatting

3. **Add vulnerability patterns** to `references/vulnerability_patterns.md`
   - Common vulnerabilities for the language
   - Secure coding examples
   - Remediation guidance

4. **Update documentation**
   - README.md
   - SKILL.md
   - INSTALL.md

### Adding New Vulnerability Patterns

1. Add to `references/owasp_top10.md` or `references/vulnerability_patterns.md`
2. Include:
   - Vulnerability description
   - Vulnerable code example
   - Secure code example
   - Explanation of the fix

### Testing

Before submitting a PR:

1. **Test the scanners**
   ```bash
   # Test Python scanner
   python scripts/scan_python.py test_data/
   
   # Test JavaScript scanner
   python scripts/scan_javascript.py code test_data/
   
   # Test full scan
   python scripts/run_security_scan.py test_data/
   ```

2. **Verify the skill packages correctly**
   ```bash
   python /path/to/package_skill.py appsec-scanner
   ```

3. **Check for errors**
   - No Python exceptions
   - Scripts run successfully
   - Output is properly formatted

## Pull Request Process

1. **Update documentation** if you've changed functionality
2. **Add examples** if you've added new features
3. **Describe your changes** clearly in the PR description
4. **Reference any related issues** using GitHub keywords (Fixes #123)
5. **Wait for review** - maintainers will review and provide feedback

### PR Checklist

- [ ] Code follows the project style guidelines
- [ ] Documentation has been updated
- [ ] All tests pass
- [ ] New features have examples
- [ ] Commit messages are clear and descriptive

## Reporting Bugs

When reporting bugs, please include:

1. **Description** - Clear description of the issue
2. **Steps to reproduce** - How to trigger the bug
3. **Expected behavior** - What should happen
4. **Actual behavior** - What actually happens
5. **Environment**:
   - Operating system
   - Python version
   - Node.js version (if applicable)
   - Tool versions (Bandit, ESLint, etc.)
6. **Error messages** - Full error output
7. **Sample code** - Minimal code that reproduces the issue

## Feature Requests

When requesting features, please include:

1. **Use case** - Why is this feature needed?
2. **Proposed solution** - How should it work?
3. **Alternatives** - Other approaches you've considered
4. **Additional context** - Any other relevant information

## Code Review Process

All PRs will be reviewed by maintainers for:

- **Correctness** - Does it work as intended?
- **Code quality** - Is it well-written and maintainable?
- **Documentation** - Is it properly documented?
- **Testing** - Does it include appropriate tests?
- **Style** - Does it follow project conventions?

## Community Guidelines

- Be respectful and constructive
- Help others learn and grow
- Focus on the issue, not the person
- Accept feedback gracefully
- Give credit where credit is due

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

If you have questions about contributing:

1. Check existing issues and discussions
2. Open a new issue with the "question" label
3. Contact the maintainers

## Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes
- Project documentation

Thank you for helping make this project better!
