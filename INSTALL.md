# Installation Guide - Enhanced Edition

## Quick Setup

### 1. Install Required Tools

**Python Security Tools:**
```bash
pip install bandit pyyaml --break-system-packages

# Or use requirements.txt
pip install -r requirements.txt --break-system-packages
```

**JavaScript/Node.js Security Tools:**
```bash
# Install globally
npm install -g eslint eslint-plugin-security

# Or in your project
npm install --save-dev eslint eslint-plugin-security
```

### 2. Install the Skill (for Claude)

**Option A: Upload to Claude**
1. Download `appsec-scanner.skill` file
2. Go to Settings → Skills in Claude
3. Click "Add Skill"
4. Upload the `.skill` file
5. Enable the skill

**Option B: Use Directly (without Claude skill system)**
1. Clone or download this repository
2. Install Python dependencies: `pip install -r requirements.txt --break-system-packages`
3. Use the scripts directly:
   ```bash
   python scripts/run_security_scan.py /path/to/your/project
   ```

### 3. Verify Installation

Test the installation:

```bash
# Test main scanner (with all features)
python scripts/run_security_scan.py .

# Test Python scanner
python scripts/scan_python.py .

# Test secret scanner
python scripts/scan_secrets.py .

# Test JavaScript scanner (if you have JS files)
python scripts/scan_javascript.py code .

# Test dependency scanner (if you have package.json)
python scripts/scan_javascript.py npm .
```

## System Requirements

- **Python**: 3.7 or higher
- **Node.js**: 14 or higher (for JavaScript/Node.js scanning)
- **Operating System**: Linux, macOS, or Windows

## Troubleshooting Installation

### Python Tools

If `pip install` fails:
```bash
# Try with --user flag
pip install --user bandit

# Or use pip3
pip3 install bandit --break-system-packages
```

### Node.js Tools

If global npm install fails:
```bash
# Use npx to run without global install
npx eslint --version

# Or install locally in your project
cd /path/to/your/project
npm install --save-dev eslint eslint-plugin-security
```

### Permission Issues

If you get permission errors:
```bash
# Linux/macOS - use sudo (not recommended for pip)
sudo npm install -g eslint eslint-plugin-security

# Or install in user directory
npm install -g --prefix ~/.local eslint eslint-plugin-security
```

## Optional Tools

For enhanced scanning capabilities:

```bash
# Python additional tools
pip install safety pip-audit --break-system-packages

# JavaScript additional tools
npm install -g retire snyk
```

## Verifying Tool Installation

```bash
# Check Bandit
bandit --version

# Check ESLint
eslint --version
# or
npx eslint --version

# Check npm (should be installed with Node.js)
npm --version
```

## Next Steps

After installation:
1. Read the [README.md](README.md) for usage instructions
2. Review [SKILL.md](SKILL.md) for comprehensive documentation
3. Run your first scan: `python scripts/run_security_scan.py .`
4. Check the [references/](references/) folder for security guidance

## Support

If you encounter issues:
1. Check the troubleshooting section in README.md
2. Verify all prerequisites are installed
3. Check file permissions on scripts
4. Open an issue on GitHub with:
   - Your operating system
   - Python version (`python --version`)
   - Node.js version (`node --version`)
   - Error message
