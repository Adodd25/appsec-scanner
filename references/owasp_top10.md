# OWASP Top 10 Web Application Security Risks (2021)

This reference provides guidance on the OWASP Top 10 security risks and how to identify and fix them in Python, JavaScript, and Node.js applications.

## A01:2021 - Broken Access Control

**Description:** Restrictions on what authenticated users can do are not properly enforced. Attackers can exploit these flaws to access unauthorized functionality and/or data.

**Common Vulnerabilities:**
- Missing access control checks
- Bypassing access control by modifying URL, HTML page, or API request
- Insecure Direct Object References (IDOR)
- Privilege escalation

**Detection Patterns:**
```python
# Python - Vulnerable
@app.route('/user/<user_id>')
def get_user(user_id):
    # No check if current user can access this user_id
    return User.query.get(user_id)

# Python - Secure
@app.route('/user/<user_id>')
@login_required
def get_user(user_id):
    if current_user.id != user_id and not current_user.is_admin:
        abort(403)
    return User.query.get(user_id)
```

```javascript
// JavaScript/Node - Vulnerable
app.get('/api/user/:id', (req, res) => {
  // No authorization check
  db.getUser(req.params.id).then(user => res.json(user));
});

// JavaScript/Node - Secure
app.get('/api/user/:id', authenticateToken, (req, res) => {
  if (req.user.id !== req.params.id && !req.user.isAdmin) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  db.getUser(req.params.id).then(user => res.json(user));
});
```

## A02:2021 - Cryptographic Failures

**Description:** Failures related to cryptography which often leads to sensitive data exposure.

**Common Vulnerabilities:**
- Transmitting data in clear text
- Using weak cryptographic algorithms
- Improper key management
- Not using encryption for sensitive data

**Detection Patterns:**
```python
# Python - Vulnerable
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()  # MD5 is broken

# Python - Secure
from werkzeug.security import generate_password_hash
password_hash = generate_password_hash(password)  # Uses bcrypt/scrypt
```

```javascript
// JavaScript/Node - Vulnerable
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');  // MD5 is broken

// JavaScript/Node - Secure
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 10);  // Proper password hashing
```

## A03:2021 - Injection

**Description:** Hostile data is used as part of a command or query, tricking the interpreter into executing unintended commands or accessing data without proper authorization.

**Common Types:**
- SQL Injection
- NoSQL Injection
- OS Command Injection
- LDAP Injection

**Detection Patterns:**
```python
# Python - SQL Injection Vulnerable
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)

# Python - Secure (Parameterized)
query = "SELECT * FROM users WHERE username = %s"
cursor.execute(query, (username,))

# Python - Command Injection Vulnerable
os.system(f"ping {user_input}")

# Python - Secure
subprocess.run(["ping", "-c", "1", user_input], check=True)
```

```javascript
// JavaScript/Node - SQL Injection Vulnerable
const query = `SELECT * FROM users WHERE username = '${username}'`;
connection.query(query, callback);

// JavaScript/Node - Secure (Parameterized)
const query = 'SELECT * FROM users WHERE username = ?';
connection.query(query, [username], callback);

// JavaScript/Node - Command Injection Vulnerable
exec(`ls ${userInput}`, callback);

// JavaScript/Node - Secure
execFile('ls', [userInput], callback);
```

## A04:2021 - Insecure Design

**Description:** Risks related to design and architectural flaws, calling for more use of threat modeling, secure design patterns, and reference architectures.

**Common Issues:**
- Missing or ineffective security controls
- Not implementing defense in depth
- Lack of security requirements in design phase
- Not considering threat modeling

**Prevention:**
- Use threat modeling for critical authentication, access control, and business logic
- Integrate security and privacy-related user stories into user stories
- Write unit and integration tests to validate that all critical flows are resistant to the threat model
- Use security design patterns and reference architectures

## A05:2021 - Security Misconfiguration

**Description:** Missing appropriate security hardening across any part of the application stack or improperly configured permissions.

**Common Issues:**
- Unnecessary features enabled
- Default accounts with default passwords
- Overly verbose error messages revealing sensitive information
- Missing security headers
- Outdated software

**Detection Patterns:**
```python
# Python - Vulnerable (Debug mode in production)
app = Flask(__name__)
app.debug = True  # Never do this in production!

# Python - Secure
app = Flask(__name__)
app.debug = os.environ.get('FLASK_ENV') == 'development'
```

```javascript
// JavaScript/Node - Vulnerable
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.stack });  // Exposes stack trace
});

// JavaScript/Node - Secure
app.use((err, req, res, next) => {
  console.error(err.stack);  // Log internally
  res.status(500).json({ error: 'Internal server error' });  // Generic message
});
```

## A06:2021 - Vulnerable and Outdated Components

**Description:** Using components with known vulnerabilities, unsupported or out-of-date software.

**Common Issues:**
- Not knowing versions of components
- Using vulnerable, unsupported, or out-of-date software
- Not regularly scanning for vulnerabilities
- Not fixing or upgrading underlying platform, frameworks in a timely fashion

**Prevention:**
- Remove unused dependencies
- Continuously inventory component versions (using tools like npm audit, pip-audit)
- Only obtain components from official sources over secure links
- Monitor for unmaintained libraries and components

## A07:2021 - Identification and Authentication Failures

**Description:** Confirmation of user's identity, authentication, and session management is critical to protect against authentication-related attacks.

**Common Issues:**
- Permits automated attacks like credential stuffing
- Permits brute force or other automated attacks
- Permits default, weak, or well-known passwords
- Uses weak or ineffective credential recovery processes
- Missing or ineffective multi-factor authentication
- Exposes session identifiers in the URL
- Does not properly invalidate session IDs

**Detection Patterns:**
```python
# Python - Vulnerable (No rate limiting)
@app.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(username=request.form['username']).first()
    if user and user.check_password(request.form['password']):
        login_user(user)
        return redirect('/')
    return 'Invalid credentials'

# Python - Secure (With rate limiting)
from flask_limiter import Limiter

limiter = Limiter(app, key_func=lambda: request.remote_addr)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    user = User.query.filter_by(username=request.form['username']).first()
    if user and user.check_password(request.form['password']):
        login_user(user)
        return redirect('/')
    return 'Invalid credentials'
```

```javascript
// JavaScript/Node - Vulnerable (Session in URL)
app.get('/dashboard/:sessionId', (req, res) => {
  const session = sessions[req.params.sessionId];
  if (session) {
    res.render('dashboard', { user: session.user });
  }
});

// JavaScript/Node - Secure (Session in httpOnly cookie)
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { 
    httpOnly: true,
    secure: true,  // HTTPS only
    sameSite: 'strict'
  }
}));
```

## A08:2021 - Software and Data Integrity Failures

**Description:** Code and infrastructure that does not protect against integrity violations, such as using plugins, libraries, or modules from untrusted sources.

**Common Issues:**
- Using unsigned or unverified software updates
- Insecure CI/CD pipelines
- Auto-update without sufficient integrity verification
- Insecure deserialization

**Detection Patterns:**
```python
# Python - Vulnerable (Unsafe deserialization)
import pickle
user_data = pickle.loads(request.data)  # Can execute arbitrary code!

# Python - Secure (Use JSON)
import json
user_data = json.loads(request.data)
```

```javascript
// JavaScript/Node - Vulnerable
const obj = eval(userInput);  // Never use eval on user input!

// JavaScript/Node - Secure
const obj = JSON.parse(userInput);
```

## A09:2021 - Security Logging and Monitoring Failures

**Description:** Insufficient logging and monitoring coupled with missing or ineffective integration with incident response allows attackers to further attack systems.

**Common Issues:**
- Login failures not logged
- Warnings and errors not logged
- Logs not monitored for suspicious activity
- Logs only stored locally
- No alerting thresholds or response escalation processes

**Detection Patterns:**
```python
# Python - Vulnerable (No logging)
@app.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(username=request.form['username']).first()
    if user and user.check_password(request.form['password']):
        return 'Success'
    return 'Failed'

# Python - Secure (With logging)
import logging

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(request.form['password']):
        logging.info(f"Successful login for user: {username}")
        return 'Success'
    logging.warning(f"Failed login attempt for user: {username} from IP: {request.remote_addr}")
    return 'Failed'
```

## A10:2021 - Server-Side Request Forgery (SSRF)

**Description:** SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL, allowing an attacker to coerce the application to send requests to unexpected destinations.

**Common Scenarios:**
- Fetching URLs supplied by users
- Importing data from URLs
- Webhook implementations

**Detection Patterns:**
```python
# Python - Vulnerable
import requests

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    response = requests.get(url)  # Can access internal resources!
    return response.text

# Python - Secure
import requests
from urllib.parse import urlparse

ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    parsed = urlparse(url)
    
    # Validate domain
    if parsed.netloc not in ALLOWED_DOMAINS:
        return 'Invalid URL', 400
    
    # Validate scheme
    if parsed.scheme not in ['http', 'https']:
        return 'Invalid URL scheme', 400
    
    response = requests.get(url, timeout=5)
    return response.text
```

```javascript
// JavaScript/Node - Vulnerable
app.get('/fetch', (req, res) => {
  const url = req.query.url;
  fetch(url).then(response => response.text()).then(data => res.send(data));
});

// JavaScript/Node - Secure
const ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com'];

app.get('/fetch', async (req, res) => {
  const url = new URL(req.query.url);
  
  // Validate domain
  if (!ALLOWED_DOMAINS.includes(url.hostname)) {
    return res.status(400).send('Invalid domain');
  }
  
  // Validate protocol
  if (!['http:', 'https:'].includes(url.protocol)) {
    return res.status(400).send('Invalid protocol');
  }
  
  const response = await fetch(url.href);
  const data = await response.text();
  res.send(data);
});
```

## Quick Reference: Scanning Tools

**Python:**
- `bandit` - Security linter for Python code
- `safety` - Check Python dependencies for known vulnerabilities
- `pip-audit` - Audit Python packages for known CVEs

**JavaScript/Node.js:**
- `npm audit` - Check npm dependencies for vulnerabilities
- `eslint-plugin-security` - ESLint plugin for security issues
- `retire.js` - Scanner detecting use of vulnerable JavaScript libraries
- `snyk` - Find and fix vulnerabilities in open source dependencies

**General:**
- `OWASP ZAP` - Web application security scanner
- `SonarQube` - Continuous code quality and security inspection
- `Semgrep` - Lightweight static analysis for multiple languages
