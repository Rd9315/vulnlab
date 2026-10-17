# VulnLab — Web Exploitation Practice App

A deliberately vulnerable Flask application with 10 classic web
exploitation challenges. **For local/isolated learning use only — never
deploy this on a public server or shared network.**

## Setup

```bash
cd vulnapp
pip install -r requirements.txt
python3 app.py
```

Then open http://127.0.0.1:5000

The database is recreated fresh (`vulnlab.db`) every time you start the app.

## Challenges

| # | Path | Vulnerability | Hint |
|---|------|----------------|------|
| 1 | `/sqli/login` | SQL injection — login bypass | `admin' --` as username |
| 1b | `/sqli/search?q=` | SQL injection — UNION extraction | `' UNION SELECT id, username, password FROM users --` |
| 2 | `/xss/reflected?name=` | Reflected XSS | `<script>alert(1)</script>` |
| 3 | `/xss/stored` | Stored XSS | post `<img src=x onerror=alert(1)>` as a comment |
| 4 | `/cmdi/ping` | OS command injection | host: `127.0.0.1; id` |
| 5 | `/idor/login` → `/idor/doc/<id>` | IDOR | log in as `alice`, then browse `/idor/doc/3` (admin's doc) |
| 6 | `/upload` | Unrestricted file upload | upload any file type, no validation |
| 7 | `/ssrf/fetch` | SSRF | fetch `http://127.0.0.1:5000/notes/view?file=flag.txt` |
| 8 | `/notes/view?file=` | Path traversal / LFI | `?file=../app.py` |
| 9 | `/auth/remember` | Broken auth — trusted client cookie | edit the `role` cookie to `admin` in devtools |
| 10 | `/deser/profile` | Insecure deserialization (pickle) | craft a pickle payload with `__reduce__` |

Each vulnerable line in `app.py` is commented `# VULNERABLE: ...` explaining
exactly what's wrong, so you can compare your exploit against the root
cause, and then practice fixing it (parameterized queries, output escaping,
`subprocess` without `shell=True`, ownership checks, allow-lists, etc.).

## Notes

- `app.secret_key` is hardcoded on purpose (weak session secret).
- Flask debug mode is on — the Werkzeug debugger PIN is shown in the
  console (another classic misconfiguration to be aware of, not just an
  accident).
- There's nothing here checking for real user auth beyond what's needed
  to demonstrate each bug — don't reuse any of this code in a real app.
