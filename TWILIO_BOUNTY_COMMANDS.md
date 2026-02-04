# Twilio Bug Bounty - PHANTOM AI Commands

**Username:** bugsbunny
**Platform:** HackerOne
**Program:** Twilio
**Rate:** 5 req/sec (safe for enterprise targets)

---

## Pre-Flight Safety Check

```bash
# Run this FIRST to verify all safety mechanisms are working
python tests/test_safety_verification.py
```

Expected output: `ALL SAFETY CHECKS PASSED`

---

## Priority 1: Primary APIs (High Value Targets)

### 1.1 Twilio Main API
```bash
phantom bounty https://api.twilio.com --platform hackerone -u bugsbunny --rate 5
```

### 1.2 SendGrid API
```bash
phantom bounty https://api.sendgrid.com --platform hackerone -u bugsbunny --rate 5
```

### 1.3 Segment API
```bash
phantom bounty https://api.segment.io --platform hackerone -u bugsbunny --rate 5
```

### 1.4 Twilio Verify API
```bash
phantom bounty https://verify.twilio.com --platform hackerone -u bugsbunny --rate 5
```

### 1.5 Twilio Authy API
```bash
phantom bounty https://api.authy.com --platform hackerone -u bugsbunny --rate 5
```

---

## Priority 2: Web Applications (Auth/Console)

### 2.1 Twilio Console (Login)
```bash
phantom bounty "https://www.twilio.com/login" --platform hackerone -u bugsbunny --rate 5
```

### 2.2 SendGrid App
```bash
phantom bounty https://app.sendgrid.com --platform hackerone -u bugsbunny --rate 5
```

### 2.3 Segment App
```bash
phantom bounty https://app.segment.com --platform hackerone -u bugsbunny --rate 5
```

### 2.4 SendGrid Signup
```bash
phantom bounty https://signup.sendgrid.com --platform hackerone -u bugsbunny --rate 5
```

### 2.5 SendGrid Marketing
```bash
phantom bounty https://mc.sendgrid.com --platform hackerone -u bugsbunny --rate 5
```

---

## Priority 3: Main Domains

### 3.1 SendGrid Main
```bash
phantom bounty https://sendgrid.com --platform hackerone -u bugsbunny --rate 5
```

### 3.2 Twilio Blog
```bash
phantom bounty https://www.twilio.com/blog --platform hackerone -u bugsbunny --rate 5
```

### 3.3 Twilio Help
```bash
phantom bounty https://help.twilio.com --platform hackerone -u bugsbunny --rate 5
```

---

## Priority 4: Infrastructure & Other Services

### 4.1 Twilio WebSocket
```bash
phantom bounty https://tsock.us1.twilio.com --platform hackerone -u bugsbunny --rate 5
```

### 4.2 SendGrid SMTP (Limited Testing)
```bash
# SMTP requires special handling - use recon only
phantom recon smtp.sendgrid.net --platform hackerone -u bugsbunny
```

### 4.3 Twilio SIP (Wildcard)
```bash
# Test main SIP endpoint
phantom bounty https://sip.twilio.com --platform hackerone -u bugsbunny --rate 5
```

---

## Priority 5: CDN Assets (Lower Priority)

### 5.1 Static CDN
```bash
# CDNs typically have limited attack surface
phantom bounty https://static.twilio.com --platform hackerone -u bugsbunny --rate 5
```

---

## Batch Commands (Run All in Sequence)

### Run All Priority 1 (APIs)
```bash
# APIs - High value targets (~16 min each at 5 req/sec)
phantom bounty https://api.twilio.com --platform hackerone -u bugsbunny --rate 5 && \
phantom bounty https://api.sendgrid.com --platform hackerone -u bugsbunny --rate 5 && \
phantom bounty https://api.segment.io --platform hackerone -u bugsbunny --rate 5
```

### Run All Priority 2 (Web Apps)
```bash
# Web Applications
phantom bounty https://app.sendgrid.com --platform hackerone -u bugsbunny --rate 5 && \
phantom bounty https://app.segment.com --platform hackerone -u bugsbunny --rate 5 && \
phantom bounty https://signup.sendgrid.com --platform hackerone -u bugsbunny --rate 5
```

### Run All (Full Scan)
```bash
# Full scope scan (~3 hours total at 5 req/sec)
for target in \
  "https://api.twilio.com" \
  "https://api.sendgrid.com" \
  "https://api.segment.io" \
  "https://app.sendgrid.com" \
  "https://app.segment.com" \
  "https://signup.sendgrid.com" \
  "https://mc.sendgrid.com" \
  "https://sendgrid.com" \
  "https://www.twilio.com/blog" \
  "https://help.twilio.com" \
  "https://tsock.us1.twilio.com"; do
  echo "=== Scanning: $target ==="
  phantom bounty "$target" --platform hackerone -u bugsbunny --rate 5
  echo ""
  sleep 10  # Short pause between targets
done
```

---

## Custom Header Examples

### With Extra Headers
```bash
# Add custom authorization or tracking headers
phantom bounty https://api.twilio.com --platform hackerone -u bugsbunny --rate 5 \
  -H "X-Research-Purpose: security-testing" \
  -H "X-Contact: your-email@example.com"
```

### Different Output Formats
```bash
# JSON report (for parsing)
phantom bounty https://api.twilio.com --platform hackerone -u bugsbunny --rate 5 -f json

# Markdown report
phantom bounty https://api.twilio.com --platform hackerone -u bugsbunny --rate 5 -f md

# HTML report (default)
phantom bounty https://api.twilio.com --platform hackerone -u bugsbunny --rate 5 -f html
```

---

## OUT OF SCOPE - DO NOT TEST

The following targets are **INELIGIBLE** for bounty:

| Target | Reason |
|--------|--------|
| zipwhip.com | Ineligible |
| webinars.twilio.com | Ineligible |
| webinars.segment.com | Ineligible |
| twiliotraining.com | Ineligible |
| twil.io | Ineligible |
| transform.twilio.com | Ineligible |
| talks.twilio.com | Ineligible |
| surveys.twilio.com | Ineligible |
| support.twilio.com | Ineligible |
| support.sendgrid.com | Ineligible |
| store.twilio.com | Ineligible |
| status.twilio.com | Ineligible |
| status.sendgrid.com | Ineligible |
| status.segment.com | Ineligible |
| signal.twilio.com | Ineligible |
| lab.authy.com | Ineligible |
| community.segment.com | Ineligible |
| twilio.com/labs | Ineligible |
| twilio.com/jobs | Ineligible |
| segment.com/jobs | Ineligible |
| segment.com/contact | Ineligible |
| events.cdpweek.com | Ineligible |
| apjevents.twilio.com | Ineligible |
| TwimlBins | Ineligible |
| Twilio Wireless | Ineligible |
| Twilio Quest | Ineligible |
| Electric Imp | Ineligible |
| Ytica | Ineligible |
| All Kurento domains | Ineligible |
| Third-party services | Ineligible |

---

## Safety Reminders

1. **All commands use safe mode** - Only GET/HEAD/OPTIONS requests
2. **X-Bug-Bounty header** is automatically added to all requests
3. **Destructive payloads** are blocked at the HTTP layer
4. **Rate limiting** is set to 5 req/sec (safe for Twilio)

### Verify Your Header is Being Sent
```bash
# Test that your header is being injected
phantom bounty https://httpbin.org/headers --platform hackerone -u bugsbunny --rate 5
```

---

## Time Estimates (at 5 req/sec)

| Target Type | Estimated Time |
|-------------|----------------|
| Single API | ~16-20 min |
| Web App | ~20-25 min |
| All Priority 1 | ~50 min |
| Full Scope (11 targets) | ~3 hours |

---

## Quick Reference

| Command | Description |
|---------|-------------|
| `phantom bounty <url> -u bugsbunny --rate 5` | Standard bounty scan |
| `phantom bounty <url> -u bugsbunny --rate 5 -f json` | JSON output |
| `phantom bounty <url> -u bugsbunny --rate 10` | Faster (if no WAF issues) |
| `phantom recon <domain>` | Recon only (no testing) |
| `phantom quick <url>` | Fast scan (5 modules) |
| `phantom full <url>` | Full scan (75+ modules) |

---

## Reporting Findings

When you find something:

1. **Validate the finding** - Ensure it's not a false positive
2. **Document the impact** - What can an attacker do?
3. **Create PoC** - Minimal reproduction steps
4. **Submit to HackerOne** - Include PHANTOM report

Good hunting!
