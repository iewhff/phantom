# PetNTester AI — Enterprise Remediation Plan (v1.0)

**Date:** 2026-01-30
**Author:** Claude Code — Enterprise Audit
**Target:** PetNTester AI (scanning subsystem)
**Purpose:** Convert the existing audit output into a hardened, enterprise-grade remediation plan, implementation roadmap, and actionable engineering ticket set.

---

# Executive summary

PetNTester AI demonstrates a mature architecture and exceptional breadth of scanning capability (52 modules). However, three critical implementation gaps block enterprise adoption:

1. **Tool orchestration and chaining are broken** — external Linux tools run in isolation and findings are not fed back to modules (60% capability unused).
2. **Chain engine is theoretical** — chain handlers return prepared templates instead of executing escalation actions.
3. **Phantom triggers & missing tool mappings** — multiple chains reference non-existent tools; chains silently fail.

This remediation plan closes those gaps while preserving safe defaults and legal guardrails. Objectives:

- Make tool chaining reliable and bi-directional.
- Convert prepared chains into verified escalation flows under an explicit exploit policy.
- Add robust inter-module context sharing, parameter correlation, and instrumentation.
- Harden CI checks, governance, and telemetry for enterprise use.

Estimated effort: **4–8 engineering sprints** (teams and scope dependent). Prioritized immediate actions are included.

---

# High-level priorities (must-do)

**P0 (Immediate — apply within 1 week):**
- Implement `Exploit Policy Engine` (detect-only / verify / exploit modes). Default: **detect-only**. Require explicit `--exploit` flag + signed authorization for destructive actions.
- Wire Linux tools to run *before* module scanning and feed results into a `ScanContext` shared object.
- Remove or validate phantom TOOL_CHAINS; add discovery-time validation.

**P1 (Short term — 2 weeks):**
- Convert chain handlers from templates to *confirmable* actions (safe verification first). Add execution toggles that obey Exploit Policy.
- Implement `ScanContext` pub/sub and parameter correlation (preserve discovered query params, headers, cookies).
- Fix sqlmap integration: enable auto-trigger only in `verify` or `exploit` modes and implement JSON output parsing.

**P2 (Medium term — 4–8 weeks):**
- Authenticated scanning pipeline (login automation, session propagation, API key handling).
- Business-logic module and Attack Graph Planner to generate prioritized attack paths.
- Integrate external recon (GitHub, Shodan) and enterprise reporting (JIRA, Slack, remediation lifecycle).

---

# Recommended architecture changes (concise)

## 1. ScanContext — single source of truth

**Purpose:** hold discoveries and metadata; enable modules to publish and subscribe.

**Key features:**
- Per-scan `ScanContext` instance (thread/async-safe).
- `publish(key, value, origin)` and `subscribe(key, callback)` API.
- Snapshotting for reproducibility and reporting.
- Storage of discovered endpoints with full parameter metadata.

**Example usage:**

```python
# scan_context.py (concept)
class ScanContext:
    def __init__(self):
        self._store = defaultdict(list)
        self._subscribers = defaultdict(list)

    def publish(self, key, value, origin=None):
        self._store[key].append({"value": value, "origin": origin})
        for cb in self._subscribers[key]:
            cb(value, origin)

    def subscribe(self, key, callback):
        self._subscribers[key].append(callback)

    def get(self, key):
        return [e['value'] for e in self._store.get(key, [])]
```

## 2. Exploit Policy Engine (EPE)

**Purpose:** explicit guardrail for any action that could damage or expose data.

**Modes:** `detect_only` (default), `verify` (non-destructive proofs-of-concept), `exploit` (full escalation; require signed approval and audit log).

**Policy enforcement points:**
- Any chain handler must call `EPE.allow(action_context)` and obey response.
- CLI and API must refuse `exploit` mode without admin token + signed justification.

**Example decision flow:**

```
module -> finding -> chain_engine -> request_allow_from_EPE
EPE returns: {allow: False, reason: 'detect_only active'}
chain_engine either: save prepared template OR run safe verification steps
```

## 3. Tool Orchestration & Triggers

**Key changes:**
- Run Linux/external tools in Phase 1 (before module execution) to prime modules with findings.
- Formalize `asset_data` format for tool outputs (hosts, ports, service details, discovered params).
- Implement validation of TOOL_CHAINS on startup: warn/error for missing targets.

**Asset example:**

```json
{
  "endpoints": [
    { "url": "https://example.com/api/users?id=", "params": ["id"], "method": "GET" }
  ],
  "services": [ {"port": 3306, "service": "mysql", "host": "10.0.0.5" } ]
}
```

---

# Concrete code changes (high impact)

Below are recommended, copy-paste friendly changes. Treat as PR patches.

## A. Enable linux tools and run them before modules

**File:** `scanning/full_scanner.py`

```diff
-    use_linux_tools = False
+    use_linux_tools = True
@@
-    # current order: modules -> linux tools
-    await self._run_modules_scan(result, target)
-    if use_linux_tools:
-        await self._run_linux_tools_scan(result, target)
+    # desired order: linux tools -> modules
+    if use_linux_tools:
+        tool_results = await self._run_linux_tools_scan(result, target)
+        context.publish("external_tools", tool_results, origin="linux_tools")
+    await self._run_modules_scan(result, target, context=context)
```

**Notes:** publish `tool_results` to `ScanContext` to allow modules to consume findings.

## B. Validate TOOL_CHAINS on startup

**File:** `scanning/linux_tools_orchestrator.py`

```python
# on init
for tool, mapping in TOOL_CHAINS.items():
    for key, handlers in mapping.items():
        for handler in handlers:
            if handler not in self.available_tools:
                log.warning(f"TOOL_CHAINS references missing tool {handler}; removing")
                mapping[key] = [h for h in handlers if h in self.available_tools]
```

## C. Chain handlers: confirmable actions (safely)

**File:** `scanning/vuln_chain_engine.py`

**Pattern change:** handlers return structured objects with states: `prepared` | `verified` | `executed` and a standard `execute()` coroutine that respects EPE.

```python
async def _sqli_mysql_udf_rce(self, finding, context):
    prepared = {
       "name": "SQLi → MySQL UDF RCE Chain",
       "state": "prepared",
       "poc": {"steps": [...]}
    }
    # attempt a safe verification if allowed
    if await self.epe.allow("verify", finding):
        verified = await self._verify_sqli_remote(finding, context)
        prepared.update({"state": "verified", "verification": verified})
    return prepared
```

**Important:** verification must be non-destructive (no file writes, no DB drops). Full exploitation only in `exploit` mode.

## D. SQLMap integration (safe, gated)

**File:** `scanning/modules/sqli_scanner.py`

Key changes:
- Set `_use_sqlmap` based on orchestrator availability and EPE setting
- Use `--batch --output-dir` and `--dump-format=JSON` to parse results

```python
if findings and self._use_sqlmap and await self.epe.allow("verify", context=finding):
    cmd = ["sqlmap", "-u", target_url, "--batch", "--output-dir", outdir, "--dump-format=JSON"]
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=PIPE, stderr=PIPE)
    stdout, stderr = await proc.communicate()
    # parse JSON outputs from outdir
```

**Note:** actual `--dump` should be gated to `exploit` mode only.

---

# Operational changes & governance

## Authorization & audit

- All `exploit` mode runs require an **admin API token** + **run justification** (string) sent with request
- The EPE must record: user, rationale, timestamp, scan_id, modules allowed, and outcome
- For regulated customers, require manual sign-off before escalations

## Safe defaults

- Default CLI and scheduler: `--mode=detect_only`
- CI runs must use `--mode=verify` or `detect_only` only
- Production pentest runs (exploit) require ephemeral credentials and auditable approvals

## Logging & observability

- Add structured logs for: tool executions, chain attempts, EPE decisions, errors
- Export telemetry to central system: Prometheus metrics for `escalations_attempted`, `escalations_success`, `tools_triggered`

**Suggested metrics:**
- `petntester_tools_triggered_total{tool}`
- `petntester_chain_attempts_total{chain}`
- `petntester_escalation_success_total`

---

# Test plan & verification checklist

## Automated unit tests (examples)

- `test_scancontext_publish_subscribe()` — ensures publish/subscribe integrity
- `test_toolchain_validation()` — verifies missing tools are logged and removed
- `test_epe_default_detect_only()` — EPE denies exploit by default
- `test_sqlmap_json_parser()` — parser extracts expected keys from sample JSON

## Integration test scenarios

1. **Tool orchestration smoke test (CI)**
   - Input: mock `nmap` output with HTTP service
   - Expect: modules receive `external_tools` in context and schedule targeted scans
2. **Chain verification test (safe)**
   - Input: mock SQLi finding
   - Mode: `verify`
   - Expect: chain handler runs non-destructive verification and updates finding state to `verified`
3. **Exploit guard test**
   - Mode: `exploit` without admin token
   - Expect: run refused and logged

## Manual validation steps (operators)

- `python -m cli.main scan https://example.com --use-tools --mode=detect_only`
- Ensure scan prints `external_tools` results and modules consume them
- Re-run with `--mode=verify` to confirm verification steps execute

---

# Prioritized ticket list (ready to open)

**CRITICAL (week):**
1. `FEAT: Exploit Policy Engine (EPE)` — design + API + enforcement
2. `BUG: Run linux tools before modules & publish results` — full_scanner.py changes
3. `BUG: Validate TOOL_CHAINS on startup` — linux_tools_orchestrator.py
4. `FEAT: ScanContext pub/sub` — utils/scan_context.py
5. `BUG: Fix execution_time reporting` — linux_tools_orchestrator.py

**HIGH (2 weeks):**
6. `FEAT: Chain handler state machine (prepared/verified/executed)` — vuln_chain_engine.py
7. `FEAT: SQLMap integration (verify-mode JSON parsing)` — sqli_scanner.py
8. `CHORE: Deduplicate orchestrator init` — utils/orchestrator_utils.py

**MEDIUM (1 month):**
9. `FEAT: Authenticated scanning pipeline` — auth module, credential manager
10. `FEAT: Business Logic module` — business_logic_engine.py
11. `FEAT: External recon integrations (GitHub, Shodan)`

---

# Example PR description (template)

**Title:** Enable linux-tools orchestration and ScanContext publishing

**Summary:**
- Run linux tools in Phase 1 and publish `external_tools` to `ScanContext`.
- Modules consume `external_tools` and adjust scanning strategy.
- Adds `ScanContext` class and simple unit tests.

**Testing:**
- Unit tests added: `test_scancontext_publish_subscribe`
- Integration: smoke test script included

**Risk:** Low. Backwards compatible when `use_linux_tools=False`.

---

# Governance & customer-facing messaging

When communicating to customers and internal stakeholders, use this message:

> "We discovered orchestration and escalation gaps in the scanning engine. We will roll a safe, staged remediation that preserves the default non-destructive behavior while enabling advanced verification and controlled escalation for authorized runs."

Include this short FAQ in client communications:

- **Q:** Will you run destructive exploits on production systems?  
  **A:** No. Exploit actions are disabled by default and require explicit authorization.

- **Q:** Will I receive noisy alerts?  
  **A:** No. We will gate escalations and provide concise verified PoCs for customer review.

---

# Appendix A — Quick validation commands

```bash
# Run a safe scan (CI friendly)
python -m cli.main scan https://example.com --use-tools --mode=detect_only

# Run verification mode (non-destructive)
python -m cli.main scan https://example.com --use-tools --mode=verify --admin-token "$TOKEN"

# Run tests
pytest tests/unit -q
```

---

# Appendix B — Suggested timeline (rough)

| Sprint | Duration | Deliverables |
|--------|----------|--------------|
| Week 0 | 1 week | EPE design, ScanContext prototype, enable linux tools smoke patch |
| Week 1–2 | 2 weeks | Chain handler state machine, sqlmap verify integration, tool chain validation |
| Week 3–4 | 2 weeks | Authenticated scanning PoC, business logic module skeleton |
| Week 5–8 | 4 weeks | External recon integrations, reporting & integrations (JIRA/Slack), hardening & perf |

---

# Appendix C — Key design principles

1. **Fail-safe by default.** `detect_only` default, `exploit` explicit with audit trail.
2. **Evidence-first automation.** Tools produce facts; modules act on facts.
3. **Minimal blast radius.** Verification must be non-destructive.
4. **Reproducible scans.** Snapshot `ScanContext` and store artifacts.
5. **Human-in-loop for high-impact actions.** Manual approval required for escalations.

---

If queres, eu gero:  
- PR-ready patches (diffs) para cada arquivo crítico;  
- Test cases concretos (pytest) para `ScanContext` e `EPE`;  
- Um diagrama UML/sequence (ASCII + SVG-ready) para arquiteturas.  

Diz-me qual destes queres agora e eu crio imediatamente.

