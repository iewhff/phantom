"""
PHANTOM AI - Domain Classifier

Classifies a target into a business domain archetype using 3 signal sources:
1. Endpoint patterns (weight 0.5) — from EndpointMap
2. Technology stack (weight 0.3) — from TechIntelligence
3. Response content analysis (weight 0.2) — quick keyword scan

Called once per scan, before module execution.
Result is passed to business_logic_scanner via asset_data["domain_classification"].
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from typing import Any, Optional

import aiohttp

from scanning.business_archetypes import BusinessDomain
from utils.endpoint_map import EndpointMap, EndpointCategory
from utils.logger import get_logger

logger = get_logger(__name__)

# Permissive SSL for local/self-signed targets
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


# =============================================================================
# Classification Result
# =============================================================================

@dataclass
class DomainClassification:
    """Result of domain classification."""
    primary: BusinessDomain           # Best match
    confidence: float                 # 0.0–1.0
    scores: dict[str, float] = field(default_factory=dict)  # domain → score
    signals: list[str] = field(default_factory=list)         # What triggered it
    detected_features: set[str] = field(default_factory=set) # "has_cart", etc.

    def to_dict(self) -> dict[str, Any]:
        return {
            "primary": self.primary.value,
            "confidence": round(self.confidence, 3),
            "scores": {k: round(v, 3) for k, v in self.scores.items()},
            "signals": self.signals,
            "detected_features": sorted(self.detected_features),
        }


# =============================================================================
# Signal Definitions
# =============================================================================

# Weight: strong=3, moderate=2, weak=1
DOMAIN_ENDPOINT_SIGNALS: dict[BusinessDomain, dict[str, list[str]]] = {
    BusinessDomain.ECOMMERCE: {
        "strong": ["/cart", "/checkout", "/basket", "/products", "/shop"],
        "moderate": ["/order", "/payment", "/refund", "/coupon", "/wishlist"],
        "weak": ["/item", "/catalog", "/shipping", "/delivery"],
    },
    BusinessDomain.SAAS: {
        "strong": ["/subscription", "/plan", "/billing", "/tenant", "/workspace"],
        "moderate": ["/dashboard", "/settings", "/team", "/invite", "/seat"],
        "weak": ["/onboarding", "/upgrade", "/feature", "/usage"],
    },
    BusinessDomain.FINTECH: {
        "strong": ["/transfer", "/wallet", "/balance", "/transaction", "/withdraw"],
        "moderate": ["/deposit", "/statement", "/exchange", "/fund", "/bank"],
        "weak": ["/kyc", "/verify-identity", "/limit", "/beneficiary"],
    },
    BusinessDomain.MARKETPLACE: {
        "strong": ["/listing", "/seller", "/vendor", "/buyer", "/escrow"],
        "moderate": ["/review", "/dispute", "/commission", "/bid", "/auction"],
        "weak": ["/store", "/merchant", "/payout"],
    },
    BusinessDomain.AUTH_CENTRIC: {
        "strong": ["/oauth", "/saml", "/sso", "/authorize", "/2fa"],
        "moderate": ["/token", "/session", "/identity", "/mfa", "/consent"],
        "weak": ["/login", "/register", "/verify", "/reset-password"],
    },
    BusinessDomain.CONTENT: {
        "strong": ["/post", "/article", "/blog", "/cms", "/media"],
        "moderate": ["/publish", "/draft", "/moderate", "/comment", "/tag"],
        "weak": ["/page", "/category", "/archive", "/feed"],
    },
    BusinessDomain.API_SERVICE: {
        "strong": ["/graphql", "/webhook", "/api/v2", "/api/v3", "/openapi"],
        "moderate": ["/api-key", "/rate-limit", "/quota", "/health"],
        "weak": ["/status", "/metrics", "/docs", "/swagger"],
    },
}

# Feature detection signals
FEATURE_SIGNALS: dict[str, list[str]] = {
    "has_cart": ["/cart", "/basket", "/shopping-cart"],
    "has_checkout": ["/checkout", "/pay", "/payment"],
    "has_subscription": ["/subscription", "/plan", "/billing"],
    "has_wallet": ["/wallet", "/balance", "/transfer"],
    "has_listing": ["/listing", "/sell", "/vendor"],
    "has_oauth": ["/oauth", "/authorize", "/consent"],
    "has_content": ["/post", "/article", "/blog", "/publish"],
    "has_api_management": ["/api-key", "/webhook", "/graphql"],
    "has_mfa": ["/mfa", "/2fa", "/otp", "/totp"],
    "has_admin": ["/admin", "/manage", "/dashboard"],
}

# Technology → domain hints
TECH_DOMAIN_SIGNALS: dict[BusinessDomain, list[str]] = {
    BusinessDomain.ECOMMERCE: [
        "shopify", "woocommerce", "magento", "bigcommerce", "prestashop",
        "opencart", "stripe", "paypal", "braintree", "square",
    ],
    BusinessDomain.SAAS: [
        "chargebee", "paddle", "recurly", "intercom", "segment",
        "mixpanel", "amplitude", "launchdarkly",
    ],
    BusinessDomain.FINTECH: [
        "plaid", "dwolla", "yodlee", "wise", "currencycloud",
        "adyen", "marqeta",
    ],
    BusinessDomain.AUTH_CENTRIC: [
        "auth0", "okta", "keycloak", "firebase_auth", "cognito",
        "fusionauth", "identityserver",
    ],
    BusinessDomain.CONTENT: [
        "wordpress", "drupal", "joomla", "ghost", "strapi",
        "contentful", "sanity", "prismic",
    ],
}

# Response content keywords for domain detection
CONTENT_DOMAIN_SIGNALS: dict[BusinessDomain, list[str]] = {
    BusinessDomain.ECOMMERCE: [
        "add to cart", "checkout", "product", "price", "quantity",
        "shopping", "buy now", "order", "shipping",
    ],
    BusinessDomain.SAAS: [
        "subscription", "plan", "upgrade", "workspace", "team",
        "billing", "seats", "trial", "free tier",
    ],
    BusinessDomain.FINTECH: [
        "balance", "transfer", "transaction", "account number",
        "deposit", "withdraw", "statement", "exchange rate",
    ],
    BusinessDomain.MARKETPLACE: [
        "seller", "buyer", "listing", "bid", "escrow",
        "commission", "vendor", "marketplace",
    ],
    BusinessDomain.AUTH_CENTRIC: [
        "sign in", "single sign-on", "identity", "oauth",
        "authorize", "consent", "scope", "multi-factor",
    ],
    BusinessDomain.CONTENT: [
        "publish", "article", "blog", "author", "comment",
        "category", "tag", "draft", "editor",
    ],
}


# =============================================================================
# Classifier
# =============================================================================

class DomainClassifier:
    """Classify target into a business domain archetype."""

    # Signal weights
    W_ENDPOINTS = 0.5
    W_TECH = 0.3
    W_CONTENT = 0.2

    def __init__(
        self,
        endpoint_map: EndpointMap,
        tech_analysis: Any = None,
    ) -> None:
        self._endpoint_map = endpoint_map
        self._tech_analysis = tech_analysis
        self._signals: list[str] = []
        self._features: set[str] = set()

    async def classify(
        self,
        target: str,
        rate_limiter: Any = None,
    ) -> DomainClassification:
        """Classify target into a business domain. Called once per scan."""
        self._signals = []
        self._features = set()

        endpoint_scores = self._score_endpoints()
        tech_scores = self._score_tech_stack()
        content_scores = await self._score_content(target, rate_limiter)

        # Weighted combination
        final_scores: dict[str, float] = {}
        for domain in BusinessDomain:
            if domain == BusinessDomain.UNKNOWN:
                continue
            key = domain.value
            final_scores[key] = (
                endpoint_scores.get(key, 0.0) * self.W_ENDPOINTS
                + tech_scores.get(key, 0.0) * self.W_TECH
                + content_scores.get(key, 0.0) * self.W_CONTENT
            )

        if not final_scores:
            return DomainClassification(
                primary=BusinessDomain.UNKNOWN,
                confidence=0.0,
            )

        best_key = max(final_scores, key=final_scores.get)  # type: ignore[arg-type]
        best_score = final_scores[best_key]

        # Map back to enum
        primary = BusinessDomain.UNKNOWN
        for d in BusinessDomain:
            if d.value == best_key:
                primary = d
                break

        # If best score is too low, mark as unknown
        if best_score < 0.1:
            primary = BusinessDomain.UNKNOWN

        return DomainClassification(
            primary=primary,
            confidence=best_score,
            scores=final_scores,
            signals=self._signals,
            detected_features=self._features,
        )

    def _score_endpoints(self) -> dict[str, float]:
        """Score each domain based on discovered endpoint patterns."""
        scores: dict[str, float] = {}
        paths = [ep.path.lower() for ep in self._endpoint_map.get_all()]

        if not paths:
            return scores

        for domain, signals in DOMAIN_ENDPOINT_SIGNALS.items():
            raw_score = 0
            max_possible = (
                len(signals.get("strong", [])) * 3
                + len(signals.get("moderate", [])) * 2
                + len(signals.get("weak", [])) * 1
            )

            for path in paths:
                for keyword in signals.get("strong", []):
                    if keyword in path:
                        raw_score += 3
                        self._signals.append(f"endpoint:{keyword}→{domain.value}(strong)")
                for keyword in signals.get("moderate", []):
                    if keyword in path:
                        raw_score += 2
                        self._signals.append(f"endpoint:{keyword}→{domain.value}(moderate)")
                for keyword in signals.get("weak", []):
                    if keyword in path:
                        raw_score += 1

            # Normalize to 0-1
            if max_possible > 0:
                scores[domain.value] = min(raw_score / max_possible, 1.0)

        # Detect features
        for feature, keywords in FEATURE_SIGNALS.items():
            for path in paths:
                if any(kw in path for kw in keywords):
                    self._features.add(feature)
                    break

        return scores

    def _score_tech_stack(self) -> dict[str, float]:
        """Score each domain based on detected technology stack."""
        scores: dict[str, float] = {}

        if not self._tech_analysis:
            return scores

        # Extract detected tech names
        detected_techs: set[str] = set()
        if hasattr(self._tech_analysis, 'technologies'):
            for tech in self._tech_analysis.technologies:
                name = getattr(tech, 'name', str(tech)).lower()
                detected_techs.add(name)
        elif hasattr(self._tech_analysis, 'detected_technologies'):
            for tech in self._tech_analysis.detected_technologies:
                name = getattr(tech, 'name', str(tech)).lower()
                detected_techs.add(name)
        elif isinstance(self._tech_analysis, dict):
            for key in ('technologies', 'detected_technologies', 'tech_stack'):
                if key in self._tech_analysis:
                    for tech in self._tech_analysis[key]:
                        if isinstance(tech, str):
                            detected_techs.add(tech.lower())
                        elif isinstance(tech, dict):
                            detected_techs.add(tech.get('name', '').lower())

        if not detected_techs:
            return scores

        for domain, tech_hints in TECH_DOMAIN_SIGNALS.items():
            matches = 0
            for hint in tech_hints:
                for detected in detected_techs:
                    if hint in detected:
                        matches += 1
                        self._signals.append(f"tech:{detected}→{domain.value}")
                        break

            if tech_hints:
                scores[domain.value] = min(matches / len(tech_hints), 1.0)

        return scores

    async def _score_content(
        self,
        target: str,
        rate_limiter: Any = None,
    ) -> dict[str, float]:
        """Score each domain by scanning response content from top endpoints."""
        scores: dict[str, float] = {}

        # Get a few endpoints to probe
        endpoints = self._endpoint_map.get_all()
        probe_urls: list[str] = []

        base_url = target.rstrip("/")
        # Prioritize verified endpoints
        verified = [ep for ep in endpoints if ep.verified]
        candidates = verified[:5] if verified else endpoints[:5]

        for ep in candidates:
            if ep.path.startswith("http"):
                probe_urls.append(ep.path)
            else:
                probe_urls.append(f"{base_url}{ep.path}")

        # Always probe the root
        if base_url not in probe_urls:
            probe_urls.insert(0, base_url)

        # Limit to 5 probes
        probe_urls = probe_urls[:5]

        if not probe_urls:
            return scores

        # Collect response text from probes
        combined_text = ""
        timeout = aiohttp.ClientTimeout(total=8)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                for url in probe_urls:
                    try:
                        async with session.get(url, ssl=_SSL_CTX) as resp:
                            if resp.status == 200:
                                ct = resp.headers.get("content-type", "")
                                if "text" in ct or "json" in ct or "html" in ct:
                                    body = await resp.text()
                                    # Take first 5000 chars to limit processing
                                    combined_text += body[:5000] + " "
                    except Exception:
                        continue
        except Exception:
            return scores

        if not combined_text:
            return scores

        text_lower = combined_text.lower()

        for domain, keywords in CONTENT_DOMAIN_SIGNALS.items():
            matches = sum(1 for kw in keywords if kw in text_lower)
            if keywords:
                score = min(matches / len(keywords), 1.0)
                if score > 0:
                    scores[domain.value] = score
                    self._signals.append(
                        f"content:{domain.value}({matches}/{len(keywords)} keywords)"
                    )

        return scores
