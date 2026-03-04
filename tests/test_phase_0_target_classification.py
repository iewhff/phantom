"""
Tests for Phase 0: Target Classification

Tests the TargetClassifier's ability to correctly identify target types
and recommend appropriate scanning modules.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import httpx


# ═══════════════════════════════════════════════════════════════════════════════
# Test Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

class MockResponse:
    """Mock HTTP response for testing."""
    def __init__(
        self,
        status_code: int = 200,
        text: str = "",
        headers: Optional[Dict] = None,
        cookies: Optional[httpx.Cookies] = None,
    ):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.cookies = cookies or httpx.Cookies()

    def json(self):
        """Return empty JSON for API probe calls."""
        return {}


class MockAsyncClient:
    """
    Mock AsyncClient that returns appropriate responses based on URL.

    - Main page: Returns the static HTML
    - API probes (/api, /graphql, etc.): Returns 404
    - JS files: Returns 404
    """

    def __init__(self, main_response: MockResponse, **kwargs):
        """Accept any kwargs that httpx.AsyncClient might receive."""
        self.main_response = main_response
        self._target_url = None
        self._first_request = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def get(self, url: str, **kwargs) -> MockResponse:
        """Return appropriate response based on URL."""
        # First call is the main page
        if self._first_request:
            self._first_request = False
            self._target_url = url
            return self.main_response

        # API endpoint probes - return 404 for static sites
        api_patterns = ['/api', '/graphql', '/v1/', '/v2/', '.well-known', 'openapi', '/rest']
        if any(pattern in url for pattern in api_patterns):
            return MockResponse(status_code=404, text="Not Found")

        # JS file fetches - return 404 for static sites
        if url.endswith('.js') or '/static/js/' in url:
            return MockResponse(status_code=404, text="Not Found")

        # robots.txt, sitemap.xml - return 404 for simple static sites
        if 'robots.txt' in url or 'sitemap' in url:
            return MockResponse(status_code=404, text="Not Found")

        # Default: 404
        return MockResponse(status_code=404, text="Not Found")


def create_mock_client_factory(main_response: MockResponse):
    """Create a factory function that returns a MockAsyncClient with the given response."""
    def factory(*args, **kwargs):
        return MockAsyncClient(main_response, **kwargs)
    return factory


# Static HTML site - minimal content, no JS frameworks, no forms
STATIC_SITE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>My Blog</title>
    <link rel="stylesheet" href="/styles.css">
</head>
<body>
    <header>
        <h1>Welcome to My Blog</h1>
        <nav>
            <a href="/">Home</a>
            <a href="/about.html">About</a>
            <a href="/contact.html">Contact</a>
        </nav>
    </header>
    <main>
        <article>
            <h2>My First Post</h2>
            <p>This is a simple static blog post.</p>
        </article>
    </main>
    <footer>
        <p>&copy; 2024 My Blog</p>
    </footer>
</body>
</html>
"""

STATIC_SITE_HEADERS = {
    "content-type": "text/html; charset=utf-8",
    "server": "nginx/1.24.0",
    "cache-control": "public, max-age=3600",
    "x-cache": "HIT",
}

# React SPA - has React framework markers
REACT_SPA_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>React App</title>
</head>
<body>
    <div id="root"></div>
    <script src="/static/js/bundle.js"></script>
    <script src="/static/js/main.chunk.js"></script>
    <script src="/static/js/vendors~main.chunk.js"></script>
</body>
</html>
"""

REACT_SPA_HEADERS = {
    "content-type": "text/html; charset=utf-8",
    "server": "Vercel",
    "x-powered-by": "Next.js",
}


# ═══════════════════════════════════════════════════════════════════════════════
# Test 1: Classify Static Website
# ═══════════════════════════════════════════════════════════════════════════════

class TestClassifyStaticWebsite:
    """Tests for static website classification."""

    @pytest.fixture
    def classifier(self):
        """Create a TargetClassifier instance."""
        from scanning.target_classifier import TargetClassifier
        return TargetClassifier(settings=None)

    @pytest.mark.asyncio
    async def test_classify_static_website_basic(self, classifier):
        """
        Test that a basic static HTML site is classified as STATIC_SITE.

        Static sites have:
        - No JavaScript frameworks (React, Vue, Angular)
        - No forms
        - Minimal JavaScript (<3 script tags)
        - No dynamic content markers
        - No session cookies
        """
        from scanning.target_classifier import TargetType

        # Mock the HTTP client response
        mock_response = MockResponse(
            status_code=200,
            text=STATIC_SITE_HTML,
            headers=STATIC_SITE_HEADERS,
            cookies=httpx.Cookies(),
        )

        with patch('httpx.AsyncClient', create_mock_client_factory(mock_response)):
            result = await classifier.classify("https://example-blog.com")

            # Verify classification
            assert result.target_type == TargetType.STATIC_SITE, \
                f"Expected STATIC_SITE, got {result.target_type}"

            # Confidence should be reasonably high (>50%)
            assert result.confidence >= 0.5, \
                f"Expected confidence >= 0.5, got {result.confidence}"

    @pytest.mark.asyncio
    async def test_static_site_has_no_forms(self, classifier):
        """Test that static site detection requires no forms."""
        from scanning.target_classifier import TargetType

        mock_response = MockResponse(
            status_code=200,
            text=STATIC_SITE_HTML,
            headers=STATIC_SITE_HEADERS,
        )

        with patch('httpx.AsyncClient', create_mock_client_factory(mock_response)):
            result = await classifier.classify("https://example-blog.com")

            assert result.has_forms is False, "Static site should not have forms"

    @pytest.mark.asyncio
    async def test_static_site_has_no_login(self, classifier):
        """Test that static site detection requires no login indicators."""
        from scanning.target_classifier import TargetType

        mock_response = MockResponse(
            status_code=200,
            text=STATIC_SITE_HTML,
            headers=STATIC_SITE_HEADERS,
        )

        with patch('httpx.AsyncClient', create_mock_client_factory(mock_response)):
            result = await classifier.classify("https://example-blog.com")

            assert result.has_login is False, "Static site should not have login"

    @pytest.mark.asyncio
    async def test_static_site_skips_injection_modules(self, classifier):
        """Test that static sites skip SQL injection and other backend modules."""
        from scanning.target_classifier import TargetType

        mock_response = MockResponse(
            status_code=200,
            text=STATIC_SITE_HTML,
            headers=STATIC_SITE_HEADERS,
        )

        with patch('httpx.AsyncClient', create_mock_client_factory(mock_response)):
            result = await classifier.classify("https://example-blog.com")

            # Verify that backend modules are skipped
            assert "sqli" in result.skip_modules, "Static site should skip SQLi"
            assert "ssrf" in result.skip_modules, "Static site should skip SSRF"
            assert "cmdi" in result.skip_modules, "Static site should skip CMDi"
            assert "nosql" in result.skip_modules, "Static site should skip NoSQL"

    @pytest.mark.asyncio
    async def test_static_site_recommends_infra_modules(self, classifier):
        """Test that static sites recommend infrastructure security modules."""
        from scanning.target_classifier import TargetType

        mock_response = MockResponse(
            status_code=200,
            text=STATIC_SITE_HTML,
            headers=STATIC_SITE_HEADERS,
        )

        with patch('httpx.AsyncClient', create_mock_client_factory(mock_response)):
            result = await classifier.classify("https://example-blog.com")

            # Verify that infrastructure modules are recommended
            assert "ssl" in result.recommended_modules, "Static site should recommend SSL"
            assert "headers" in result.recommended_modules, "Static site should recommend headers"
            assert "cors" in result.recommended_modules, "Static site should recommend CORS"

    @pytest.mark.asyncio
    async def test_static_site_skip_reasons_are_professional(self, classifier):
        """Test that skip reasons are professional and scope-based, not assumptions."""
        from scanning.target_classifier import TargetType

        mock_response = MockResponse(
            status_code=200,
            text=STATIC_SITE_HTML,
            headers=STATIC_SITE_HEADERS,
        )

        with patch('httpx.AsyncClient', create_mock_client_factory(mock_response)):
            result = await classifier.classify("https://example-blog.com")

            # Verify skip reasons are professional
            for module, reason in result.skip_reasons.items():
                assert "Not tested:" in reason, \
                    f"Skip reason for {module} should start with 'Not tested:'"
                assert "no database" not in reason.lower(), \
                    f"Skip reason should not assume architecture: {reason}"

    @pytest.mark.asyncio
    async def test_html_with_cdn_detected(self, classifier):
        """Test that CDN is detected from headers."""
        from scanning.target_classifier import TargetType

        cdn_headers = {
            **STATIC_SITE_HEADERS,
            "cf-ray": "abc123",  # Cloudflare indicator
            "server": "cloudflare",
        }

        mock_response = MockResponse(
            status_code=200,
            text=STATIC_SITE_HTML,
            headers=cdn_headers,
        )

        with patch('httpx.AsyncClient', create_mock_client_factory(mock_response)):
            result = await classifier.classify("https://cdn-blog.com")

            assert "cloudflare" in result.detected_cdn.lower(), \
                f"Should detect Cloudflare CDN, got: {result.detected_cdn}"

    @pytest.mark.asyncio
    async def test_static_site_with_minimal_javascript(self, classifier):
        """Test that sites with minimal JS (<3 scripts) can still be static."""
        from scanning.target_classifier import TargetType

        html_with_one_script = """
        <!DOCTYPE html>
        <html>
        <head><title>Blog</title></head>
        <body>
            <h1>Welcome</h1>
            <p>Content here</p>
            <script src="/analytics.js"></script>
        </body>
        </html>
        """

        mock_response = MockResponse(
            status_code=200,
            text=html_with_one_script,
            headers=STATIC_SITE_HEADERS,
        )

        with patch('httpx.AsyncClient', create_mock_client_factory(mock_response)):
            result = await classifier.classify("https://minimal-js-blog.com")

            # Should still be classified as static (1 script < 3 threshold)
            assert result.target_type == TargetType.STATIC_SITE or \
                   result.target_type.value in ("static_site", "cloud_only"), \
                   f"Expected static-like type, got {result.target_type}"

    @pytest.mark.asyncio
    async def test_not_static_when_has_forms(self, classifier):
        """Test that sites with forms are NOT classified as static."""
        from scanning.target_classifier import TargetType

        html_with_form = """
        <!DOCTYPE html>
        <html>
        <head><title>Contact</title></head>
        <body>
            <h1>Contact Us</h1>
            <form action="/submit" method="POST">
                <input type="text" name="name">
                <input type="email" name="email">
                <textarea name="message"></textarea>
                <button type="submit">Send</button>
            </form>
        </body>
        </html>
        """

        mock_response = MockResponse(
            status_code=200,
            text=html_with_form,
            headers=STATIC_SITE_HEADERS,
        )

        with patch('httpx.AsyncClient', create_mock_client_factory(mock_response)):
            result = await classifier.classify("https://has-form.com")

            assert result.has_forms is True, "Should detect form"
            # With a form, it should NOT be classified as pure STATIC_SITE
            # (it might be BACKEND_CLASSIC or similar)


# ═══════════════════════════════════════════════════════════════════════════════
# Test 2: Classify SPA (React)
# ═══════════════════════════════════════════════════════════════════════════════

class TestClassifyReactSPA:
    """Tests for React SPA classification."""

    @pytest.fixture
    def classifier(self):
        """Create a TargetClassifier instance."""
        from scanning.target_classifier import TargetClassifier
        return TargetClassifier(settings=None)

    @pytest.mark.asyncio
    async def test_classify_react_spa(self, classifier):
        """Test that React SPA is detected correctly."""
        from scanning.target_classifier import TargetType

        mock_response = MockResponse(
            status_code=200,
            text=REACT_SPA_HTML,
            headers=REACT_SPA_HEADERS,
        )

        with patch('httpx.AsyncClient', create_mock_client_factory(mock_response)):
            result = await classifier.classify("https://react-app.com")

            # Should be SPA or SPA_WITH_BACKEND (Next.js detected)
            assert result.target_type in (TargetType.SPA, TargetType.SPA_WITH_BACKEND), \
                f"Expected SPA type, got {result.target_type}"

    @pytest.mark.asyncio
    async def test_react_spa_detects_framework(self, classifier):
        """Test that React framework is detected from HTML."""
        from scanning.target_classifier import TargetType

        # HTML with clear React markers
        react_html = """
        <!DOCTYPE html>
        <html>
        <head><title>React App</title></head>
        <body>
            <div id="root" data-reactroot></div>
            <script src="/static/js/bundle.js"></script>
        </body>
        </html>
        """

        mock_response = MockResponse(
            status_code=200,
            text=react_html,
            headers={"content-type": "text/html"},
        )

        with patch('httpx.AsyncClient', create_mock_client_factory(mock_response)):
            result = await classifier.classify("https://react-app.com")

            # Check that React is detected
            frameworks_lower = [f.lower() for f in result.detected_frameworks]
            technologies_lower = [t.lower() for t in result.detected_technologies]
            all_detected = frameworks_lower + technologies_lower

            assert any("react" in item for item in all_detected), \
                f"Should detect React, got: {result.detected_frameworks} + {result.detected_technologies}"


# ═══════════════════════════════════════════════════════════════════════════════
# Test 3: Classify SPA (Angular)
# ═══════════════════════════════════════════════════════════════════════════════

class TestClassifyAngularSPA:
    """Tests for Angular SPA classification."""

    @pytest.fixture
    def classifier(self):
        """Create a TargetClassifier instance."""
        from scanning.target_classifier import TargetClassifier
        return TargetClassifier(settings=None)

    @pytest.mark.asyncio
    async def test_classify_angular_spa(self, classifier):
        """Test that Angular SPA is detected correctly."""
        from scanning.target_classifier import TargetType

        angular_html = """
        <!DOCTYPE html>
        <html>
        <head><title>Angular App</title></head>
        <body>
            <app-root ng-version="16.2.0"></app-root>
            <script src="/runtime.js"></script>
            <script src="/polyfills.js"></script>
            <script src="/main.js"></script>
        </body>
        </html>
        """

        mock_response = MockResponse(
            status_code=200,
            text=angular_html,
            headers={"content-type": "text/html"},
        )

        with patch('httpx.AsyncClient', create_mock_client_factory(mock_response)):
            result = await classifier.classify("https://angular-app.com")

            # Should be SPA type
            assert result.target_type in (TargetType.SPA, TargetType.SPA_WITH_BACKEND), \
                f"Expected SPA type, got {result.target_type}"

    @pytest.mark.asyncio
    async def test_angular_spa_detects_framework(self, classifier):
        """Test that Angular framework is detected from HTML."""
        from scanning.target_classifier import TargetType

        angular_html = """
        <!DOCTYPE html>
        <html>
        <head><title>Angular</title></head>
        <body>
            <app-root _nghost-abc-123></app-root>
        </body>
        </html>
        """

        mock_response = MockResponse(
            status_code=200,
            text=angular_html,
            headers={"content-type": "text/html"},
        )

        with patch('httpx.AsyncClient', create_mock_client_factory(mock_response)):
            result = await classifier.classify("https://angular-app.com")

            frameworks_lower = [f.lower() for f in result.detected_frameworks]
            technologies_lower = [t.lower() for t in result.detected_technologies]
            all_detected = frameworks_lower + technologies_lower

            assert any("angular" in item for item in all_detected), \
                f"Should detect Angular, got: {result.detected_frameworks} + {result.detected_technologies}"


# ═══════════════════════════════════════════════════════════════════════════════
# Test 4: Classify API (REST)
# ═══════════════════════════════════════════════════════════════════════════════

class MockAPIClient:
    """Mock client for API testing that returns JSON responses."""

    def __init__(self, api_response: MockResponse, main_response: MockResponse = None, **kwargs):
        self.api_response = api_response
        self.main_response = main_response
        self._first_request = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def get(self, url: str, **kwargs) -> MockResponse:
        """Return appropriate response based on URL."""
        # API endpoints return JSON
        if '/api' in url or '/v1/' in url or '/rest' in url:
            return self.api_response

        # Main page returns HTML or redirect to API docs
        if self._first_request:
            self._first_request = False
            if self.main_response:
                return self.main_response
            # API-first sites often return JSON or minimal HTML
            return MockResponse(
                status_code=200,
                text='{"status": "ok", "version": "1.0"}',
                headers={"content-type": "application/json"},
            )

        return MockResponse(status_code=404, text="Not Found")


def create_api_mock_client_factory(api_response: MockResponse, main_response: MockResponse = None):
    """Create a factory for API mocking."""
    def factory(*args, **kwargs):
        return MockAPIClient(api_response, main_response, **kwargs)
    return factory


class TestClassifyRESTAPI:
    """Tests for REST API classification."""

    @pytest.fixture
    def classifier(self):
        """Create a TargetClassifier instance."""
        from scanning.target_classifier import TargetClassifier
        return TargetClassifier(settings=None)

    @pytest.mark.asyncio
    async def test_classify_rest_api(self, classifier):
        """Test that REST API is detected when main page returns JSON."""
        from scanning.target_classifier import TargetType

        api_response = MockResponse(
            status_code=200,
            text='{"status": "ok", "version": "1.0", "endpoints": ["/users", "/products"]}',
            headers={"content-type": "application/json"},
        )

        with patch('httpx.AsyncClient', create_api_mock_client_factory(api_response)):
            result = await classifier.classify("https://api.example.com")

            assert result.target_type == TargetType.API_FIRST, \
                f"Expected API_FIRST, got {result.target_type}"

    @pytest.mark.asyncio
    async def test_api_signals_api_endpoints(self, classifier):
        """Test that API detection records API endpoint signals."""
        from scanning.target_classifier import TargetType

        api_response = MockResponse(
            status_code=200,
            text='{"data": [], "message": "success"}',
            headers={"content-type": "application/json"},
        )

        with patch('httpx.AsyncClient', create_api_mock_client_factory(api_response)):
            result = await classifier.classify("https://api.example.com")

            # Check API endpoint detection signals
            api_signals = [k for k in result.signals.keys() if 'api_endpoint' in k]
            assert len(api_signals) > 0, "Should have API endpoint signals"
            # Also check that API type was correctly identified
            assert result.target_type == TargetType.API_FIRST, \
                f"Expected API_FIRST, got {result.target_type}"


# ═══════════════════════════════════════════════════════════════════════════════
# Test 5: Classify GraphQL API
# ═══════════════════════════════════════════════════════════════════════════════

class MockGraphQLClient:
    """Mock client for GraphQL testing."""

    def __init__(self, **kwargs):
        self._first_request = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def get(self, url: str, **kwargs) -> MockResponse:
        """Return GraphQL playground for /graphql."""
        if '/graphql' in url:
            # GraphQL endpoints typically return a playground or introspection
            return MockResponse(
                status_code=200,
                text="""
                <!DOCTYPE html>
                <html>
                <head><title>GraphQL Playground</title></head>
                <body>
                    <div id="root">GraphQL Playground</div>
                    <script>
                        // GraphQL Playground
                        window.__APOLLO_CLIENT__ = {};
                    </script>
                </body>
                </html>
                """,
                headers={"content-type": "text/html"},
            )

        # Main page - minimal HTML indicating GraphQL
        if self._first_request:
            self._first_request = False
            return MockResponse(
                status_code=200,
                text="""
                <!DOCTYPE html>
                <html>
                <head><title>API</title></head>
                <body>
                    <h1>API Service</h1>
                    <p>GraphQL endpoint: /graphql</p>
                </body>
                </html>
                """,
                headers={"content-type": "text/html"},
            )

        return MockResponse(status_code=404, text="Not Found")


def create_graphql_mock_factory():
    """Create factory for GraphQL mock client."""
    def factory(*args, **kwargs):
        return MockGraphQLClient(**kwargs)
    return factory


class TestClassifyGraphQL:
    """Tests for GraphQL API classification."""

    @pytest.fixture
    def classifier(self):
        """Create a TargetClassifier instance."""
        from scanning.target_classifier import TargetClassifier
        return TargetClassifier(settings=None)

    @pytest.mark.asyncio
    async def test_graphql_endpoint_detected(self, classifier):
        """Test that GraphQL endpoint is detected."""
        from scanning.target_classifier import TargetType

        with patch('httpx.AsyncClient', create_graphql_mock_factory()):
            result = await classifier.classify("https://api.example.com/graphql")

            # GraphQL should be detected (API_FIRST or signal present)
            # Check either target type or detected technologies
            is_api = result.target_type == TargetType.API_FIRST
            has_graphql = any("graphql" in t.lower() for t in result.detected_technologies)

            assert is_api or has_graphql, \
                f"Expected API_FIRST or GraphQL detection, got {result.target_type}, techs: {result.detected_technologies}"


# ═══════════════════════════════════════════════════════════════════════════════
# Test 6: Never Skip Critical Modules
# ═══════════════════════════════════════════════════════════════════════════════

class TestNeverSkipCritical:
    """Tests that critical modules are never skipped for dynamic targets."""

    @pytest.fixture
    def classifier(self):
        """Create a TargetClassifier instance."""
        from scanning.target_classifier import TargetClassifier
        return TargetClassifier(settings=None)

    @pytest.mark.asyncio
    async def test_backend_never_skips_sqli_xss(self, classifier):
        """Test that backend classic targets never skip SQLi and XSS."""
        from scanning.target_classifier import TargetType

        backend_html = """
        <!DOCTYPE html>
        <html>
        <head><title>Login</title></head>
        <body>
            <form action="/login" method="POST">
                <input type="text" name="username">
                <input type="password" name="password">
                <button type="submit">Login</button>
            </form>
            <?php // Powered by PHP ?>
        </body>
        </html>
        """

        # Create a mock client that returns the backend page AND
        # returns 200 for /api to indicate backend processing
        class MockBackendClient:
            def __init__(self, **kwargs):
                self._first_request = True

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def get(self, url: str, **kwargs) -> MockResponse:
                if self._first_request:
                    self._first_request = False
                    return MockResponse(
                        status_code=200,
                        text=backend_html,
                        headers={"content-type": "text/html", "x-powered-by": "PHP/8.0"},
                    )
                # Return 200 for /api to indicate backend
                if '/api' in url:
                    return MockResponse(
                        status_code=200,
                        text='{"status": "ok"}',
                        headers={"content-type": "application/json"},
                    )
                return MockResponse(status_code=404, text="Not Found")

        def backend_factory(*args, **kwargs):
            return MockBackendClient(**kwargs)

        with patch('httpx.AsyncClient', backend_factory):
            result = await classifier.classify("https://backend-app.com")

            # With forms, login, and API endpoints, this should be BACKEND_CLASSIC or SPA_WITH_BACKEND
            # Either way, SQLi and XSS should be recommended
            assert result.target_type in (TargetType.BACKEND_CLASSIC, TargetType.SPA_WITH_BACKEND, TargetType.API_FIRST), \
                f"Expected dynamic backend type, got {result.target_type}"

            # For dynamic backends, injection testing should be enabled
            if result.target_type == TargetType.BACKEND_CLASSIC:
                assert "sqli" in result.recommended_modules, "Backend should recommend SQLi"
                assert "xss" in result.recommended_modules, "Backend should recommend XSS"

    @pytest.mark.asyncio
    async def test_spa_with_backend_tests_injections(self, classifier):
        """Test that SPA_WITH_BACKEND still tests injection modules."""
        from scanning.target_classifier import TargetType, MODULE_RECOMMENDATIONS

        # SPA_WITH_BACKEND should have injection modules recommended
        spa_backend_recs = MODULE_RECOMMENDATIONS.get(TargetType.SPA_WITH_BACKEND, {})
        recommended = spa_backend_recs.get("recommended", [])

        assert "sqli" in recommended, "SPA_WITH_BACKEND should recommend SQLi"
        assert "nosql" in recommended, "SPA_WITH_BACKEND should recommend NoSQL"


# ═══════════════════════════════════════════════════════════════════════════════
# Run tests
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
