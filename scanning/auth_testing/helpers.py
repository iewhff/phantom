"""
Auth Testing Helper Functions.

Utility functions for authentication and authorization testing:
- User identifier extraction
- Data comparison
- ID manipulation for IDOR testing
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional, Protocol
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


class AuthContextProtocol(Protocol):
    """Protocol for auth context objects."""

    @property
    def email(self) -> Optional[str]:
        ...

    @property
    def user_id(self) -> Optional[str]:
        ...

    @property
    def basket_id(self) -> Optional[str]:
        ...

    @property
    def token(self) -> Optional[str]:
        ...

    @property
    def cookies(self) -> Optional[dict[str, str]]:
        ...


def extract_user_identifiers(body: str, user: AuthContextProtocol) -> list[str]:
    """
    Extract user-specific identifiers from response body.

    Args:
        body: Response body text
        user: User auth context with email, user_id, etc.

    Returns:
        List of unique identifiers found
    """
    identifiers: list[str] = []

    # Add known user identifiers
    if user.email:
        identifiers.append(user.email)
    if user.user_id:
        identifiers.append(user.user_id)
    if hasattr(user, "basket_id") and user.basket_id:
        identifiers.append(user.basket_id)

    # Try to extract from JSON
    try:
        data = json.loads(body)
        # Only process dict responses, not arrays
        if isinstance(data, dict):
            for key in ["email", "user_id", "userId", "id", "username", "name"]:
                if key in data and data[key]:
                    identifiers.append(str(data[key]))
                if "user" in data and isinstance(data["user"], dict):
                    if key in data["user"] and data["user"][key]:
                        identifiers.append(str(data["user"][key]))
    except (json.JSONDecodeError, TypeError):
        pass

    return [i for i in identifiers if i]


def contains_victim_data(
    attacker_body: str, victim_identifiers: list[str], victim: AuthContextProtocol
) -> bool:
    """
    Check if attacker's response contains victim's data.

    Args:
        attacker_body: Response body from attacker's request
        victim_identifiers: List of victim's identifiers
        victim: Victim's auth context

    Returns:
        True if victim's data is found in attacker's response
    """
    # Check for victim's email or ID in attacker's response
    for identifier in victim_identifiers:
        if identifier and len(identifier) > 3:  # Avoid short matches
            if identifier in attacker_body:
                return True

    # Check for victim's specific fields
    if victim.email and victim.email in attacker_body:
        return True
    if victim.user_id and victim.user_id in attacker_body:
        return True

    return False


def get_auth_headers(auth_context: Optional[AuthContextProtocol]) -> dict[str, str]:
    """
    Get authentication headers from auth context.

    Args:
        auth_context: Auth context with token and/or cookies

    Returns:
        Dict of authentication headers
    """
    headers: dict[str, str] = {}
    if auth_context:
        if auth_context.token:
            headers["Authorization"] = f"Bearer {auth_context.token}"
        if auth_context.cookies:
            headers["Cookie"] = "; ".join(
                f"{k}={v}" for k, v in auth_context.cookies.items()
            )
    return headers


def generate_expanded_ids(
    original_id: str, working_id: str, expand_to: int
) -> list[int | str]:
    """
    Generate expanded IDs for IDOR testing.

    Strategy: Start from original_id and explore nearby values,
    then branch out to common admin/test values.

    Args:
        original_id: The original ID to expand from
        working_id: A known working ID (unused currently)
        expand_to: Maximum number of IDs to generate

    Returns:
        List of candidate IDs to test
    """
    ids: list[int | str] = []

    # Try to parse as integer for numeric expansion
    try:
        base = int(original_id)

        # Nearby values (most likely to work)
        for offset in range(-5, 6):
            candidate = base + offset
            if candidate >= 0 and candidate not in ids:
                ids.append(candidate)

        # Common ID patterns
        common_ids = [0, 1, 2, 100, 1000, 9999]
        for cid in common_ids:
            if cid not in ids:
                ids.append(cid)

        # Sequential from 1
        for i in range(1, min(20, expand_to)):
            if i not in ids:
                ids.append(i)

    except ValueError:
        # String-based ID (UUID, slug, etc.)
        # Try common test values
        ids = ["admin", "test", "user", "1", "0", "null", "undefined"]

    return ids[:expand_to]


def replace_id_in_url(url: str, original_id: str, new_id: str) -> str:
    """
    Replace an ID in a URL with a new value.

    Handles patterns like:
    - /api/users/123 → /api/users/456
    - /api/users?id=123 → /api/users?id=456
    - /api/users/123/profile → /api/users/456/profile

    Args:
        url: Original URL
        original_id: ID to replace
        new_id: New ID value

    Returns:
        URL with replaced ID
    """
    # First try direct path replacement
    if f"/{original_id}/" in url:
        return url.replace(f"/{original_id}/", f"/{new_id}/")
    if url.endswith(f"/{original_id}"):
        return url[: -len(original_id)] + new_id

    # Try query parameter replacement
    parsed = urlparse(url)
    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        modified = False
        for key, values in params.items():
            if original_id in values:
                params[key] = [new_id if v == original_id else v for v in values]
                modified = True
        if modified:
            new_query = urlencode(params, doseq=True)
            return urlunparse(parsed._replace(query=new_query))

    # Try regex patterns for common ID formats
    patterns = [
        (r"/(\d+)(?:/|$)", new_id),  # Numeric path segment
        (r"id=([^&]+)", f"id={new_id}"),  # id query param
        (r"userId=([^&]+)", f"userId={new_id}"),  # userId query param
    ]

    for pattern, replacement in patterns:
        if re.search(pattern, url):
            return re.sub(pattern, replacement, url, count=1)

    # Couldn't replace - return original
    return url


def extract_data_content(body: str) -> set[str]:
    """
    Extract meaningful data tokens from response.

    Used for comparing authenticated vs unauthenticated responses.

    Args:
        body: Response body text

    Returns:
        Set of extracted string tokens
    """
    # Extract quoted strings (likely data values)
    strings = re.findall(r'"([^"]{3,50})"', body)
    return set(strings)
