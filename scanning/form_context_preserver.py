"""
Form Context Preservation v1.0 - Maintain Valid Values During Testing

PROBLEM:
When testing one form parameter (e.g., injecting SQLi into 'username'),
other fields are often empty or invalid, causing the server to reject
the request before even processing the injected parameter.

Example:
  - Form has: username, password, email, phone
  - Testing SQLi in username with: username=admin' OR '1'='1
  - But password="" causes "Password required" error → injection never tested!

SOLUTION:
Maintain valid context values for all fields while testing one at a time.

Philosophy: "Test parameters, not form validation bypass."

Author: PHANTOM AI
Version: 1.0.0
"""

from __future__ import annotations

import re
import json
import random
import string
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum
from urllib.parse import urlencode
import logging

logger = logging.getLogger(__name__)


class FieldType(Enum):
    """Recognized field types for value generation."""
    TEXT = "text"
    EMAIL = "email"
    PASSWORD = "password"
    PHONE = "phone"
    URL = "url"
    NUMBER = "number"
    INTEGER = "integer"
    FLOAT = "float"
    DATE = "date"
    DATETIME = "datetime"
    TIME = "time"
    SELECT = "select"
    CHECKBOX = "checkbox"
    RADIO = "radio"
    TEXTAREA = "textarea"
    FILE = "file"
    HIDDEN = "hidden"
    ID = "id"
    USERNAME = "username"
    NAME = "name"
    ADDRESS = "address"
    CITY = "city"
    STATE = "state"
    COUNTRY = "country"
    ZIPCODE = "zipcode"
    CARD_NUMBER = "card_number"
    CVV = "cvv"
    EXPIRY = "expiry"
    AMOUNT = "amount"
    QUANTITY = "quantity"
    COMMENT = "comment"
    SEARCH = "search"
    CSRF = "csrf"
    UNKNOWN = "unknown"


@dataclass
class FieldDefinition:
    """Definition of a form field with validation."""
    name: str
    field_type: FieldType = FieldType.UNKNOWN
    is_required: bool = False
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    pattern: Optional[str] = None
    options: List[str] = field(default_factory=list)  # For select/radio
    default_value: Optional[str] = None
    placeholder: Optional[str] = None
    depends_on: Optional[str] = None  # Field this depends on

    # Injection relevance
    is_injectable: bool = True
    is_csrf: bool = False


@dataclass
class FormDefinition:
    """Complete form definition with all fields."""
    action: str
    method: str = "POST"
    enctype: str = "application/x-www-form-urlencoded"
    fields: List[FieldDefinition] = field(default_factory=list)
    submit_button: Optional[str] = None
    submit_value: Optional[str] = None
    csrf_field_name: Optional[str] = None
    discovered_from: str = ""  # URL where form was found

    def get_injectable_fields(self) -> List[FieldDefinition]:
        """Get fields that should be tested for injection."""
        return [f for f in self.fields if f.is_injectable and not f.is_csrf]

    def get_field(self, name: str) -> Optional[FieldDefinition]:
        """Get field by name."""
        for f in self.fields:
            if f.name == name:
                return f
        return None


class FormContextPreserver:
    """
    Maintains valid form context while testing individual parameters.

    Usage:
        preserver = FormContextPreserver()

        # Learn form structure
        form = preserver.analyze_form(html_content, form_action_url)

        # Get data for testing 'username' field
        test_data = preserver.get_test_data(
            form=form,
            target_field="username",
            injection_payload="admin' OR '1'='1"
        )
        # Returns: {"username": "admin' OR '1'='1", "password": "Test1234!", "email": "test@example.com", ...}
    """

    # Name patterns to detect field types
    FIELD_TYPE_PATTERNS = {
        FieldType.EMAIL: [r"email", r"e-mail", r"mail"],
        FieldType.PASSWORD: [r"password", r"passwd", r"pwd", r"pass", r"secret"],
        FieldType.PHONE: [r"phone", r"tel", r"mobile", r"cell", r"fax"],
        FieldType.USERNAME: [r"username", r"user_name", r"user", r"login", r"account"],
        FieldType.NAME: [r"name", r"fullname", r"full_name", r"firstname", r"lastname", r"first_name", r"last_name"],
        FieldType.ADDRESS: [r"address", r"street", r"addr"],
        FieldType.CITY: [r"city", r"town"],
        FieldType.STATE: [r"state", r"province", r"region"],
        FieldType.COUNTRY: [r"country", r"nation"],
        FieldType.ZIPCODE: [r"zip", r"postal", r"postcode", r"zip_code"],
        FieldType.CARD_NUMBER: [r"card", r"cc_number", r"card_number", r"cardnumber"],
        FieldType.CVV: [r"cvv", r"cvc", r"security_code", r"card_code"],
        FieldType.EXPIRY: [r"expir", r"exp_date", r"expiry", r"exp_month", r"exp_year"],
        FieldType.AMOUNT: [r"amount", r"total", r"price", r"cost", r"value"],
        FieldType.QUANTITY: [r"quantity", r"qty", r"count", r"num"],
        FieldType.COMMENT: [r"comment", r"message", r"description", r"content", r"body", r"text", r"note"],
        FieldType.SEARCH: [r"search", r"query", r"q", r"keyword", r"term"],
        FieldType.URL: [r"url", r"website", r"link", r"href", r"redirect", r"return", r"next"],
        FieldType.DATE: [r"date", r"birth", r"dob"],
        FieldType.ID: [r"^id$", r"_id$", r"^.*_id$", r"^.*id$"],
        FieldType.CSRF: [r"csrf", r"token", r"_token", r"nonce", r"authenticity", r"verification"],
    }

    # Valid placeholder values by type
    TYPE_PLACEHOLDERS: Dict[FieldType, str] = {
        FieldType.TEXT: "TestValue",
        FieldType.EMAIL: "test@example.com",
        FieldType.PASSWORD: "Test1234!",
        FieldType.PHONE: "+1234567890",
        FieldType.URL: "https://example.com",
        FieldType.NUMBER: "100",
        FieldType.INTEGER: "42",
        FieldType.FLOAT: "99.99",
        FieldType.DATE: "2024-01-15",
        FieldType.DATETIME: "2024-01-15T10:30:00",
        FieldType.TIME: "10:30",
        FieldType.USERNAME: "testuser",
        FieldType.NAME: "John Doe",
        FieldType.ADDRESS: "123 Test Street",
        FieldType.CITY: "New York",
        FieldType.STATE: "NY",
        FieldType.COUNTRY: "US",
        FieldType.ZIPCODE: "10001",
        FieldType.CARD_NUMBER: "4111111111111111",
        FieldType.CVV: "123",
        FieldType.EXPIRY: "12/25",
        FieldType.AMOUNT: "100.00",
        FieldType.QUANTITY: "1",
        FieldType.COMMENT: "Test comment",
        FieldType.SEARCH: "test",
        FieldType.ID: "1",
        FieldType.SELECT: "",  # Use first option
        FieldType.CHECKBOX: "on",
        FieldType.RADIO: "",  # Use first option
        FieldType.TEXTAREA: "Test content for textarea field.",
        FieldType.HIDDEN: "",  # Keep original
        FieldType.CSRF: "",  # Keep original
        FieldType.UNKNOWN: "test",
    }

    # Field dependencies (field → depends on)
    FIELD_DEPENDENCIES = {
        "state": "country",
        "province": "country",
        "city": "state",
        "zipcode": "city",
        "zip_code": "city",
        "postal_code": "city",
    }

    def __init__(self):
        """Initialize form context preserver."""
        self._form_cache: Dict[str, FormDefinition] = {}
        self._learned_values: Dict[str, Dict[str, str]] = {}  # URL → field → valid value

    def analyze_form(self, html: str, form_url: str) -> Optional[FormDefinition]:
        """
        Analyze HTML to extract form definition.

        Args:
            html: HTML content containing the form
            form_url: URL where the form was found

        Returns:
            FormDefinition or None if no form found
        """
        # Find forms
        form_pattern = r'<form([^>]*)>(.*?)</form>'
        form_matches = list(re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE))

        if not form_matches:
            logger.debug(f"[FORM_CONTEXT] No forms found at {form_url}")
            return None

        # Use first form (or could be enhanced to handle multiple)
        form_match = form_matches[0]
        form_attrs = form_match.group(1)
        form_body = form_match.group(2)

        # Extract form attributes
        action = self._extract_attr(form_attrs, "action") or form_url
        method = self._extract_attr(form_attrs, "method") or "POST"
        enctype = self._extract_attr(form_attrs, "enctype") or "application/x-www-form-urlencoded"

        # Extract fields
        fields = self._extract_fields(form_body)

        # Find submit button
        submit_name, submit_value = self._find_submit_button(form_body)

        # Find CSRF field
        csrf_name = self._find_csrf_field(fields)

        form_def = FormDefinition(
            action=action,
            method=method.upper(),
            enctype=enctype,
            fields=fields,
            submit_button=submit_name,
            submit_value=submit_value,
            csrf_field_name=csrf_name,
            discovered_from=form_url,
        )

        # Cache for later
        self._form_cache[form_url] = form_def

        logger.debug(
            f"[FORM_CONTEXT] Analyzed form at {form_url}: "
            f"{len(fields)} fields, action={action}, method={method}"
        )

        return form_def

    def _extract_attr(self, attrs: str, name: str) -> Optional[str]:
        """Extract attribute value from HTML tag attributes."""
        pattern = rf'{name}\s*=\s*["\']([^"\']+)["\']'
        match = re.search(pattern, attrs, re.IGNORECASE)
        return match.group(1) if match else None

    def _extract_fields(self, form_body: str) -> List[FieldDefinition]:
        """Extract all fields from form body."""
        fields = []

        # Input fields
        input_pattern = r'<input([^>]*)/?>'
        for match in re.finditer(input_pattern, form_body, re.IGNORECASE):
            attrs = match.group(1)
            field_def = self._parse_input_field(attrs)
            if field_def:
                fields.append(field_def)

        # Select fields
        select_pattern = r'<select([^>]*)>(.*?)</select>'
        for match in re.finditer(select_pattern, form_body, re.DOTALL | re.IGNORECASE):
            attrs = match.group(1)
            options_html = match.group(2)
            field_def = self._parse_select_field(attrs, options_html)
            if field_def:
                fields.append(field_def)

        # Textarea fields
        textarea_pattern = r'<textarea([^>]*)>(.*?)</textarea>'
        for match in re.finditer(textarea_pattern, form_body, re.DOTALL | re.IGNORECASE):
            attrs = match.group(1)
            content = match.group(2).strip()
            field_def = self._parse_textarea_field(attrs, content)
            if field_def:
                fields.append(field_def)

        return fields

    def _parse_input_field(self, attrs: str) -> Optional[FieldDefinition]:
        """Parse input field attributes."""
        name = self._extract_attr(attrs, "name")
        if not name:
            return None

        input_type = self._extract_attr(attrs, "type") or "text"
        value = self._extract_attr(attrs, "value")
        placeholder = self._extract_attr(attrs, "placeholder")
        required = "required" in attrs.lower()
        min_length = self._extract_attr(attrs, "minlength")
        max_length = self._extract_attr(attrs, "maxlength")
        pattern = self._extract_attr(attrs, "pattern")

        # Detect field type
        field_type = self._detect_field_type(name, input_type)

        # Check if injectable
        is_injectable = field_type not in (FieldType.HIDDEN, FieldType.CSRF)
        is_csrf = field_type == FieldType.CSRF or self._is_csrf_field(name)

        # Handle hidden fields
        if input_type == "hidden":
            field_type = FieldType.HIDDEN
            is_injectable = not is_csrf  # Hidden fields can be injectable unless CSRF

        return FieldDefinition(
            name=name,
            field_type=field_type,
            is_required=required,
            min_length=int(min_length) if min_length else None,
            max_length=int(max_length) if max_length else None,
            pattern=pattern,
            default_value=value,
            placeholder=placeholder,
            is_injectable=is_injectable,
            is_csrf=is_csrf,
        )

    def _parse_select_field(self, attrs: str, options_html: str) -> Optional[FieldDefinition]:
        """Parse select field and extract options."""
        name = self._extract_attr(attrs, "name")
        if not name:
            return None

        required = "required" in attrs.lower()

        # Extract options
        options = []
        option_pattern = r'<option[^>]*value=["\']([^"\']*)["\'][^>]*>'
        for match in re.finditer(option_pattern, options_html, re.IGNORECASE):
            options.append(match.group(1))

        # Get selected/default value
        selected_pattern = r'<option[^>]*selected[^>]*value=["\']([^"\']*)["\']'
        selected = re.search(selected_pattern, options_html, re.IGNORECASE)
        default_value = selected.group(1) if selected else (options[0] if options else None)

        # Detect field type
        field_type = self._detect_field_type(name, "select")

        return FieldDefinition(
            name=name,
            field_type=field_type,
            is_required=required,
            options=options,
            default_value=default_value,
            is_injectable=True,
        )

    def _parse_textarea_field(self, attrs: str, content: str) -> Optional[FieldDefinition]:
        """Parse textarea field."""
        name = self._extract_attr(attrs, "name")
        if not name:
            return None

        required = "required" in attrs.lower()
        placeholder = self._extract_attr(attrs, "placeholder")
        max_length = self._extract_attr(attrs, "maxlength")

        field_type = self._detect_field_type(name, "textarea")

        return FieldDefinition(
            name=name,
            field_type=field_type,
            is_required=required,
            max_length=int(max_length) if max_length else None,
            default_value=content if content else None,
            placeholder=placeholder,
            is_injectable=True,
        )

    def _find_submit_button(self, form_body: str) -> Tuple[Optional[str], Optional[str]]:
        """Find submit button name and value."""
        # Look for input type=submit
        submit_pattern = r'<input[^>]+type=["\']submit["\'][^>]*>'
        match = re.search(submit_pattern, form_body, re.IGNORECASE)
        if match:
            name = self._extract_attr(match.group(0), "name")
            value = self._extract_attr(match.group(0), "value")
            return name, value

        # Look for button type=submit
        button_pattern = r'<button[^>]+type=["\']submit["\'][^>]*name=["\']([^"\']+)["\'][^>]*>([^<]*)</button>'
        match = re.search(button_pattern, form_body, re.IGNORECASE)
        if match:
            return match.group(1), match.group(2).strip()

        return None, None

    def _find_csrf_field(self, fields: List[FieldDefinition]) -> Optional[str]:
        """Find CSRF token field name."""
        for f in fields:
            if f.is_csrf:
                return f.name
        return None

    def _detect_field_type(self, name: str, input_type: str) -> FieldType:
        """Detect field type from name and HTML input type."""
        name_lower = name.lower()

        # Check HTML5 input types
        type_mapping = {
            "email": FieldType.EMAIL,
            "tel": FieldType.PHONE,
            "url": FieldType.URL,
            "number": FieldType.NUMBER,
            "date": FieldType.DATE,
            "datetime-local": FieldType.DATETIME,
            "time": FieldType.TIME,
            "password": FieldType.PASSWORD,
            "hidden": FieldType.HIDDEN,
            "checkbox": FieldType.CHECKBOX,
            "radio": FieldType.RADIO,
            "file": FieldType.FILE,
        }

        if input_type in type_mapping:
            return type_mapping[input_type]

        # Check name patterns
        for field_type, patterns in self.FIELD_TYPE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, name_lower):
                    return field_type

        return FieldType.UNKNOWN

    def _is_csrf_field(self, name: str) -> bool:
        """Check if field name indicates CSRF token."""
        name_lower = name.lower()
        csrf_indicators = [
            "csrf", "token", "_csrf", "csrftoken", "authenticity_token",
            "_token", "user_token", "nonce", "verification", "__requestverificationtoken"
        ]
        return any(ind in name_lower for ind in csrf_indicators)

    def get_test_data(
        self,
        form: FormDefinition,
        target_field: str,
        injection_payload: str,
        csrf_token: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Get form data with valid values for all fields except target.

        Args:
            form: Form definition
            target_field: Field to inject into
            injection_payload: Payload to inject
            csrf_token: Current CSRF token value (if needed)

        Returns:
            Dict with all form fields, target field has payload
        """
        data = {}

        for field_def in form.fields:
            if field_def.name == target_field:
                # Use injection payload for target field
                data[field_def.name] = injection_payload
            elif field_def.is_csrf and csrf_token:
                # Use provided CSRF token
                data[field_def.name] = csrf_token
            elif field_def.is_csrf and field_def.default_value:
                # Use default CSRF value
                data[field_def.name] = field_def.default_value
            else:
                # Use valid placeholder value
                data[field_def.name] = self._get_valid_value(field_def, form)

        # Add submit button
        if form.submit_button and form.submit_value:
            data[form.submit_button] = form.submit_value

        return data

    def _get_valid_value(self, field_def: FieldDefinition, form: FormDefinition) -> str:
        """Get a valid value for a field."""
        # 1. Use default value if present
        if field_def.default_value:
            return field_def.default_value

        # 2. Use learned value if available
        cache_key = f"{form.discovered_from}:{field_def.name}"
        if cache_key in self._learned_values:
            return self._learned_values[cache_key]

        # 3. Use first option for select/radio
        if field_def.options:
            return field_def.options[0]

        # 4. Use type-specific placeholder
        value = self.TYPE_PLACEHOLDERS.get(field_def.field_type, "test")

        # 5. Respect constraints
        if field_def.min_length and len(value) < field_def.min_length:
            value = value + "x" * (field_def.min_length - len(value))

        if field_def.max_length and len(value) > field_def.max_length:
            value = value[:field_def.max_length]

        return value

    def learn_valid_value(
        self,
        form_url: str,
        field_name: str,
        valid_value: str,
    ) -> None:
        """
        Learn a valid value for a field (from successful submissions).

        Args:
            form_url: URL of the form
            field_name: Field name
            valid_value: Known-good value
        """
        if form_url not in self._learned_values:
            self._learned_values[form_url] = {}

        self._learned_values[form_url][field_name] = valid_value
        logger.debug(
            f"[FORM_CONTEXT] Learned valid value for {field_name} at {form_url}"
        )

    def get_multi_field_test_sequence(
        self,
        form: FormDefinition,
        payloads: List[str],
        csrf_token: Optional[str] = None,
    ) -> List[Tuple[str, Dict[str, str]]]:
        """
        Generate test data for all injectable fields with all payloads.

        Args:
            form: Form definition
            payloads: List of injection payloads to test
            csrf_token: Current CSRF token

        Returns:
            List of (target_field, form_data) tuples
        """
        tests = []

        injectable_fields = form.get_injectable_fields()

        for field_def in injectable_fields:
            for payload in payloads:
                test_data = self.get_test_data(
                    form=form,
                    target_field=field_def.name,
                    injection_payload=payload,
                    csrf_token=csrf_token,
                )
                tests.append((field_def.name, test_data))

        return tests

    def encode_form_data(
        self,
        data: Dict[str, str],
        enctype: str = "application/x-www-form-urlencoded",
    ) -> Tuple[str, Dict[str, str]]:
        """
        Encode form data for submission.

        Args:
            data: Form data dict
            enctype: Form encoding type

        Returns:
            (encoded_data, headers) tuple
        """
        if enctype == "application/x-www-form-urlencoded":
            return urlencode(data), {"Content-Type": enctype}

        elif enctype == "application/json":
            return json.dumps(data), {"Content-Type": enctype}

        elif "multipart/form-data" in enctype:
            # For multipart, return raw dict and let client handle boundary
            return data, {}  # type: ignore

        else:
            return urlencode(data), {"Content-Type": "application/x-www-form-urlencoded"}

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of preserved contexts."""
        return {
            "forms_cached": len(self._form_cache),
            "learned_values": sum(len(v) for v in self._learned_values.values()),
            "forms": [
                {
                    "url": url,
                    "fields": len(form.fields),
                    "injectable": len(form.get_injectable_fields()),
                }
                for url, form in self._form_cache.items()
            ],
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def analyze_and_preserve(
    html: str,
    form_url: str,
    preserver: Optional[FormContextPreserver] = None,
) -> Optional[FormDefinition]:
    """
    Quick function to analyze form and preserve context.

    Args:
        html: HTML content
        form_url: URL of the form
        preserver: Optional existing preserver to use

    Returns:
        FormDefinition or None
    """
    if preserver is None:
        preserver = FormContextPreserver()

    return preserver.analyze_form(html, form_url)


def get_sqli_test_data(
    form: FormDefinition,
    target_field: str,
    csrf_token: Optional[str] = None,
) -> List[Dict[str, str]]:
    """
    Get test data for common SQLi payloads.

    Args:
        form: Form definition
        target_field: Field to test
        csrf_token: CSRF token if needed

    Returns:
        List of form data dicts with different SQLi payloads
    """
    preserver = FormContextPreserver()

    sqli_payloads = [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "' UNION SELECT NULL--",
        "'; DROP TABLE test--",
        "1 OR 1=1",
        "1' ORDER BY 1--",
    ]

    return [
        preserver.get_test_data(form, target_field, payload, csrf_token)
        for payload in sqli_payloads
    ]


def get_xss_test_data(
    form: FormDefinition,
    target_field: str,
    csrf_token: Optional[str] = None,
) -> List[Dict[str, str]]:
    """
    Get test data for common XSS payloads.

    Args:
        form: Form definition
        target_field: Field to test
        csrf_token: CSRF token if needed

    Returns:
        List of form data dicts with different XSS payloads
    """
    preserver = FormContextPreserver()

    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "'-alert(1)-'",
        "\"><script>alert(1)</script>",
        "{{constructor.constructor('alert(1)')()}}",
        "<body onload=alert(1)>",
    ]

    return [
        preserver.get_test_data(form, target_field, payload, csrf_token)
        for payload in xss_payloads
    ]
