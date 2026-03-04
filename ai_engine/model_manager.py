"""
Model Manager for Ollama integration.
Handles LLM communication with retry and error handling.

SECURITY: Implements response validation to prevent AI response injection attacks.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any, AsyncIterator

import httpx
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


# =============================================================================
# RESPONSE VALIDATION - Security against AI response injection
# =============================================================================

# Maximum depth for nested JSON structures (prevents stack overflow)
MAX_JSON_DEPTH = 20

# Maximum string length for individual values (prevents memory exhaustion)
MAX_STRING_LENGTH = 100_000

# Maximum number of items in arrays/objects (prevents memory exhaustion)
MAX_COLLECTION_SIZE = 1000

# Dangerous patterns that should never appear in AI responses used as code/commands
DANGEROUS_PATTERNS = [
    r'os\.system\s*\(',
    r'subprocess\.',
    r'eval\s*\(',
    r'exec\s*\(',
    r'__import__\s*\(',
    r'open\s*\([^)]*[\'"]w',  # Writing files
    r'rm\s+-rf',
    r'curl\s+.*\|.*sh',
    r'wget\s+.*\|.*sh',
]


class ResponseValidationError(Exception):
    """Raised when AI response fails validation."""
    pass


class ModelError(Exception):
    """Error communicating with model."""
    pass


def _validate_json_depth(obj: Any, current_depth: int = 0) -> None:
    """
    Validate JSON structure doesn't exceed maximum depth.

    SECURITY: Prevents stack overflow attacks via deeply nested structures.
    """
    if current_depth > MAX_JSON_DEPTH:
        raise ResponseValidationError(
            f"JSON structure exceeds maximum depth of {MAX_JSON_DEPTH}"
        )

    if isinstance(obj, dict):
        if len(obj) > MAX_COLLECTION_SIZE:
            raise ResponseValidationError(
                f"Object has {len(obj)} keys, exceeds maximum of {MAX_COLLECTION_SIZE}"
            )
        for value in obj.values():
            _validate_json_depth(value, current_depth + 1)
    elif isinstance(obj, list):
        if len(obj) > MAX_COLLECTION_SIZE:
            raise ResponseValidationError(
                f"Array has {len(obj)} items, exceeds maximum of {MAX_COLLECTION_SIZE}"
            )
        for item in obj:
            _validate_json_depth(item, current_depth + 1)
    elif isinstance(obj, str):
        if len(obj) > MAX_STRING_LENGTH:
            raise ResponseValidationError(
                f"String length {len(obj)} exceeds maximum of {MAX_STRING_LENGTH}"
            )


def _check_dangerous_patterns(text: str) -> list[str]:
    """
    Check for dangerous patterns in text.

    SECURITY: Detects potential code injection attempts in AI responses.

    Returns:
        List of matched dangerous patterns (empty if none found)
    """
    found = []
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            found.append(pattern)
    return found


def validate_ai_response(
    data: dict[str, Any],
    schema: dict[str, Any] | None = None,
    check_dangerous: bool = True,
) -> dict[str, Any]:
    """
    Validate AI response against security constraints and optional schema.

    SECURITY: Comprehensive validation to prevent AI response injection attacks.

    Args:
        data: Parsed JSON response from AI
        schema: Optional schema defining expected structure:
                {
                    "required_fields": ["field1", "field2"],
                    "field_types": {"field1": str, "field2": list},
                    "allowed_fields": ["field1", "field2", "optional"],
                }
        check_dangerous: Check for dangerous code patterns

    Returns:
        Validated data dict

    Raises:
        ResponseValidationError: If validation fails
    """
    # Validate structure depth and size
    _validate_json_depth(data)

    # Check for dangerous patterns in string values
    if check_dangerous:
        def check_strings(obj: Any) -> None:
            if isinstance(obj, str):
                dangerous = _check_dangerous_patterns(obj)
                if dangerous:
                    logger.warning(
                        f"Dangerous patterns detected in AI response: {dangerous}"
                    )
                    # Log but don't raise - the patterns might be in security findings
            elif isinstance(obj, dict):
                for v in obj.values():
                    check_strings(v)
            elif isinstance(obj, list):
                for item in obj:
                    check_strings(item)

        check_strings(data)

    # Validate against schema if provided
    if schema:
        # Check required fields
        required = schema.get("required_fields", [])
        for field in required:
            if field not in data:
                raise ResponseValidationError(
                    f"Missing required field: {field}"
                )

        # Check field types
        field_types = schema.get("field_types", {})
        for field, expected_type in field_types.items():
            if field in data and not isinstance(data[field], expected_type):
                actual_type = type(data[field]).__name__
                raise ResponseValidationError(
                    f"Field '{field}' has type {actual_type}, expected {expected_type.__name__}"
                )

        # Check for unexpected fields (if allowed_fields specified)
        allowed = schema.get("allowed_fields")
        if allowed is not None:
            for field in data:
                if field not in allowed:
                    logger.warning(f"Unexpected field in AI response: {field}")

    return data


class ModelManager:
    """
    Manages communication with Ollama LLM.
    
    Features:
    - Async API calls
    - Retry with exponential backoff
    - Streaming support
    - Token counting
    - Response parsing
    """
    
    def __init__(self, settings: Settings) -> None:
        """
        Initialize model manager.
        
        Args:
            settings: Application settings
        """
        self.settings = settings
        self.config = settings.ai
        
        self.base_url = self.config.base_url
        self.model = self.config.model
        self.timeout = self.config.timeout
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
    )
    async def generate(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> str:
        """
        Generate text completion.
        
        Args:
            prompt: User prompt
            system: System prompt
            temperature: Override temperature
            max_tokens: Maximum tokens to generate
            json_mode: Request JSON output
            
        Returns:
            Generated text
        """
        temperature = temperature if temperature is not None else self.config.temperature
        max_tokens = max_tokens or self.config.max_tokens
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        
        if system:
            payload["system"] = system
        
        if json_mode:
            payload["format"] = "json"
        
        logger.debug(f"Generating with model {self.model}")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/api/generate",
                json=payload,
            )
            
            if response.status_code != 200:
                raise ModelError(f"Model returned status {response.status_code}")
            
            data = response.json()
            return data.get("response", "")
    
    async def generate_stream(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float | None = None,
    ) -> AsyncIterator[str]:
        """
        Stream text generation.
        
        Args:
            prompt: User prompt
            system: System prompt
            temperature: Override temperature
            
        Yields:
            Generated text chunks
        """
        temperature = temperature if temperature is not None else self.config.temperature
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": True,
            "options": {
                "temperature": temperature,
            },
        }
        
        if system:
            payload["system"] = system
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/api/generate",
                json=payload,
            ) as response:
                async for line in response.aiter_lines():
                    if line:
                        try:
                            data = json.loads(line)
                            if chunk := data.get("response"):
                                yield chunk
                        except json.JSONDecodeError:
                            continue
    
    async def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float | None = None,
        json_mode: bool = False,
    ) -> str:
        """
        Chat completion with message history.
        
        Args:
            messages: List of {"role": "user/assistant/system", "content": "..."}
            temperature: Override temperature
            json_mode: Request JSON output
            
        Returns:
            Assistant response
        """
        temperature = temperature if temperature is not None else self.config.temperature
        
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }
        
        if json_mode:
            payload["format"] = "json"
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/api/chat",
                json=payload,
            )
            
            if response.status_code != 200:
                raise ModelError(f"Model returned status {response.status_code}")
            
            data = response.json()
            return data.get("message", {}).get("content", "")
    
    async def embed(self, text: str) -> list[float]:
        """
        Generate embedding for text.
        
        Args:
            text: Text to embed
            
        Returns:
            Embedding vector
        """
        payload = {
            "model": self.config.embedding_model,
            "prompt": text,
        }
        
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(
                f"{self.base_url}/api/embeddings",
                json=payload,
            )
            
            if response.status_code != 200:
                raise ModelError(f"Embedding failed with status {response.status_code}")
            
            data = response.json()
            return data.get("embedding", [])
    
    async def health_check(self) -> bool:
        """Check if model is available."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                return response.status_code == 200
        except Exception:
            return False
    
    async def list_models(self) -> list[str]:
        """List available models."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                
                if response.status_code == 200:
                    data = response.json()
                    return [m["name"] for m in data.get("models", [])]
        except Exception as e:
            # FIX 2026-02-12: Log model listing error
            logger.debug(f"[ModelManager] Error listing models: {e}")

        return []
    
    def parse_json_response(
        self,
        response: str,
        schema: dict[str, Any] | None = None,
        validate: bool = True,
    ) -> dict[str, Any]:
        """
        Parse and validate JSON from model response.

        SECURITY: Validates response structure to prevent AI response injection.

        Handles markdown code blocks and cleaning.

        Args:
            response: Raw model response
            schema: Optional schema for validation:
                    {
                        "required_fields": ["field1"],
                        "field_types": {"field1": str},
                        "allowed_fields": ["field1", "field2"],
                    }
            validate: Whether to perform security validation (default: True)

        Returns:
            Parsed and validated JSON dict

        Raises:
            ResponseValidationError: If validation fails (when validate=True)
        """
        # Clean markdown code blocks
        text = response.strip()

        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]

        text = text.strip()

        # Limit input size before parsing
        if len(text) > MAX_STRING_LENGTH * 10:
            logger.warning("AI response exceeds maximum size limit")
            return {}

        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON response: {e}")
            return {}

        # Validate if enabled
        if validate and isinstance(data, dict):
            try:
                return validate_ai_response(data, schema=schema)
            except ResponseValidationError as e:
                logger.warning(f"AI response validation failed: {e}")
                return {}

        return data if isinstance(data, dict) else {}
