"""
RFC 6901 JSON Pointer implementation and bidirectional resolver.
Guarantees standards compliance for evidence pointers.
"""

from typing import Any, List, Union


def escape_rfc6901_token(token: Union[str, int]) -> str:
    """
    Escapes a token according to RFC 6901:
    '~' is replaced by '~0'
    '/' is replaced by '~1'
    """
    s = str(token)
    return s.replace("~", "~0").replace("/", "~1")


def unescape_rfc6901_token(token: str) -> str:
    """
    Unescapes an RFC 6901 token:
    '~1' is replaced by '/'
    '~0' is replaced by '~'
    """
    return token.replace("~1", "/").replace("~0", "~")


def build_rfc6901_pointer(tokens: List[Union[str, int]]) -> str:
    """
    Builds an RFC 6901 pointer string from a sequence of keys/indices.
    Example: ['behavior', 'dropped', 0] -> '/behavior/dropped/0'
    """
    if not tokens:
        return ""
    escaped_tokens = [escape_rfc6901_token(t) for t in tokens]
    return "/" + "/".join(escaped_tokens)


def resolve_json_pointer(doc: Any, pointer: str) -> Any:
    """
    Resolves an RFC 6901 JSON pointer against a JSON-like Python dict/list structure.
    Raises ValueError, KeyError, or IndexError if path cannot be resolved.
    """
    if pointer == "" or pointer is None:
        return doc

    if not pointer.startswith("/"):
        raise ValueError(f"Invalid RFC 6901 JSON Pointer '{pointer}': Must start with '/' or be empty")

    parts = pointer[1:].split("/")
    current = doc

    for idx, raw_part in enumerate(parts):
        token = unescape_rfc6901_token(raw_part)
        if isinstance(current, dict):
            if token not in current:
                raise KeyError(f"Key '{token}' not found at step {idx} for pointer '{pointer}'")
            current = current[token]
        elif isinstance(current, list):
            try:
                index = int(token)
            except ValueError:
                raise IndexError(f"Expected integer index for list at step {idx}, got '{token}' in '{pointer}'")
            if index < 0 or index >= len(current):
                raise IndexError(f"List index {index} out of bounds (len={len(current)}) in pointer '{pointer}'")
            current = current[index]
        else:
            raise ValueError(f"Cannot traverse into primitive {type(current)} at step {idx} for pointer '{pointer}'")

    return current
