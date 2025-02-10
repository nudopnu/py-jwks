import base64

def base64url_encode(data: bytes) -> str:
    """Base64 URL encode without padding."""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def big_endian_encode(number: int) -> bytes:
    """Encode as big endian bytes"""
    byte_length = (number.bit_length() + 7) // 8
    return number.to_bytes(byte_length, byteorder="big")
