import hashlib


def _hash_identity_segment(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()
