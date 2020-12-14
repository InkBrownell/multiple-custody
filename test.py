import pytest
from Crypto.Random import get_random_bytes

from main import EncryptedShare


def test_empty_decode():
    with pytest.raises(ValueError):
        EncryptedShare.decode([])


class TestInvalidEncode:
    def test_empty_encode(self):
        with pytest.raises(ValueError):
            EncryptedShare.encode('abc', {})

    def test_double_encode(self):
        with pytest.raises(ValueError):
            EncryptedShare.encode('abc', {'any': ['a'], 'all': ['b']})


def test_single_custody():
    secret = get_random_bytes(16)
    schema = {'any': ['a']}
    result = EncryptedShare.decode(EncryptedShare.encode(secret, schema))
    assert result == secret


def test_any_copies():
    secret = get_random_bytes(16)
    schema = {'any': ['a', 'b', 'c', 'd']}
    shares = EncryptedShare.encode(secret, schema)
    for share in shares:
        result = EncryptedShare.decode([share])
        assert result == secret


def test_all_copies():
    secret = get_random_bytes(16)
    schema = {'any': ['a', 'b', 'c', 'd']}
    shares = EncryptedShare.encode(secret, schema)
    result = EncryptedShare.decode(shares)
    assert result == secret


def test_insufficient_copies():
    secret = get_random_bytes(16)
    schema = {'all': ['a', 'b', 'c', 'd']}
    shares = EncryptedShare.encode(secret, schema)
    for share in shares:
        with pytest.raises(ValueError):
            EncryptedShare.decode([share])
    with pytest.raises(ValueError):
        EncryptedShare.decode(shares[:3])
