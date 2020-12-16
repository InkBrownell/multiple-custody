import pytest
from Crypto.Random import get_random_bytes

from main import EncryptedShare


def test_empty_decode():
    with pytest.raises(ValueError):
        EncryptedShare.decode([])


class TestInvalidEncode:
    def test_empty_encode(self):
        secret = get_random_bytes(16)
        with pytest.raises(ValueError):
            EncryptedShare.encode(secret, {})

    def test_double_encode(self):
        secret = get_random_bytes(16)
        with pytest.raises(ValueError):
            EncryptedShare.encode(secret, {'any': ['a'], 'all': ['b']})

    def test_bad_key(self):
        secret = get_random_bytes(16)
        schema = {'does not exist': ['a', 'b', 'c', 'd']}
        with pytest.raises(ValueError):
            EncryptedShare.encode(secret, schema)

    def test_value_not_list(self):
        secret = get_random_bytes(16)
        schema = {'any': 'haha I\'m not a list, I fooled you!'}
        with pytest.raises(ValueError):
            EncryptedShare.encode(secret, schema)

    def test_value_empty_list(self):
        secret = get_random_bytes(16)
        schema = {'any': []}
        with pytest.raises(ValueError):
            EncryptedShare.encode(secret, schema)

    def test_schema_not_dict(self):
        secret = get_random_bytes(16)
        schema = 'don\'t tell them I\'m not a dictionary'
        with pytest.raises(ValueError):
            EncryptedShare.encode(secret, schema)

    def test_insufficient_at_least(self):
        secret = get_random_bytes(16)
        schema = {'at least 3': ['a']}
        with pytest.raises(ValueError):
            EncryptedShare.encode(secret, schema)

    def test_invalid_minimum(self):
        secret = get_random_bytes(16)
        schema = {'at least -3': ['a', 'b', 'c']}
        with pytest.raises(ValueError):
            EncryptedShare.encode(secret, schema)

    def test_invalid_value_entry(self):
        secret = get_random_bytes(16)
        schema = {'any': ['a', ['b', 'd', 'e'], 'c']}
        with pytest.raises(ValueError):
            EncryptedShare.encode(secret, schema)


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


def test_nested_any():
    secret = get_random_bytes(16)
    schema = {
        'any': [
            'a',
            'b',
            'c',
            {'any': ['d', 'e', 'f']}
        ]
    }
    shares = EncryptedShare.encode(secret, schema)
    for share in shares:
        result = EncryptedShare.decode([share])
        assert result == secret


def test_any_and_any():
    secret = get_random_bytes(16)
    schema = {
        'all': [
            {'any': ['a', 'b', 'c']},
            {'any': ['d', 'e', 'f']}
        ]
    }
    shares = EncryptedShare.encode(secret, schema)
    shares_by_name = {share.name: share for share in shares}
    with pytest.raises(ValueError):
        EncryptedShare.decode([shares_by_name['a']])
    with pytest.raises(ValueError):
        EncryptedShare.decode([shares_by_name['a'], shares_by_name['b']])
    with pytest.raises(ValueError):
        EncryptedShare.decode([shares_by_name['a'], shares_by_name['b'], shares_by_name['c']])

    result = EncryptedShare.decode([shares_by_name['b'], shares_by_name['e']])
    assert result == secret


def test_at_least():
    secret = get_random_bytes(16)
    schema = {
        'at least 2': [
            {'any': ['a', 'b', 'c']},
            {'any': ['d', 'e', 'f']},
            {'any': ['g', 'h', 'i']}
        ]
    }
    shares = EncryptedShare.encode(secret, schema)
    shares_by_name = {share.name: share for share in shares}
    with pytest.raises(ValueError):
        EncryptedShare.decode([shares_by_name['a']])
    with pytest.raises(ValueError):
        EncryptedShare.decode([shares_by_name['a'], shares_by_name['b']])
    with pytest.raises(ValueError):
        EncryptedShare.decode([shares_by_name['a'], shares_by_name['b'], shares_by_name['c']])

    result = EncryptedShare.decode([shares_by_name['b'], shares_by_name['e']])
    assert result == secret
    result = EncryptedShare.decode([shares_by_name['f'], shares_by_name['g']])
    assert result == secret
    result = EncryptedShare.decode([shares_by_name['i'], shares_by_name['a']])
    assert result == secret


def test_mismatched_schema():
    secret = get_random_bytes(16)
    schema1 = {
        'all': ['a', 'b', 'c']
    }
    schema2 = {
        'at least 2': ['a', 'b', 'c']
    }
    shares1 = EncryptedShare.encode(secret, schema1)
    shares2 = EncryptedShare.encode(secret, schema2)

    with pytest.raises(ValueError):
        EncryptedShare.decode([shares1[0], shares2[0]])


def test_same_schema_different_secret():
    secret1 = get_random_bytes(16)
    secret2 = get_random_bytes(16)
    schema = {
        'at least 2': ['a', 'b', 'c']
    }
    shares1 = EncryptedShare.encode(secret1, schema)
    shares2 = EncryptedShare.encode(secret2, schema)

    with pytest.raises(ValueError):
        EncryptedShare.decode([shares1[0], shares2[0]])


def test_complicated_schema():
    secret = get_random_bytes(16)
    schema = {
        'any': [
            {'at least 2': ['a', 'b', 'c']},
            {'all': [
                'a',
                {'at least 5': ['d', 'e', 'f', 'g', 'h', 'i', 'j']}
            ]}
        ]
    }
    shares = EncryptedShare.encode(secret, schema)
    shares_by_name = {share.name: share for share in shares}

    result = EncryptedShare.decode([shares_by_name['a'], shares_by_name['c']])
    assert result == secret

    result = EncryptedShare.decode([
        shares_by_name['a'],
        shares_by_name['f'],
        shares_by_name['g'],
        shares_by_name['e'],
        shares_by_name['j'],
        shares_by_name['i']
    ])
    assert result == secret
