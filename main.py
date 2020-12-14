"""Contains EncryptedShare"""
from typing import List

from Crypto.Hash import SHA3_256
from Crypto.Protocol.SecretSharing import Shamir


class EncryptedShare:
    """An object representing a single SSSS share."""
    def __init__(self, name, ciphertext, schema, hashed_plaintext):
        self.name = name
        self.ciphertext = ciphertext
        self.schema = schema
        self.hashed_plaintext = hashed_plaintext

    @classmethod
    def encode(cls, plaintext, schema):
        """Encode a given secret according to a given schema.

        :param plaintext: The data to hide
        :param schema: The way the data should be encoded
        :returns: A list of encrypted shares
        :rtype: List[EncryptedShare]"""
        if len(schema) != 1:
            raise ValueError('Schema must have exactly one top level expression')

        if (lst := schema.get('any')) or (lst := schema.get('or')):
            threshold = 1
            num_shares = len(lst)
        elif (lst := schema.get('all')) or (lst := schema.get('and')):
            threshold = num_shares = len(lst)
        else:
            raise ValueError(f'Unknown keyword: "{schema.keys()[0]}"')

        shares = Shamir.split(threshold, num_shares, plaintext)

        hashed_plaintext = SHA3_256.new(plaintext).hexdigest()
        return [
            EncryptedShare(
                name=id,
                ciphertext=share,
                schema=schema,
                hashed_plaintext=hashed_plaintext
            )
            for id, share in zip(lst, shares)
        ]

    @staticmethod
    def decode(shares):
        """Recover the plaintext from a list of shares.

        :param shares: A list of shares
        :type shares: List[EncryptedShare]
        :returns: The decrypted plaintext
        :rtype: bytes"""
        if len(shares) == 0:
            raise ValueError('You must have at least one share!')
        if not EncryptedShare.satisfies(shares):
            raise ValueError('You do not have enough shares to decrypt this message.')
        return Shamir.combine([share.ciphertext for share in shares])

    @staticmethod
    def satisfies(shares):
        """Check whether a set of shares satisfies their schemas.

        :param shares: A collection of shares
        :type shares: List[EncryptedShare]
        :returns: A boolean indicating whether these shares are sufficient to decrypt the secret
        :rtype: bool"""
        schema = shares[0].schema
        hashed_plaintext = shares[0].hashed_plaintext
        ids = set()
        for share in shares:
            if share.schema != schema:
                raise ValueError(
                    f'Share "{share.name}" does not have the same schema as'
                    f' share "{shares[0].name}". All shares must have the same'
                    f' schema!'
                )
            if share.hashed_plaintext != hashed_plaintext:
                raise ValueError(
                    f'Share "{share.name}" does not have the same plaintext'
                    f' hash as "{shares[0].name}". This indicates that the two'
                    f' shares were created with different plaintexts. All '
                    f'shares must have the same hash!'
                )
            ids.add(share.name)

        possible_ids, threshold, _ = EncryptedShare.parse_schema(schema)
        return len(ids.intersection(possible_ids)) >= threshold

    @staticmethod
    def parse_schema(schema):
        """Given a schema, find the parameters which it requires.

        :param schema: An object recovered from json.load
        :type schema: dict"""
        if len(schema) != 1:
            raise ValueError('Schema must have exactly one top level expression')
        if (possible_ids := schema.get('any')) or (possible_ids := schema.get('or')):
            possible_ids = set(possible_ids)
            threshold = 1
            num_shares = len(possible_ids)
        elif (possible_ids := schema.get('all')) or (possible_ids := schema.get('and')):
            possible_ids = set(possible_ids)
            threshold = num_shares = len(possible_ids)
        else:
            raise ValueError(f'Unknown keyword: "{schema.keys()[0]}"')
        return possible_ids, threshold, num_shares
