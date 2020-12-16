"""Contains EncryptedShare"""
import itertools
import re
from functools import partial
from typing import List, Dict

from Crypto.Hash import SHA3_256
from Crypto.Protocol.SecretSharing import Shamir
from sympy import Symbol, simplify_logic, true, to_cnf

from sympy.logic import And, Or


class EncryptedShare:
    """An object representing a single SSSS share."""

    def __init__(self, name, ciphertexts, schema, hashed_plaintext):
        self.name = name
        self.ciphertexts = ciphertexts
        self.schema = schema
        self.hashed_plaintext = hashed_plaintext

    @classmethod
    def encode(cls, plaintext, schema):
        """Encode a given secret according to a given schema.

        :param plaintext: The data to hide
        :param schema: The way the data should be encoded
        :returns: A list of encrypted shares
        :rtype: List[EncryptedShare]"""
        expression = to_cnf(  # Product of sums form
            EncryptedShare.parse_schema(schema),
            simplify=True,
            force=True
        )
        hashed_plaintext = SHA3_256.new(plaintext).hexdigest()
        if isinstance(expression, Symbol):  # Only one symbol at expression root
            num_shares = threshold = 1
            shares = Shamir.split(threshold, num_shares, plaintext, ssss=False)
            result = [
                EncryptedShare(
                    name=expression.name,
                    ciphertexts=shares,
                    schema=schema,
                    hashed_plaintext=hashed_plaintext
                )
            ]
        elif isinstance(expression, Or):  # A secret shared in plaintext between multiple keyholders
            num_shares = threshold = 1
            shares = Shamir.split(threshold, num_shares, plaintext, ssss=False)
            result = [
                EncryptedShare(
                    name=symbol.name,
                    ciphertexts=shares,
                    schema=schema,
                    hashed_plaintext=hashed_plaintext
                )
                for symbol in expression.args
            ]
        elif isinstance(expression, And):
            # A secret shared only in part to each key holder
            num_shares = threshold = len(expression.args)
            shares = Shamir.split(threshold, num_shares, plaintext, ssss=False)
            symbols = expression.free_symbols
            share_distribution = {symbol.name: set() for symbol in symbols}
            for subexpression, share in zip(expression.args, shares):
                for symbol in subexpression.free_symbols:
                    share_distribution[symbol.name].add(share)
            result = [
                EncryptedShare(
                    name=name,
                    ciphertexts=shares,
                    schema=schema,
                    hashed_plaintext=hashed_plaintext
                )
                for name, shares in share_distribution.items()
            ]
        else:
            # Should in theory never happen
            raise RuntimeError('Unknown expression type!')

        return result

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
        return Shamir.combine(
            list(set().union(*[share.ciphertexts for share in shares])),
            ssss=False
        )

    @staticmethod
    def satisfies(shares: List):
        """Check whether a set of shares satisfies their schemas.

        :param shares: A collection of shares
        :returns: A boolean indicating whether these shares are sufficient to decrypt the secret"""
        schema = shares[0].schema
        hashed_plaintext = shares[0].hashed_plaintext
        names = set()
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
            names.add(share.name)

        expression = EncryptedShare.parse_schema(schema)

        return simplify_logic(
            expression.subs({
                Symbol(names): True
                for names in names
            })
        ) is true

    @staticmethod
    def parse_schema(schema: Dict[str, List]):
        """Given a schema, find the parameters which it requires.

        :param schema: An object recovered from json.load"""
        if not isinstance(schema, dict):
            raise ValueError('Top level of schema must be a dictionary')
        if len(schema) != 1:
            raise ValueError('Schema must have exactly one top level expression')
        (key, expressions), = schema.items()
        if not isinstance(expressions, list):
            raise ValueError('All dictionary values must be lists')
        if len(expressions) == 0:
            raise ValueError('Dictionary values may not be empty lists')

        if key in ['or', 'any']:
            combining_func = Or
        elif key in ['all', 'and']:
            combining_func = And
        elif match := re.match(r'^at least (-?\d+)$', key):
            minimum = int(match.group(1))
            if minimum <= 0:
                raise ValueError(f'In "{key}": number ({minimum}) must be a positive integer')

            def at_least(*sym, minimum_present):
                if minimum_present > len(sym):
                    raise ValueError(
                        f'Minimum number of expressions is'
                        f' {minimum_present}, but there are only {len(sym)}'
                        f' expressions present')
                combinations = itertools.combinations(sym, minimum_present)
                return Or(*[
                    And(*combination)
                    for combination in combinations
                ])

            combining_func = partial(at_least, minimum_present=minimum)
        else:
            raise ValueError(f'Unknown keyword: "{key}"')

        symbols = []
        for expression in expressions:
            if isinstance(expression, str):
                symbols.append(Symbol(expression))
            elif isinstance(expression, dict):
                symbols.append(EncryptedShare.parse_schema(expression))
            else:
                raise ValueError(
                    f'Unknown expression, expected str or dict: "{expression}"'
                )
        return combining_func(*symbols)
