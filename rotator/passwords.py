"""Password generation, and the characters left out of it."""

from __future__ import annotations

import secrets

# Letters, digits and the punctuation that survives every consumer of these
# credentials. Excluded on purpose:
#   / @ " and a space   RDS rejects all four in a master password
#   : and the quotes    a libpq connection string parses them
#   \ and `             a shell or a psql meta command eats them
# The set is 70 characters, so 40 of them carry about 245 bits.
ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~!*()"


def generate(length: int) -> str:
    if length < 24:
        raise ValueError(f"length {length} is below 24")
    return "".join(secrets.choice(ALPHABET) for _ in range(length))
