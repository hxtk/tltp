import datetime
import hashlib
import random
import struct
from typing import Optional
from typing import Protocol
from typing import Union


class FixedRandom(random.Random):

    def __init__(self, source: bytes):
        super().__init__()
        self.source = source

    def seed(self, *args, **kwargs) -> None:
        del args, kwargs
        return None

    def random(self):
        source, self.source = self.source[:7], self.source[7:]
        return (int.from_bytes(source, 'big') >> 3) * (2**-53)


class ValidAlphabet(Protocol):

    def __call__(self, prior: str) -> str:
        raise NotImplementedError


class StaticAlphabet(object):

    def __init__(self, alphabet: str):
        self.alphabet = alphabet

    def __call__(self, prior: str) -> str:
        del prior
        return self.alphabet


def disa_alphabet(prior: str) -> str:
    lower = set('abcdefghijklmnopqrstuvwxyz')
    upper = set(x.upper() for x in lower)
    digit = set('0123456789')
    symbol = set('~!@#$%^&*()-=[]\\{}|;:\'",./<>?')
    if len(prior) < 3:
        return ''.join(sorted(lower | upper | digit | symbol))
    if len(prior) < 4 and len(set(prior[-3:])) > 1:
        return ''.join(sorted(lower | upper | digit | symbol))

    out = set('')
    # No more than four consecutive of the same character class.
    if not lower.issuperset(prior[-4:]):
        out |= lower
    if not upper.issuperset(prior[-4:]):
        out |= upper
    if not digit.issuperset(prior[-4:]):
        out |= digit
    if not symbol.issuperset(prior[-4:]):
        out |= symbol

    # No more than three consecutive of the same character.
    if len(set(prior[-3:])) == 1:
        out.remove(prior[-1])

    return ''.join(sorted(out))


def time_password(
    password: Union[str, bytes],
    name: Union[str, bytes],
    interval: datetime.timedelta,
    for_time: Optional[datetime.datetime] = None,
    offset: int = 0,
    length: int = 15,
    alphabet: Union[str, ValidAlphabet] = disa_alphabet,
) -> str:
    if isinstance(password, str):
        password = password.encode(encoding='utf-8')
    if isinstance(name, str):
        name = name.encode(encoding='utf-8')
    if for_time is None:
        for_time = datetime.datetime.utcnow()

    counter = int(for_time.timestamp() // interval.total_seconds()) + offset
    salt = name + struct.pack('<Q', counter)
    return derive_password(
        password=password,
        salt=salt,
        length=length,
        alphabet=alphabet,
    )


def derive_password(
    password: Union[str, bytes],
    salt: Union[str, bytes],
    length: int = 15,
    alphabet: Union[str, ValidAlphabet] = disa_alphabet,
) -> str:
    if isinstance(password, str):
        password = password.encode(encoding='utf-8')
    if isinstance(salt, str):
        salt = salt.encode(encoding='utf-8')

    randomness = hashlib.scrypt(
        password=password,
        salt=salt,
        dklen=7 * length,
        n=2**14,
        r=14,
        p=1,
    )

    rand = FixedRandom(randomness)
    if isinstance(alphabet, str):
        alphabet = StaticAlphabet(alphabet)
    password = ''
    for _ in range(length):
        charset = alphabet(password)
        password += charset[rand.randrange(0, len(charset))]
    return password
