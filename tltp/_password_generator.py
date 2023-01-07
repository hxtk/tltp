"""Password generation module."""
import datetime
import hashlib
import random
import struct
from typing import Optional
from typing import Protocol
from typing import Union

_LOWER = 'abcdefghijklmnopqrstuvwxyz'
_UPPER = _LOWER.upper()
_DIGIT = '0123456789'
_SYMBOL = '~!@#$%^&*()-=[]\\{}|;:\'",./<>?'
_CLASSES = [_LOWER, _UPPER, _DIGIT, _SYMBOL]
_ALL = ''.join(_CLASSES)


class PasswordFunction(Protocol):
    """Protocol for password generation.

    Implementations MUST be pure functions, producing identical outputs for
    identical inputs (i.e., reproducible random number generation SHALL result
    in reproducible output for a password of a given length.
    """

    def __call__(
            self,
            length: int,
            rand: random.Random = random.SystemRandom(),
    ) -> str:
        """Generate a password of a given length using the provided RNG.

        Args:
            length: the length of the generated password. The length SHALL be
                a non-negative integer. Implementations MUST return a string
                of that length. Implementations MAY raise a ValueError if they
                cannot honor the provided length value for any reason. The
                message SHOULD explain why the length cannot be honored.
            rand: a random number generator that MUST be used to produce all
                random choices within the password generation. Implementations
                MUST NOT use alternative sources of randomness, lest they
                will violate the reproducibility contract of this protocol.

        Returns:
            A randomized string of the specified length.
        """
        del rand
        return '0' * length


def random_password(
        length: int,
        rand: random.Random = random.SystemRandom(),
) -> str:
    """A PasswordFunction for generating random passwords."""
    return ''.join(rand.choice(_ALL) for _ in range(length))


def _disa_valid(password: str) -> bool:
    """Evaluate password against DISA rules to validate compliance.

    Args:
        password: a candidate password

    Returns:
        True if password matches DISA's criteria; false otherwise.
    """
    a = password

    # These criteria are guaranteed by construction, so we assert their
    # correctness.
    for c in _CLASSES:
        assert not set(c).isdisjoint(a)

    # If it contains a string of four identical characters.
    if any(w == x == y == z for w, x, y, z in zip(a, a[1:], a[2:], a[3:])):
        return False

    # If it contains a string of five characters in the same class.
    for i in range(5, len(a)):
        sub = set(a[i - 5:i])
        if any(sub.issubset(x) for x in _CLASSES):
            return False

    return True


def disa_password(length: int = 15,
                  rand: random.Random = random.SystemRandom()) -> str:
    """Generate a random password compliant with DISA requirements.

    DISA requirements are derived from the STIG for RHEL 8. Compliant passwords:
    - SHALL have a length not less than 15 characters,
    - SHALL include at least one capital letter,
    - SHALL include at least one lower-case letter,
    - SHALL include at least one digit,
    - SHALL include at least one symbol,
    - SHALL NOT include a substring of four identical characters, and
    - SHALL NOT include a substring of five characters from the same class.

    Passwords meeting the first five criteria are obtained by construction,
    yielding 17.58 + (x - 4)*6.51 + log₂(x(x-1)(x-2)(x-3)) bits of entropy for
    a length of `x`. Minimal-length passwords are constructed with approximately
    104 bits of entropy, though a small (but not-yet-quantified) amount of that
    entropy is discarded in the rejection sampling process described below.

    Passwords not meeting the two exclusive criteria are rejected and re-sampled
    from scratch. This iterative process will return quickly with high
    probability, but in general cannot be proven to halt with a maliciously
    constructed infinite randomness source.

    Args:
        length: the number of characters in the password to be generated. This
            value MUST be at least 15 or a ValueError SHALL be raised.
        rand: a random source to be used for password generation.

    Returns:
        A random password compliant with the criteria specified in the DISA
        STIG for RHEL 8.
    """
    if length < 15:
        raise ValueError(
            'DISA password requirements require a minimum of 15 characters.')

    required = ''.join(x[rand.randrange(len(x))] for x in _CLASSES)

    padding = ''
    for _ in range(length - len(_CLASSES)):
        padding += rand.choice(_ALL)

    for x in required:
        k = rand.randint(0, len(padding))
        padding = padding[:k] + x + padding[k:]

    # Reject invalid passwords
    if not _disa_valid(padding):
        return disa_password(length, rand)

    return padding


def time_password(
    password: Union[str, bytes],
    name: Union[str, bytes],
    interval: datetime.timedelta = datetime.timedelta(days=60),
    for_time: Optional[datetime.datetime] = None,
    offset: int = 0,
    length: int = 15,
    generator: PasswordFunction = random_password,
) -> str:
    """Generate a time-based password from a master password.

    Args:
        password: the master password provided by the user.
        name: the name for which the password is being generated, used as salt
        interval: the time-interval for which passwords are valid
        for_time: the timestamp for which the generated password must be
            generated.
        offset: the offset of time intervals for the given timestamp, e.g., an
            offset of 1 will generate the password valid for the next time
            interval while an offset of -1 will generate the password valid for
            the previous time interval.
        length: the length of the generated password
        generator: the password generation function

    Returns:
        A password that is a deterministic result of
    """
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
        generator=generator,
    )


def derive_password(
    password: Union[str, bytes],
    salt: Union[str, bytes],
    generator: PasswordFunction,
    length: int = 15,
) -> str:
    """Derive a password from a master password.

    The derived password will be derived using `scrypt` to stretch the salted
    master password to 7x the length in bytes of the intended derived password.
    This derived byte sequence is then used as an entropy pool to derive
    deterministic random choices from among the given alphabet until the desired
    length is reached.

    Args:
        password: the master password.
        salt: the salt applied to the master password.
        generator: the function used to generate a random password.
        length: the length of the derived password.

    Returns:
        A computationally hard password uniquely determined by the inputs.
    """
    if isinstance(password, str):
        password = password.encode(encoding='utf-8')
    if isinstance(salt, str):
        salt = salt.encode(encoding='utf-8')

    randomness = hashlib.scrypt(
        password=password,
        salt=salt,
        dklen=256,
        n=2**14,
        r=14,
        p=1,
    )

    # We seed the default random number generator with 2048-bits of
    # computationally hard pseudorandomness. We resist predictability attacks
    # by ensuring that at most `length` bytes are observed for a given seed.
    rand = random.Random(randomness)
    return generator(length, rand)
