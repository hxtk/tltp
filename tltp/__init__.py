"""Time-derived passwords."""
from tltp import _password_generator

__all__ = [
    'derive_password',
    'disa_password',
    'random_password',
    'time_password',
    'PasswordFunction',
]

derive_password = _password_generator.derive_password
disa_password = _password_generator.disa_password
random_password = _password_generator.random_password
time_password = _password_generator.time_password
PasswordFunction = _password_generator.PasswordFunction
