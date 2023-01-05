"""Time-derived passwords."""
from tltp import _password_generator

__all__ = ['disa_alphabet', 'time_password']

time_password = _password_generator.time_password
disa_alphabet = _password_generator.disa_alphabet
