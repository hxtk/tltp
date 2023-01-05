"""Entrypoint for TLTP Command Line application."""
import argparse
import datetime
import getpass
import sys

try:
    import pyperclip
except ImportError:
    from tltp.cli import _pyperclip as pyperclip

import tltp

parser = argparse.ArgumentParser(
    prog='tltp',
    description=('Generate a time-derived password for the given name. '
                 'The name may be any string, such as a service, domain, '
                 'URI, or an arbitrary value. These names must must be '
                 'retrievable, as this password manager stores no state: '
                 'the password name and the master password uniquely '
                 'determine the derived password at the current time.'),
)
parser.add_argument(
    dest='name',
    type=str,
    help='The name for which to generate a password.',
)
parser.add_argument(
    '-o',
    '--offset',
    dest='offset',
    type=int,
    help=('the number of time intervals to skip; '
          'negative numbers skip backwards (default: 0)'),
    default=0,
)
parser.add_argument(
    '-i',
    '--interval',
    dest='interval',
    type=int,
    help='the number of days between password changes (default: 60)',
    default=60,
)
parser.add_argument(
    '-L',
    '--size',
    dest='size',
    type=int,
    help='length of the derived password in characters (default: 15)',
    default=15,
)
parser.add_argument(
    '--noshow',
    action='store_false',
    dest='show',
    help='do not print the derived password to stdout',
    default=True,
)
parser.add_argument(
    '-c',
    '--confirm',
    action='store_true',
    dest='confirm',
    help='confirm the master password by requiring it to be entered twice',
    default=False,
)
parser.add_argument(
    '--clip',
    action='store_true',
    dest='clip',
    help='copy the derived password to the clipboard',
    default=False,
)
parser.add_argument(
    '--remaining',
    action='store_true',
    dest='remaining',
    help='show the remaining time until the next password rotation',
    default=False,
)
parser.add_argument(
    '--alphabet',
    help='a string representing the set of characters for the derived password',
)
parser.add_argument(
    '--alphabet_function',
    help=('A qualified import string for a function accepting a partial '
          'candidate password and returning a string whose characters '
          'represent the set of valid choices for the next character. '
          'Defaults to a password generation scheme compliant with the DISA '
          'STIG for Linux Operating Systems. Formatted as `foo.bar:baz`.'),
)


def main():
    args = parser.parse_args()

    password = getpass.getpass('Master Password: ')
    if args.confirm:
        confirm = getpass.getpass('Confirm Master Password: ')
        if confirm != password:
            print('Master passwords did not match.', file=sys.stderr)
            sys.exit(1)

    alphabet = tltp.disa_alphabet
    if args.alphabet is not None:
        alphabet = args.alphabet
    elif args.alphabet_function is not None:
        module, _, func = args.alphabet_function.partition(':')
        try:
            alphabet = getattr(__import__(module), func)
        except (AttributeError, ModuleNotFoundError) as e:
            print('Error loading alphabet function:', e, file=sys.stderr)
            sys.exit(1)

    interval = datetime.timedelta(days=args.interval)
    out = tltp.time_password(
        password=password,
        name=args.name,
        interval=interval,
        offset=args.offset,
        length=args.size,
        alphabet=alphabet,
    )

    if args.show:
        print(out)

    if args.clip:
        pyperclip.copy(out)

    if args.remaining:
        seconds = interval.total_seconds()
        seconds = seconds - datetime.datetime.utcnow().timestamp() % seconds
        remaining = datetime.timedelta(seconds=seconds)
        print(f'Your passwords will rotate in {remaining.days} days.')
        print(('Use --offset=1 to get the next password or '
               '--offset=-1 to get the previous one.'))


if __name__ == '__main__':
    main()
