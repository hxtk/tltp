"""Entrypoint for TLTP Command Line application."""
import argparse
import contextlib
import datetime
import getpass
import os
import random
import shlex
import sys
from typing import Generator
from typing import IO
from typing import List
from typing import Optional

try:
    import pyperclip
except ImportError:
    from tltp.cli import _pyperclip as pyperclip

import tltp


def _get_parser():
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
        '-x',
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
        help=('show the remaining time until the next password rotation '
              'on the stderr stream to allow the password to be piped'),
        default=False,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '--generator',
        dest='generator',
        help=('password generation function reference formatted as '
              '`module:func`, e.g., `foo.bar:baz` identifies a function `baz` '
              'in module `foo.bar` matching the `tltp.PasswordFunction` '
              'protocol (default: `tltp:disa_password`)'),
    )
    group.add_argument(
        '--alphabet',
        dest='alphabet',
        help=('unordered list of valid characters to be used for random '
              'password generation'),
    )
    return parser


def get_arguments(argv: List[str], flag_file: Optional[IO] = None):
    if flag_file is not None:
        argv = shlex.split(flag_file.read()) + argv
    return _get_parser().parse_args(argv)


@contextlib.contextmanager
def _try_open(path: Optional[str]) -> Generator[Optional[IO], None, None]:
    if path is None:
        yield None
        return

    f = open(path, 'r', encoding='utf-8')
    try:
        yield f
    finally:
        f.close()


def main():
    flag_file = os.getenv('TLTP_FLAGFILE')
    with _try_open(flag_file) as f:
        args = get_arguments(sys.argv[1:], f)

    password = getpass.getpass('Master Password: ')
    if args.confirm:
        confirm = getpass.getpass('Confirm Master Password: ')
        if confirm != password:
            print('Master passwords did not match.', file=sys.stderr)
            sys.exit(1)

    generator = tltp.disa_password
    if args.generator is not None:
        module, sep, func = args.generator.partition(':')
        if sep == '':
            print(
                f'Invalid generator function specifier {args.generator}',
                file=sys.stderr,
            )
            sys.exit(1)
        try:
            generator = getattr(__import__(module), func)
        except (AttributeError, ModuleNotFoundError) as e:
            print('Error loading generator function:', e, file=sys.stderr)
            sys.exit(1)
    elif args.alphabet is not None:

        def gen(length: int, rand: random.Random) -> str:
            alphabet = ''.join(sorted(args.alphabet.split()))
            return ''.join(rand.choice(alphabet) for _ in range(length))

        generator = gen

    interval = datetime.timedelta(days=args.interval)
    try:
        out = tltp.time_password(
            password=password,
            name=args.name,
            interval=interval,
            offset=args.offset,
            length=args.size,
            generator=generator,
        )
    except ValueError as e:
        print(f'Error generating password: {e}', file=sys.stderr)
        sys.exit(2)

    if args.show:
        print(out)

    if args.clip:
        pyperclip.copy(out)

    if args.remaining:
        now = datetime.datetime.utcnow()
        seconds = interval.total_seconds()
        seconds = seconds - now.timestamp() % seconds
        remaining = datetime.timedelta(seconds=seconds)
        time = now + remaining
        print(
            f'Your passwords will rotate in {remaining.days} days at {time}.',
            file=sys.stderr,
        )
        print(
            ('Use --offset=1 to get the next password or --offset=-1 to get '
             'the previous one.'),
            file=sys.stderr,
        )


if __name__ == '__main__':
    main()
