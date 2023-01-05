import datetime
import getpass

from absl import app
from absl import flags
from absl import logging

try:
    import pyperclip
except ImportError:
    from tltp.cli import _pyperclip as pyperclip

import tltp

flags.DEFINE_integer(
    'offset',
    0,
    'Number of time intervals to skip. Negative numbers skip backwards.',
    short_name='o',
)
flags.DEFINE_integer(
    'interval',
    60,
    'Number of days between password changes.',
    short_name='i',
)
flags.DEFINE_integer(
    'size',
    15,
    'Length of the derived password.',
    short_name='L',
)
flags.DEFINE_boolean('show', True, 'Print the password to stdout.')
flags.DEFINE_boolean(
    'confirm',
    False,
    'Confirm master password by requiring it to be entered twice identically.',
    short_name='c',
)

flags.DEFINE_boolean('clip', False, 'Copy the password to the clipboard.')


def main(argv):
    if len(argv) != 2:
        app.usage(
            f'Usage: {argv[0]} <name> [--offset=N] [--interval=M]',
            writeto_stdout=False,
            exitcode=1,
            detailed_error='Missing required argument `name`.',
        )

    password = getpass.getpass('Master Password: ')
    if flags.FLAGS.confirm:
        confirm = getpass.getpass('Confirm Master Password: ')
        if confirm != password:
            logging.fatal('Master passwords did not match.')

    interval = datetime.timedelta(days=flags.FLAGS.interval)
    out = tltp.time_password(
        password=password,
        name=argv[1],
        interval=interval,
        offset=flags.FLAGS.offset,
        length=flags.FLAGS.size,
    )

    if flags.FLAGS.show:
        print(out)

    if flags.FLAGS.clip:
        pyperclip.copy(password)

    seconds = interval.total_seconds()
    seconds = seconds - datetime.datetime.utcnow().timestamp() % seconds
    remaining = datetime.timedelta(seconds=seconds)
    print(f'Your passwords will rotate in {remaining.days} days.')
    print(
        ('Use --offset=1 to get the next password or '
         '--offset=-1 to get the previous one.')
    )


if __name__ == '__main__':
    app.run(main)