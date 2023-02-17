# Time-based Long-Term Passwords

This program's name is a play on TOTP. Stateless password managers exist which
use password-based key derivation functions to generate random passwords from a
master password in a way that is unique to each use case and resistant to brute
force; however, these password managers generally have a few problems that
surface in certain use cases:

### Password rotation requirements

Some organizations or services impose a maximum lifetime for which a password
may remain in service before being rotated. We incorporate a timestamp into the
password generation using an algorithm similar to TOTP—with a much longer
default period—to allow passwords to be rotated without our program storing any
internal state. Prior passwords can be retrieved (and upcoming passwords can be
accessed ahead of time) using the `--offset` argument.

### Password complexity constraints

Some organizations or services impose constraints on the passwords that may be
used with their systems. In stateful password managers with pseudorandom
generation, this is a non-issue because one may simply choose another—doing
rejection sampling by hand—but in a stateless system, there is no simple way to
choose another. It must therefore be guaranteed that the password generation
scheme shall never produce an unacceptable password. As a result, this program
accepts arbitrary password generation functions that can be tailored to your
organization's needs.

## User Guide

### Installation

Simply clone this repository and run `pip install .`. This package has no
third-party dependencies to run, although the optional dependency `pyperclip`
may be installed to enable the password to be copied to the clipboard
automatically using the `--clip` flag.

### Usage

The program may be invoked after being installed with either the provided
console script `tltp` or the python module entrypoint `python -m tltp`.

The basic usage of this program can be displayed using the `-h` or `--help`
flag:

```
$ tltp -h
usage: tltp [-h] [-o OFFSET] [-i INTERVAL] [-L SIZE] [--noshow] [-c] [-x]
            [--remaining] [--generator GENERATOR | --alphabet ALPHABET]
            name

Generate a time-derived password for the given name. The name may be any
string, such as a service, domain, URI, or an arbitrary value. These names
must must be retrievable, as this password manager stores no state: the
password name and the master password uniquely determine the derived password
at the current time.

positional arguments:
  name                  The name for which to generate a password.

options:
  -h, --help            show this help message and exit
  -o OFFSET, --offset OFFSET
                        the number of time intervals to skip; negative numbers
                        skip backwards (default: 0)
  -i INTERVAL, --interval INTERVAL
                        the number of days between password changes (default:
                        60)
  -L SIZE, --size SIZE  length of the derived password in characters (default:
                        15)
  --noshow              do not print the derived password to stdout
  -c, --confirm         confirm the master password by requiring it to be
                        entered twice
  -x, --clip            copy the derived password to the clipboard
  --remaining           show the remaining time until the next password
                        rotation on the stderr stream to allow the password to
                        be piped
  --generator GENERATOR
                        password generation function reference formatted as
                        `module:func`, e.g., `foo.bar:baz` identifies a
                        function `baz` in module `foo.bar` matching the
                        `tltp.PasswordFunction` protocol (default:
                        `tltp:disa_password`)
  --alphabet ALPHABET   unordered list of valid characters to be used for
                        random password generation
```

### Configuration

If the environment variable `TLTP_FLAGFILE` is set, each line of that file shall
be interpreted as an argument and prepended to the command line flags. This can
be used to help save typing with commonly-used flags.
