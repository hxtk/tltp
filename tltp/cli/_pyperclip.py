from absl import logging


def copy(_: str):
    logging.fatal("""This feature requires the optional dependency `pyperclip`.
    You may install it by running the following command:
        $ pip install pyperclip
    """)