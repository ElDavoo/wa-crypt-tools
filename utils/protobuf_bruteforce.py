"""
This script tries to find protobuf messages in a file.
Props to protobuf_inspector for the parser.
"""

from __future__ import annotations

from protobuf_inspector.types import StandardParser
from io import BytesIO
from os.path import getsize

import argparse


def parsecmdline() -> argparse.Namespace:
    """Sets up the argument parser"""
    parser = argparse.ArgumentParser(description='Find protocol buffers in a file.')
    parser.add_argument('file_name', type=str, help='A file that you believe contains protobuf messages.')
    parser.add_argument('-k', '--keep-going', action='store_true', help='Don\'t stop after the first result.')
    parser.add_argument('-r', '--range', type=int, default=512, help='The number of bytes to search. Ignored if -w is '
                                                                     'set.')
    parser.add_argument('-w', '--whole-file', action='store_true', help='Search the whole file. Not advised for large '
                                                                        'files')
    return parser.parse_args()


def load_file(file_name: str, byte_range=0, reverse=False) -> bytes:
    """ Loads a file and returns it as a byte array.
    If byte_range is set, it will return the first byte_range bytes of the file.
    If reverse is set, it will return the last byte_range bytes of the file.
    """
    try:

        size = getsize(file_name)

        if byte_range > size / 2:
            raise ValueError("Range provided is bigger than half of file. Use -w or lower the range.")

        with open(file_name, 'rb') as f:

            if byte_range < 1:
                if reverse:
                    raise ValueError("Cannot read the whole file from end")
                return f.read()

            if reverse:
                f.seek(size - byte_range)
                return f.read(byte_range)

            return f.read(byte_range)

    except IOError:
        print("File not found or other IO error")
        exit(1)


def get_truncated_stream(content: bytes, start: int, end: int) -> BytesIO:
    """ Returns a BytesIO object with the content truncated to the given range. """
    return BytesIO(content[start:end])


def main():
    args = parsecmdline()

    if args.whole_file:

        whole_file = load_file(args.file_name)
        search(whole_file, args.keep_going)

    else:

        # We first try the first "range" bytes.
        whole_file = load_file(args.file_name, args.range)
        search(whole_file, args.keep_going)

        print("Now searching at the end of the file")
        # Then we try the last "range" bytes.
        size = getsize(args.file_name)
        whole_file = load_file(args.file_name, args.range, reverse=True)
        search(whole_file, args.keep_going, size - len(whole_file))

    if args.keep_going:
        print("Finished")
    else:
        print("Nothing found")
        exit(1)


def protoparse(stream):
    return StandardParser().parse_message(stream, "message")


class Message:
    last_good_i = 0
    last_good_j = 0
    output = ""


def search(whole_file: bytes, keep_going: bool, offset=0):
    """ Searches for protobuf messages in the given byte array. """

    for i in range(len(whole_file)):
        message = Message()

        for j in range(i + 1, len(whole_file)):
            candidate = get_truncated_stream(whole_file, i, j)
            try:
                message.output = protoparse(candidate)
                message.last_good_j = j
                message.last_good_i = i

            except Exception:
                pass
        if message.last_good_j and message.last_good_i == i:
            print("\n Message from byte {} to {}".format(message.last_good_i + offset, message.last_good_j + offset))
            print(message.output)
            if not keep_going:
                exit(0)


if __name__ == "__main__":
    main()
