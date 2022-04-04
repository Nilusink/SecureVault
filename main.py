"""
Securely encrypt directories

Author:
Nilusink
"""
from cryption_tools import *
import sys
import os


def main() -> int:
    """
    main program
    """
    running = True
    now_dir = os.path.abspath("./")

    # "cli" for navigating
    while running:
        cmd_in = input(f"{'/'.join(now_dir.split())}>> ").split()
        if not cmd_in:
            continue

        match cmd_in[0]:
            case "cd":
                new = os.path.realpath("" if cmd_in[1] == "~" else (now_dir + "/") + " ".join(cmd_in[1::]))
                if os.path.exists(new):
                    now_dir = new

                else:
                    print(f"{new}: No such file or directory")

            case "ls":
                files = os.listdir(now_dir)
                print(" ".join(files))

            case "encrypt":
                if len(cmd_in) < 2:
                    print(f"Please specify a password!")
                    continue
                encrypt_directory(cmd_in[1], now_dir)

            case "decrypt":
                if len(cmd_in) < 2:
                    print(f"Please specify a password!")
                    continue
                try:
                    decrypt_directory(cmd_in[1], now_dir)

                except KeyError:
                    print(f"Invalid Password!")

            case "exit":
                return 0

            case _:
                print(f"{cmd_in[0]}: not found")

    return 0


if __name__ == "__main__":
    sys.exit(main())
