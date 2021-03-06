"""
Tools for encrypting and decrypting strings

Authors:
Nilusink
zwer on StackOverflow (https://stackoverflow.com/users/7553525/zwer)
"""
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import base64
import shutil
import os


class ConsoleColors:
    """
    for better readability (colors) in the console
    """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def file_name_encryption(string: str) -> str:
    """
    encrypt a string viable for file names
    """
    out: str = ""
    part_len = 3
    for character in string:
        num = str(ord(character))
        out += "0" * (part_len-len(num)) + num
    return out


def file_name_decryption(string: str) -> str:
    """
    the inverse of file_name_encryption
    """
    out: str = ""
    part_len = 3
    for i in range(len(string)//part_len):
        part = string[i*part_len:(i+1)*part_len]
        out += chr(int(part))
    return out


def encrypt(source, key, encode=True):
    # source = source.encode()
    key = SHA256.new(key.encode()).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = Random.new().read(AES.block_size)  # generate IV
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
    data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt

    return base64.b64encode(data).decode("latin-1") if encode else data


def decrypt(source, key, decode=True):
    if decode:
        source = base64.b64decode(source.encode("latin-1"))

    key = SHA256.new(key.encode()).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")

    return data[:-padding]  # remove the padding


def force_move(origin: str, dest: str) -> None:
    """
    temporarily move a directory to /tmp/
    """
    assert origin and dest, f"empty parameter for force_move: {origin=}, {dest=}"
    assert os.path.isdir(origin), f"{origin}: no such file or directory"
    directory = origin.rstrip("/")

    # copy original directory to temp folder
    if os.path.exists(dest):
        shutil.rmtree(dest)

    shutil.move(directory, dest)

    # re-create the original folder
    os.mkdir(directory)


def encrypt_directory(password: str, directory: str) -> None:
    """
    encrypt a whole directory
    """
    directory = directory.rstrip("/")
    now_dir = directory + "/../" + directory.split("/")[-1] + "_temp"
    now_dir = os.path.realpath(now_dir)

    # copy files to temp
    force_move(directory, now_dir)

    try:
        for element in os.listdir(now_dir):
            now_file = now_dir + "/" + element
            now_file_orig = directory + "/" + element
            now_file_name = directory + "/" + file_name_encryption(element)
            if os.path.isfile(now_file):
                with open(now_file, "rb") as inp:
                    file_dat = inp.read()
                    with open(now_file_name, "wb") as out:
                        try:
                            out.write(encrypt(file_dat, password, encode=True).encode())
                            print(f"{ConsoleColors.OKGREEN}encrypted{ConsoleColors.ENDC}: "
                                  f"{now_file_orig}")

                        except UnicodeDecodeError:
                            assert file_dat, "empty file!"
                            out.write(file_dat)
                            print(f"{ConsoleColors.FAIL}failed{ConsoleColors.ENDC}: "
                                  f"{now_file_orig}")

            elif os.path.isdir(now_file):
                shutil.copytree(now_file, now_file_orig)
                encrypt_directory(password, now_file_orig)

    except Exception as e:
        print(f"failsafe, copying back")
        force_move(now_dir, directory)
        if os.path.exists(now_dir):
            shutil.rmtree(now_dir)
        raise e

    finally:
        if os.path.exists(now_dir):
            shutil.rmtree(now_dir)


def decrypt_directory(password: str, directory: str) -> None:
    """
    decrypt a whole directory
    """
    directory = directory.rstrip("/")
    now_dir = directory + "/../" + directory.split("/")[-1] + "_temp"
    now_dir = os.path.realpath(now_dir)

    # copy files to temp
    force_move(directory, now_dir)

    try:
        for element in os.listdir(now_dir):
            now_file = now_dir + "/" + element
            try:
                de = file_name_decryption(element)

            except ValueError:
                de = element

            now_file_orig = directory + "/" + de
            if os.path.isfile(now_file):
                with open(now_file, "rb") as inp:
                    file_dat = inp.read()
                    with open(now_file_orig, "wb") as out:
                        try:
                            data = file_dat.decode()
                            if data.startswith("nE"):
                                raise UnicodeDecodeError

                            out.write(decrypt(data, password, decode=True))
                            print(f"{ConsoleColors.OKGREEN}decrypted{ConsoleColors.ENDC}: "
                                  f"{now_file_orig}")

                        except UnicodeDecodeError:
                            out.write(file_dat.lstrip(b"nE"))
                            print(f"{ConsoleColors.FAIL}not encrypted{ConsoleColors.ENDC}: "
                                  f"{now_file_orig}")
                            continue

            elif os.path.isdir(now_file):
                shutil.copytree(now_file, now_file_orig)
                decrypt_directory(password, now_file_orig)

    except Exception as e:
        assert os.path.exists(now_dir), "temporary folder gone"
        assert os.path.exists(directory), "original folder gone"
        print(f"failsafe, copying back ({e})")
        force_move(now_dir, directory)
        if os.path.exists(now_dir):
            shutil.rmtree(now_dir)

        if type(e) == ValueError:
            raise KeyError("Invalid Password!")
        raise e

    finally:
        if os.path.exists(now_dir):
            shutil.rmtree(now_dir)


if __name__ == "__main__":
    x = file_name_encryption("hi")
    y = file_name_decryption(x)
    print(f"{x=}, {y=}")