import binascii
import os
import ssl
import socket
import hashlib
import logging
from enum import Enum
import pickle
import traceback
from typing import List, Dict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.backends import default_backend


def initiate_logger():
    formatting = "%(asctime)s | %(levelname)s | %(message)s"
    logging_level = logging.DEBUG
    logging.basicConfig(
        handlers=[
            logging.StreamHandler(),  # Print to console
        ],
        level=logging._checkLevel(logging_level),
        format=formatting,
        datefmt="%Y-%m-%d %H:%M:%S",
    )


initiate_logger()
logger = logging.getLogger(__name__)


# Enum for packet types
class PacketType(Enum):
    TEXT = 1  # text message
    SECURE = 2  # secure text. text will be hidden in the client side
    GET = 3  # server is sending a file to the client
    PUT = 4  # client is seding a file to the server


# Packet class. Instances of this class are being sent to the client
class Packet:
    def __init__(self, text: str, type: PacketType = PacketType.TEXT, data: object = None) -> None:
        self.type = type
        self.text = f"Server: {text}"
        self.data = data


# A user class, representing a user registered in the system
class User:
    def __init__(self, username: str, password: str, salt: str = None) -> None:
        self.username = username
        if not salt:
            self.salt = self.generate_salt()
        else:
            self.salt = salt
        self.password = self.hash_password(password)

    def generate_salt(self):
        return binascii.hexlify(os.urandom(16)).decode()

    def hash_password(self, password: str):
        return hashlib.sha256((password + self.salt).encode()).hexdigest()


# DEFINE EXCEPTIONS
class FileInterfaceError(Exception):
    "Base class for all exceptions of this module."
    message = "Unknown error."

    def __str__(self):
        return self.message


class InputError(FileInterfaceError):
    """
    The client provided a faulty input
    """

    message = "Input Error"


class SendingError(FileInterfaceError):
    """
    There was an error with sending the packet to the client
    """

    message = "There was an error with sending the packet to the client"


class WritingFileError(FileInterfaceError):
    """
    There was an error with writing the user's file as part of the PUT command
    """

    message = "There was an error with writing the file."


class HelloError(InputError):
    """
    An Error was caught in the registration process
    """

    def __init__(self, input: str):
        self.input = input
        super_message = self.message
        self.message = f"{super_message}: An Error was caught in the registration process for the input '{self.input}', please initiate a new connection"


class TransmissionTypeError(InputError):
    """
    The transmission is in the wrong format
    """

    message = "The transmission is in the wrong format, please send Packet objects as 'bytes'"


class PacketTooBigError(InputError):
    """
    The received packet was too big to digest.
    """

    message = "The received packet was too big to digest. In this interface you can transfer data up to 16 KB (Over SSL Only)"


class PacktParsingError(InputError):
    """
    The server failed to parse the message correctly.
    """

    message = "The server failed to parse the message correctly."


class WrongPacketTypeError(InputError):
    """
    The packet type is wrong.
    """

    def __init__(self, types: List[PacketType]):
        self.types = types
        self.message = f"The packet type is wrong. The user send a packet type of '{types[0]}' when it needed to be '{types[-1]}'"


class ClientClosedConnectionError(FileInterfaceError):
    """
    The client closed the connection abruptly
    """

    def __init__(self, client: ssl.SSLSocket):
        self.client = client
        self.message = f"The client '{self.client}' abruptly closed the session"


class UserExists(FileInterfaceError):
    """
    The Client attempted to register an existing username
    """

    def __init__(self, username: str):
        self.username = username
        self.message = f"The username '{self.username}' already exists, please initiate a new connection with a different user"


class UserNotExists(FileInterfaceError):
    """
    The Client attempted to log in with a non existing username
    """

    def __init__(self, username: str):
        self.username = username
        self.message = f"The username '{self.username}' does not exist, please initiate a new connection with a different username"


class UserAuthneticationError(FileInterfaceError):
    """
    The user entered the wrong password too many times
    """

    def __init__(self, username: str):
        self.username = username
        self.message = f"The username '{self.username}'  entered the wrong password too many times, please initiate a new connection with a different username"


# END EXCEPTIONS

# CONSTANTS
PORT = 50000
ENC_IV_SIZE = 16
USERS = {}  # Create a dictionary to store the username and hashed password
DB_FILE_NAME = "db_users.enc"
PRIVATE_KEY_PATH = "privateKey.key"
PUBLIC_KEY_PATH = "server.crt"
HELLO_MESSAGE = """
Hello!
Welcome to the first Open University file transaction system, over SSL!
To register, send "register <username>"
To log in, send "login <username>"
Enter your choice:"""
REGISTER_MESSAGE = """
Let's register you in the system. Please select a password:"""
REGISTER_MESSAGE_2 = """
Please repeat the password:"""
PASSWORD_NOT_MATCH = """
The inputted passwords don't match, please try again."""
LOGIN_MESSAGE = """
Let's log in. Please provide a password:"""
ACCESS_MESSAGE = """
Great news! You got access to the OpenU file interface."""
COMMAND_MENU_MESSAGE = """
Please choose a command for the server to execute (list/put/get <filename>/bye):"""
INVALID_COMMAND = """
The command sent is invalid."""
BYE_COMMAND = """
Server is exiting, bye bye."""
LIST_COMMAND = """
Listing your files."""
PUT_COMMAND_INIT = """
Please choose a file to upload. Only files up to 16 KB are supported. (Transfer is over SSL)"""
END_COMMAND = "---------------------------------------------"


def read_file_as_bytes(file_path: str):
    with open(file_path, "rb") as file:
        file_content = file.read()

    return file_content


# Users DB Encryption function
def encrypt_db(db: Dict, private_key_path: str) -> None:

    # plaintext needs to be in Bytes type
    plaintext = pickle.dumps(db)
    private_key_data = read_file_as_bytes(private_key_path)

    # Load private key
    private_key = serialization.load_pem_private_key(
        private_key_data, password=None, backend=default_backend()
    )
    # Generate a random initialization vector
    iv = os.urandom(ENC_IV_SIZE)

    # Encrypt the plaintext using the private key and the initialization vector
    cipher = Cipher(
        algorithms.AES(
            bytes(
                str(private_key.private_numbers().public_numbers.n)[:ENC_IV_SIZE], encoding="utf-8"
            )
        ),
        modes.CBC(iv),
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Concatenate the initialization vector with the ciphertext
    ciphertext = iv + ciphertext

    # Write the ciphertext to a file
    with open(DB_FILE_NAME, "wb") as ciphertext_file:
        ciphertext_file.write(ciphertext)


# Decryption function
def decrypt_db(private_key_path: str) -> Dict:

    ciphertext = read_file_as_bytes(DB_FILE_NAME)

    private_key_data = read_file_as_bytes(private_key_path)
    # Load private key
    private_key = serialization.load_pem_private_key(
        private_key_data, password=None, backend=default_backend()
    )
    # Extract the initialization vector from the ciphertext
    iv = ciphertext[:ENC_IV_SIZE]
    ciphertext = ciphertext[ENC_IV_SIZE:]

    # Decrypt the ciphertext using the private key and the initialization vector
    cipher = Cipher(
        algorithms.AES(
            bytes(
                str(private_key.private_numbers().public_numbers.n)[:ENC_IV_SIZE], encoding="utf-8"
            )
        ),
        modes.CBC(iv),
        backend=default_backend(),
    )
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return pickle.loads(plaintext)


# helper function to verify that the socket is active
def verify_active_connection(connstream: ssl.SSLSocket):

    try:
        connstream.getpeername()
    except socket.error:
        # Socket closed
        return False
    return True


# helper function that wraps the packet to be sent, handling exceptions and edge cases
def inter_write(connstream: ssl.SSLSocket, pckt: Packet, as_exception=False):

    if verify_active_connection:
        if not as_exception:
            try:
                # Connection is active
                connstream.sendall(pickle.dumps(pckt))
            except Exception:
                raise SendingError
        else:
            try:
                # Connection is active
                connstream.sendall(pickle.dumps(pckt))
            except Exception:
                logger.debug(
                    "An exception occurred that prevents the interface to send the error message back to the client"
                )
    elif not as_exception:
        raise ClientClosedConnectionError(connstream.getpeername())
    else:
        logger.debug(
            "An exception occurred that prevents the interface to send the error message back to the client"
        )


# Register a new user in the system, including adding it to the DB, and creating a designated folder
def register(username, password):
    username = username.replace("\\", "_")
    USERS[username] = User(username=username, password=password)
    logger.info(f"User registered: {username}")
    create_folder(username)
    encrypt_db(USERS, PRIVATE_KEY_PATH)
    logger.info("DB has been encrypted and saved to disk.")


# helper function that verify the right structure of a message
def validate_bytes(data):
    if not isinstance(data, bytes):
        raise TransmissionTypeError
    try:
        return pickle.loads(data)
    except Exception:
        if len(data) >= 16384:
            raise PacketTooBigError
        else:
            raise PacktParsingError


# helper function to verify the type of the packet sent is indeed of Packet type
def validate_packet_type(data: Packet):
    if not isinstance(data, Packet):
        raise TransmissionTypeError
    else:
        data.text = data.text.decode()
        return data


# helper funciton to wrap and handle receiving data from the clients
def recv_pckt(data, intended_type: PacketType = PacketType.TEXT):

    data = validate_bytes(data)
    # validating and decoding
    data = validate_packet_type(data)

    if data.type != intended_type:
        raise WrongPacketTypeError

    return data


# create a folder for a username
def create_folder(username: str):

    if not os.path.exists(username):
        os.mkdir(username)
        return f"Created:{username}"
    return f"Existed:{username}"


def main():

    # load users
    if os.path.exists(DB_FILE_NAME):
        global USERS
        USERS = decrypt_db(PRIVATE_KEY_PATH)
        logger.debug(f"Creating folders for saved DB: {str(list(map(create_folder, USERS)))}")

    # creating the SSL Context  and loading the server's certificate and key
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=PUBLIC_KEY_PATH, keyfile=PRIVATE_KEY_PATH)

    bindsocket = socket.socket()
    bindsocket.bind(("localhost", PORT))
    bindsocket.listen(5)
    logger.info("Server instance is initiated!")

    # Begin loop with a connected client
    while True:
        newsocket, fromaddr = bindsocket.accept()
        connstream = context.wrap_socket(newsocket, server_side=True)
        try:
            logger.info(f"connection started for {fromaddr}")
            inter_write(connstream, Packet(HELLO_MESSAGE, PacketType.TEXT))

            data = recv_pckt(connstream.read())

            # The user needs to be authenticated to be granted with access
            if data.text.startswith("register "):  # Register
                split = data.text.split()
                if len(split) != 2:
                    logger.debug(f"The client {fromaddr} provided a wrong 'register' input")
                    raise HelloError(data.text)
                username = split[-1]
                if username in USERS:
                    raise UserExists(username=username)

                # Helper variable to determine if the user provided matching passwords
                password_check = False

                inter_write(connstream, Packet(REGISTER_MESSAGE, PacketType.SECURE))
                while not password_check:

                    password = recv_pckt(connstream.read()).text

                    # Enter matching password again
                    inter_write(connstream, Packet(REGISTER_MESSAGE_2, PacketType.SECURE))
                    password2 = recv_pckt(connstream.read()).text

                    if password != password2:
                        inter_write(
                            connstream,
                            Packet(PASSWORD_NOT_MATCH + REGISTER_MESSAGE, PacketType.SECURE),
                        )
                    else:
                        password_check = True
                register(username=username, password=password)

            elif data.text.startswith("login "):  # Log in
                split = data.text.split()
                if len(split) != 2:
                    logger.debug(f"The client {fromaddr} provided a wrong 'login' input")
                    raise HelloError(data.text)
                username = split[-1]
                count = 2
                # 3 tries total
                while username not in USERS and count > 0:
                    inter_write(
                        connstream,
                        Packet(
                            f"No such user, you have {count} tries left. Please enter a valid username:",
                            PacketType.TEXT,
                        ),
                    )
                    username = recv_pckt(connstream.read()).text
                    count -= 1

                if username not in USERS:
                    raise UserNotExists(username=username)

                inter_write(connstream, Packet(LOGIN_MESSAGE, PacketType.SECURE))
                password = recv_pckt(connstream.read()).text

                count = 2
                while (
                    USERS[username].password != USERS[username].hash_password(password)
                    and count > 0
                ):
                    inter_write(
                        connstream,
                        Packet(
                            f"Password is incorrect, you have {count} tries left.",
                            PacketType.SECURE,
                        ),
                    )
                    password = recv_pckt(connstream.read()).text
                    count -= 1

                if USERS[username].password != USERS[username].hash_password(password):
                    raise UserAuthneticationError(username=username)

            else:  # Not login or Register
                raise HelloError(data.text)

            logger.debug(f"The username '{username}' has beed granted with interface access")

            ######################### Access Granted #################################

            inter_write(
                connstream,
                Packet(ACCESS_MESSAGE + COMMAND_MENU_MESSAGE, PacketType.TEXT),
            )

            pckt = recv_pckt(connstream.read())
            command = pckt.text
            server_path = os.getcwd()

            # Initiate command menu loop, until the user closes the connection
            while True:

                #
                # List command
                #
                if command == "list":
                    message = "{}\n{}\n{}{}".format(
                        LIST_COMMAND,
                        "\n".join(os.listdir(username)),
                        END_COMMAND,
                        COMMAND_MENU_MESSAGE,
                    )
                    inter_write(connstream, Packet(message))

                #
                # Put command
                #
                elif command == "put":
                    inter_write(connstream, Packet(text=PUT_COMMAND_INIT, type=PacketType.PUT))
                    data = recv_pckt(connstream.recv(16384), intended_type=PacketType.PUT)
                    uploaded_file_name = os.path.basename(data.text)
                    paths = [server_path, username, uploaded_file_name]
                    try:
                        with open(
                            os.path.join(*paths),
                            "wb",
                        ) as file:
                            file.write(data.data)
                    except Exception:
                        raise WritingFileError
                    inter_write(
                        connstream,
                        Packet(
                            text="{}\n{}{}".format(
                                f"The file {uploaded_file_name} was written successfully.",
                                END_COMMAND,
                                COMMAND_MENU_MESSAGE,
                            )
                        ),
                    )

                #
                # Bye command
                #
                elif command == "bye":
                    inter_write(connstream, Packet(BYE_COMMAND, PacketType.TEXT))
                    break

                # Stub command - does nothing. Not presented in the list
                elif command == "stub":
                    inter_write(connstream, Packet(text=COMMAND_MENU_MESSAGE))
                else:
                    split = command.split()
                    #
                    # Get command
                    #
                    if split[0] == "get" and len(split) == 2:
                        file_name = split[-1]
                        paths = [server_path, username, file_name]
                        get_file_path = os.path.join(*paths)

                        # default packet values
                        get_file_content = None
                        pckt_type = PacketType.TEXT
                        message = ""

                        if not os.path.isfile(get_file_path):
                            message = f"The file {file_name} does not exist your folder."
                        elif os.stat(get_file_path).st_size > 16100:
                            message = (
                                f"The file {file_name} is too big. Please choose files up to 16 KB"
                            )

                        # File is chosed successfully
                        else:
                            with open(get_file_path, "rb") as file:
                                get_file_content = file.read()

                            # Let the client know a file is being sent
                            pckt_type = PacketType.GET
                            message = f"File {file_name} is being sent. Please select a location"
                        inter_write(
                            connstream, Packet(text=message, type=pckt_type, data=get_file_content)
                        )
                    else:
                        inter_write(
                            connstream,
                            Packet(INVALID_COMMAND + COMMAND_MENU_MESSAGE, PacketType.TEXT),
                        )

                pckt = recv_pckt(connstream.read())
                command = pckt.text
        # in case an error rises, send a message back to the user, if possible
        except Exception as e:
            logger.debug(f"Error was raised for address {fromaddr}: {traceback.format_exc()}")
            inter_write(connstream, Packet(str(e), PacketType.TEXT), as_exception=True)

        # close the connection either way, and go back to the loop
        finally:
            logger.info(f"Closing the socket for {fromaddr}")
            connstream.shutdown(socket.SHUT_RDWR)
            connstream.close()


if __name__ == "__main__":
    main()
