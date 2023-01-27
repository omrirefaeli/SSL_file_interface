from enum import Enum
import pickle
import ssl
import socket
import tkinter as tk
from tkinter import filedialog
import getpass


class FileInterfaceError(Exception):
    "Base class for all exceptions of this module."
    message = "Unknown error."

    def __str__(self):
        return self.message


class SystemExitError(FileInterfaceError):
    """
    An error is raised that forced the interface to exit.
    """


class ConnectionClosedUnexpectedly(SystemExitError):
    """
    There was some error in the communication, and the server closed the socket unexpectedly
    """

    message = (
        "There was some error in the communication, and the server closed the socket unexpectedly"
    )


class WritingFileError(FileInterfaceError):
    """
    There was an error with writing the user's file as part of the GET command
    """

    message = "There was an error with writing the file."


class SendingError(FileInterfaceError):
    """
    There was an error with sending the packet to the client
    """

    message = "There was an error with sending the packet to the client"


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
        self.text = text.encode()
        self.data = data


# CONSTANTS
PORT = 50000
SERVER_ADDRESS = "localhost"


def verify_active_connection(connstream: ssl.SSLSocket):

    try:
        connstream.getpeername()
    except socket.error:
        # Socket closed
        return False
    return True


def verify_input(pckt: Packet):
    if not pckt:
        print("Connection closed by server")
        return False
    print(pckt.text)

    return True


def select_file():
    root = tk.Tk()
    root.withdraw()

    filepath = filedialog.askopenfilename()
    return filepath


def save_file():
    root = tk.Tk()
    root.withdraw()

    filepath = filedialog.asksaveasfilename()
    return filepath


# helper function that wraps the packet to be sent, handling exceptions and edge cases
def inter_write(connstream: ssl.SSLSocket, pckt: Packet):

    if verify_active_connection:
        try:
            # Connection is active
            connstream.write(pickle.dumps(pckt))
        except Exception:
            raise SendingError


def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(".\\server.crt")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    connstream = context.wrap_socket(s, server_hostname=SERVER_ADDRESS)
    connstream.connect((SERVER_ADDRESS, PORT))

    try:
        while True:
            data_received = pickle.loads(connstream.read())
            if not verify_input(data_received):
                raise ConnectionClosedUnexpectedly

            # Default values
            pckt_message = ""
            pckt_data = None
            pckt_type = PacketType.TEXT

            if data_received.type == PacketType.TEXT:
                pckt_message = input("")
            elif data_received.type == PacketType.SECURE:
                pckt_message = getpass.getpass()
            elif data_received.type == PacketType.GET:
                get_file_path = save_file()
                try:
                    with open(get_file_path, "wb") as file:
                        file.write(data_received.data)
                except Exception:
                    raise WritingFileError
                pckt_message = "stub"

            elif data_received.type == PacketType.PUT:
                upload_file_path = select_file()
                with open(upload_file_path, "rb") as file:
                    file_content = file.read()
                pckt_message = upload_file_path
                pckt_type = PacketType.PUT
                pckt_data = file_content

            # Send with final values
            inter_write(connstream, Packet(pckt_message, pckt_type, pckt_data))

    except Exception as e:
        # Must exit the interface type of error
        if isinstance(e, SystemExitError):
            raise e
        else:
            print(str(e))

    finally:
        print("aborting connection")
        connstream.close()


if __name__ == "__main__":
    main()
