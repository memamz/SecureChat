import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import base64

class server():
        def __init__(self):
            self.running = True
            key = RSA.generate(2048)											# Use RSA for public key encryption to send key at start
            self.privKey = key.exportKey('PEM')								# Use PEM instead of DER (DER is binary representation)
            self.pubKey = key.publickey().exportKey('PEM')
            print(self.pubKey)

        def run(self):
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Server socket IPV4 , TCP
            self.socket.bind((socket.gethostname(), 6666))                  # Bind the Socket to local host port 6666
            self.socket.listen(1)           								# Only 1 connection
            self.client_socket, self.client_addr = self.socket.accept()

            self.client_socket.send(self.pubKey)
            privkeyObj = RSA.importKey(self.privKey)
            msg = self.client_socket.recv(2048)
            self.AESKey = privkeyObj.decrypt(msg)
            print(self.AESKey)

            threading.Thread(target=self.receive).start()					# Thread to receive
            while self.running:
                data = input()
                data = self.encrypt(data)
                if data != '':
                    self.client_socket.send(data)
                if data == 'END':
                    self.end()


        def end(self):
            self.running = False
            self.client_socket.close()

        def receive(self):
            while self.running:
                data = self.client_socket.recv(1024)
                data = self.decrypt(data)
                if data in ['END', '', None]:
                    self.end()
                else:
                    print("client: " + data)

        def encrypt(self, msg):
            iv = Random.new().read(AES.block_size)                             # Initialization vector
            cipher = AES.new(self.AESKey, AES.MODE_CFB, iv)
            return base64.b64encode(iv + cipher.encrypt(msg))

        def decrypt(self, msg):
            msg = base64.b64decode(msg)
            iv = msg[:AES.block_size]
            cipher = AES.new(self.AESKey, AES.MODE_CFB, iv)
            return cipher.decrypt(msg[AES.block_size:]).decode('utf-8')


if __name__ == '__main__':
    my_server = server()
    my_server.run()
