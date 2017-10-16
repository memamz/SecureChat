import threading
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import base64

class client():
    def __init__(self):
        self.running = True
        self.server_host = '127.0.1.1'
        self.key = b'network security'									   # 16 bits

    def run(self):
        self.my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Cleint socket IPV4 , TCP
        self.my_socket.connect((self.server_host, 6666))				   # Connect the Socket to local host port 6666

        pubKey = self.my_socket.recv(2048)
        print(pubKey)
        pubKeyObj = RSA.importKey(pubKey)
        msg = pubKeyObj.encrypt(self.key, 'x')[0]                             # 'x' is byte string used for comptability only (ignored)
        self.my_socket.send(msg)
        print(self.key)

        threading.Thread(target=self.receive).start()					   # Thread to receive
        while self.running:
            data = input()
            data = self.encrypt(data)
            self.my_socket.send(data)
            if data == 'END':
                self.end()

    def end(self):
        self.running = False
        self.my_socket.close()

    def receive(self):
        while self.running:
            data = self.my_socket.recv(1024)
            data = self.decrypt(data)
            if data in ['END', '', None]:
                self.end()
            else:
                print("server: " + data)

    def encrypt(self, msg):
        iv = Random.new().read(AES.block_size)                             # Initialization vector
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        return base64.b64encode(iv + cipher.encrypt(msg))

    def decrypt(self, msg):
        msg = base64.b64decode(msg)
        iv = msg[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        return cipher.decrypt(msg[AES.block_size:]).decode('utf-8')

		
if __name__ == '__main__':
    my_client = client()
    my_client.run()
