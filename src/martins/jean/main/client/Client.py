#! /usr/bin/env python

import socket
import sys
import time
import threading
import select
import traceback
import base64, os;

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5

class Server(threading.Thread):
    def initialise(self, receive):
        self.receive = receive

    def run(self):
        lis = []
        lis.append(self.receive)
        user_name = input("Informe o nome do usuario com a chave publica\n>>")
        print(user_name)
        r = RsaHelper(path_to_pem="/tmp/", name_file_pem=user_name + ".pem", create_private=False);
        while 1:
            read, write, err = select.select(lis, [], [])
            for item in read:
                try:
                    s = item.recv(1024)
                    if s != '':
                        chunk = s
                        msgEncrypto = chunk.decode()
                        descriptografado = r.decrypt(msgEncrypto);
                        print(descriptografado + '\n>>')
                except:
                    traceback.print_exc(file=sys.stdout)
                    break


class Client(threading.Thread):
    def connect(self, host, port):
        self.sock.connect((host, port))

    def client(self, host, port, msg):
        sent = self.sock.send(msg)

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            host = input("Enter the server IP \n>>")
            port = int(input("Enter the server Destination Port\n>>"))
        except EOFError:
            print("Error")
            return 1

        print("Connecting\n")
        s = ''
        self.connect(host, port)
        print("Connected\n")
        user_name = input("Enter the User Name to be Used\n>>")
        r = RsaHelper(path_to_pem="/tmp/", name_file_pem=user_name + ".pem", create_private=True);
        receive = self.sock
        time.sleep(1)
        srv = Server()
        srv.initialise(receive)
        srv.daemon = True
        print("Starting service")
        srv.start()
        while 1:
            # print "Waiting for message\n"
            msg = input('>>')
            if msg == 'exit':
                break
            if msg == '':
                continue
            # print "Sending\n"
            msg = user_name + ': ' + msg
            msgCrypto = r.encrypt(msg)
            data = msgCrypto.encode()
            self.client(host, port, data)
        return (1)

class RsaHelper():
    def __init__(self, path_to_pem=None, name_file_pem="bot.pem", create_private=False):
        if path_to_pem == None:
            path_to_pem = os.path.expanduser("~");

        if not os.path.exists(path_to_pem):
            os.makedirs(path_to_pem);

        if not os.path.exists(path_to_pem + "/.ssh"):
            os.makedirs(path_to_pem + "/.ssh");

        self.path_to_private = path_to_pem + "/.ssh/private_" + name_file_pem;
        self.path_to_public = path_to_pem + "/.ssh/public_" + name_file_pem;
        self.key_pub = None;
        self.key_priv = None;
        if not os.path.exists(self.path_to_private) and create_private == True:
            self.key_priv = RSA.generate(1024);
            self.key_pub = self.key_priv.publickey();
            if not os.path.exists(self.path_to_private):
                with open(self.path_to_private, "bw") as prv_file:
                    prv_file.write(self.key_priv.exportKey());
            if not os.path.exists(self.path_to_public):
                with open(self.path_to_public, "bw") as pub_file:
                    pub_file.write(self.key_pub.exportKey());
        else:
            if os.path.exists(self.path_to_public):
                with open(self.path_to_public, "rb") as k:
                    self.key_pub = RSA.importKey(k.read());
            if os.path.exists(self.path_to_private):
                with open(self.path_to_private, "rb") as k:
                    self.key_priv = RSA.importKey(k.read());

    def encrypt(self, data):
        cipher = Cipher_PKCS1_v1_5.new(self.key_pub);
        return base64.b64encode(cipher.encrypt(data.encode())).decode();

    def decrypt(self, data):
        decipher = Cipher_PKCS1_v1_5.new(self.key_priv);
        return decipher.decrypt(base64.b64decode(data.encode()), None).decode();

if __name__ == '__main__':
    print("Starting client")
    cli = Client()
    cli.start()