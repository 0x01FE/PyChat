import socket,sys
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify
import utils

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)
recv_log = []
default_length = 128

# SERVER KEYS
server_private_key = RSA.generate(1024)
server_public_key = server_private_key.publickey()

# CLIENT PUBLIC KEYS
client_keys = {}

private_pem = server_private_key.export_key().decode()
public_pem = server_public_key.export_key().decode()




while True:
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		print("Server booted")
		print(f'Listening on {HOST}:{PORT}.')
		print('----------------------------')
		s.bind((HOST, PORT))
		s.listen()
		conn, addr = s.accept()
		with conn:
			data = b''
			print('Connected by', addr)
			while True:
				chatroom_data = open('chatrooms\chatroomlist.txt','r').read()
				print('Recv_log: '+str(recv_log))
				if addr not in client_keys:
					client_keys[addr] = conn.recv(1024).decode('UTF-8')
					if client_keys[addr] == b'': ## checking if data is empty
						break
					conn.sendall(bytes(public_pem,'UTF-8'))
					recv_log.append(f"clientkey[{addr}]")
				data = conn.recv(1024)
				print(data)
				print(data.decode('UTF-8'))
				print('Recv_log: '+str(recv_log))
				if data == b'': ## checking if data is empty
					break
				else:
					
					s_pr_key = RSA.import_key(private_pem)
					s_pu_key = RSA.import_key(public_pem)
					c_pu_key = RSA.import_key(client_keys[addr])
					d = PKCS1_OAEP.new(key=s_pr_key)
					message = data
					##decrypted_message = d.decrypt(data)
					client_cipher = PKCS1_OAEP.new(key=c_pu_key)
				
					
					if message == b'ls':
						print('x')
						## chatroom list request
						chatroom_data = utils.fetch_chatroom_data()
						encrypted_message = client_cipher.encrypt(chatroom_data)
						conn.sendall(encrypted_message)
						
					elif message == b'1':
						## chatroom room info request
						data = conn.recv(64)
						if data in chatroom_data.split():
							encrypted_message = client_cipher.encrypt(open(str(data)+'.txt','r').read())
							conn.sendall(encrypted_message)
							
					elif message == b'2':
						## read current nicknames
						encrypted_message = client_cipher.encrypt(open('nicknames.txt','r').read())
						conn.sendall(encrypted_message)
						
					elif message == b'writenick':
						print('Writing nick...')
						## write new nickname
						new_nickname = d.decrypt(conn.recv(128)).decode('UTF-8')
						with open('nicknames/nicknames.txt','a') as f:
							f.write('\n')
							f.write(str(new_nickname))
							
					elif message == b'-1':
						 ## null
						 break
						
					
					recv_log.append(message)
					##conn.sendall(decrypted_message)
					
input()
