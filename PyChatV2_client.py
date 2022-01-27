import socket,sys,os
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

# CLIENT KEYS
client_private_key = RSA.generate(1024)
client_public_key = client_private_key.publickey()

# SERVER KEY
global server_public_key
server_public_key = None
first_connection = True

private_pem = client_private_key.export_key().decode()
public_pem = client_public_key.export_key().decode()

# METHODS

def request_data(message):
	global server_public_key
	message = bytes(message,'UTF-8')
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.connect((HOST, PORT))
		s.sendall(bytes(public_pem,'UTF-8'))
		if not server_public_key:
			server_public_key = s.recv(1024)
		c_pr_key = RSA.import_key(private_pem)
		d = PKCS1_OAEP.new(c_pr_key)
		s.sendall(message)
		if message == b'ls':
			print('x')
			data = d.decrypt(s.recv(1024)).decode('UTF-8')
		return data
		
def write_nickname(message,arg1):
	global server_public_key
	global first_connection
	message = bytes(str(message),'UTF-8')
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.connect((HOST, PORT))
		s.sendall(bytes(public_pem,'UTF-8'))
		if not server_public_key:
			server_public_key = s.recv(1024)
		c_pr_key = RSA.import_key(private_pem)
		c_pu_key = RSA.import_key(public_pem)
		s_pu_key = RSA.import_key(server_public_key.decode('UTF-8'))
		server_cipher = PKCS1_OAEP.new(key=s_pu_key)
		s.sendall(message)
		encrypted_message = server_cipher.encrypt(bytes(arg1,'UTF=8')) ## 128 long
		s.sendall(encrypted_message)

## PROGRAM START

clear = lambda: os.system('cls')
title = [                                                                                                           
",-.----.                                                                                                   ",
"\    /  \                     ,----..    ,---,                   ___                              ,----,   ",
"|   :    \                   /   /   \ ,--.' |                 ,--.'|_                 ,---.    .'   .' \  ",
"|   |  .\ :                 |   :     :|  |  :                 |  | :,'               /__./|  ,----,'    | ",
".   :  |: |                 .   |  ;. /:  :  :                 :  : ' :          ,---.;  ; |  |    :  .  ; ",
"|   |   \ :    .--,         .   ; /--` :  |  |,--.  ,--.--.  .;__,'  /          /___/ \  | |  ;    |.'  /  ",
"|   : .   /  /_ ./|         ;   | ;    |  :  '   | /       \ |  |   |           \   ;  \ ' |  `----'/  ;   ",
";   | |`-', ' , ' :         |   : |    |  |   /' :.--.  .-. |:__,'| :            \   \  \: |    /  ;  /    ",
"|   | ;  /___/ \: |         .   | '___ '  :  | | | \__\/: . .  '  : |__           ;   \  ' .   ;  /  /-,   ",
":   ' |   .  \  ' |         '   ; : .'||  |  ' | : ,' .--.; |  |  | '.'|           \   \   '  /  /  /.`|   ",
":   : :    \  ;   :         '   | '/  :|  :  :_:,'/  /  ,.  |  ;  :    ;            \   `  ;./__;      :   ",
"|   | :     \  \  ;         |   :    / |  | ,'   ;  :   .'   \ |  ,   /              :   \ ||   :    .'    ",
"`---'.|      :  \  \         \   \ .'  `--''     |  ,     .-./  ---`-'                '---' ;   | .'       ",
"  `---`       \  ' ;          `---`               `--`---'                                  `---'          ",
"               `--`                                                                                      "]

for line in title:
	print(line)
print('By 0x01FE')
print()
print('Press any key to begin')
input()
clear()
while True:
	print('<------------------------------>')
	print('Welcome to PyChat V2!')
	print()
	user_nickname = input('What would you like your nickname to be? ')
	if len(user_nickname) <= 12 and len(user_nickname) < 0:
		print('Your nickname cannot be over 12 characters long or under 1 character.')
	else:
		write_nickname("writenick",user_nickname)
		response = request_data("ls")
		print(response)
		break

	

