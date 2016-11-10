import socket
import sys
import struct
import hashlib
import math
# The following libraries should be installed before executing
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Construct a TCP socket
HOST, ALICE_PORT, BOB_PORT = "140.113.194.88", 50000, 50500

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock2alice:
	# Connect to Alice
	sock2alice.connect((HOST, ALICE_PORT))

	# Send ID to Alice
	msg_size = len("0216023")
	byte_msg_size = struct.pack("i", msg_size)
	sock2alice.sendall( byte_msg_size )
	sock2alice.sendall(bytes("0216023", 'utf-8'))
	print('I send 0216023 to alice')

	# Receive hello from Alice
	msg_size = struct.unpack('i', sock2alice.recv(4))
	received = str(sock2alice.recv(int(msg_size[0])), "utf-8")
	print('Alice send ', received)

	# Connect to bob
	sock2bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock2bob.connect((HOST, BOB_PORT))

	# Send hello to Bob
	msg_size = len("hello")
	byte_msg_size = struct.pack("i", msg_size)
	sock2bob.sendall( byte_msg_size )
	sock2bob.sendall(bytes("hello", 'utf-8'))
	print('I send hello to Bob')

	# Receive public key from Bob
	msg_size = struct.unpack('i', sock2bob.recv(4))
	BobPubKey = str(sock2bob.recv(int(msg_size[0])), "utf-8")
	print('Bob\'s key :\n', BobPubKey)
	with open('Bob.pem', 'w') as f:
		f.write(BobPubKey)
		f.close()

	# Send public pem file to Alice
	with open('public.pem', 'rb') as f:
		myPubKey = serialization.load_pem_public_key(
			f.read(),
			backend=default_backend()
		)
		f.close()
	myPubPem = myPubKey.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)
	msg_size = len(str(myPubPem, 'utf-8'))
	byte_msg_size = struct.pack('i', msg_size)
	sock2alice.sendall(byte_msg_size)
	sock2alice.sendall(myPubPem)
	print('I send my RSA public key to Alice :\n', str(myPubPem, 'utf-8'))

	# Receive AES Session Key from Alice
	msg_size = struct.unpack('i', sock2alice.recv(4))
	encryptedAESKey = sock2alice.recv(int(msg_size[0]))
	print('Received C1 from Alice :\n', encryptedAESKey)
	with open('private.pem', 'rb') as f:
		myPriKey = serialization.load_pem_private_key(
			f.read(),
			password=None, 
			backend=default_backend()
		)
		f.close()
	AESKey = myPriKey.decrypt(
	    encryptedAESKey,
	    padding.OAEP(
	        mgf=padding.MGF1(algorithm=hashes.SHA1()),
	        algorithm=hashes.SHA1(),
	        label=None
	    )
	)
	print('Alice\'s AES Session Key :\n', AESKey)

	# Receive Initial Vector from Alice
	msg_size = struct.unpack('i', sock2alice.recv(4))
	encryptedIV = sock2alice.recv(int(msg_size[0]))
	print('Received C2 from Alice :\n', encryptedIV)
	IV = myPriKey.decrypt(
	    encryptedIV,
	    padding.OAEP(
	        mgf=padding.MGF1(algorithm=hashes.SHA1()),
	        algorithm=hashes.SHA1(),
	        label=None
	    )
	)
	print('Initial Vector :\n', IV)

	# Receive request from Alice
	msg_size = struct.unpack('i', sock2alice.recv(4))
	encryptedReq = sock2alice.recv(int(msg_size[0]))
	print('Received C4 :\n', encryptedReq)
	cipher = Cipher(algorithms.AES(AESKey), modes.CBC(IV), backend=default_backend())
	decryptor = cipher.decryptor()
	req = decryptor.update(encryptedReq) + decryptor.finalize()
	print('Request :\n', str(req))

	# Send AES Session Key to Bob
	with open('Bob.pem', 'rb') as f:
		BobPubKey = serialization.load_pem_public_key(
			f.read(),
			backend=default_backend()
		)
		f.close()
	encryptedAESKey = BobPubKey.encrypt(
		bytes(AESKey),
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA1()),
	        algorithm=hashes.SHA1(),
        	label=None
		)
	)
	msg_size = len(encryptedAESKey)
	byte_msg_size = struct.pack('i', msg_size)
	sock2bob.sendall(byte_msg_size)
	sock2bob.sendall(encryptedAESKey)
	print('I send encrypted AES session key to Bob :\n', str(encryptedAESKey))

	# Send Initial Vector to Bob
	encryptedIV = BobPubKey.encrypt(
		bytes(IV),
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA1()),
	        algorithm=hashes.SHA1(),
        	label=None
		)
	)
	msg_size = len(encryptedIV)
	byte_msg_size = struct.pack('i', msg_size)
	sock2bob.sendall(byte_msg_size)
	sock2bob.sendall(encryptedIV)
	print('I send encrypted Initial Vector to Bob :\n', str(encryptedIV))

	# Send Request to Bob
	msg_size = len(encryptedReq)
	byte_msg_size = struct.pack('i', msg_size)
	sock2bob.sendall(byte_msg_size)
	sock2bob.sendall(encryptedReq)
	print('I send encrypted request to Bob :\n', str(encryptedReq))

	# Receive Response from Bob
	msg_size = struct.unpack('i', sock2bob.recv(4))
	encryptedRes = sock2bob.recv(int(msg_size[0]))
	print('Received C7 :\n', encryptedRes)
	cipher = Cipher(algorithms.AES(AESKey), modes.CBC(IV), backend=default_backend())
	decryptor = cipher.decryptor()
	res = decryptor.update(encryptedRes) + decryptor.finalize()
	print('Response :\n', str(res))

	# Receive bye from Bob
	msg_size = struct.unpack("i", sock2bob.recv(4))
	received = str(sock2bob.recv(int(msg_size[0])), "utf-8")
	print(received)

	# Send Response to Alice
	msg_size = len(encryptedRes)
	byte_msg_size = struct.pack('i', msg_size)
	sock2alice.sendall(byte_msg_size)
	sock2alice.sendall(encryptedRes)
	print('I send encrypted response to Alice :\n', str(encryptedRes))
	
	# Send bye to Alice
	msg_size = len("bye")
	byte_msg_size = struct.pack("i", msg_size)
	sock2alice.sendall( byte_msg_size )
	sock2alice.sendall(bytes("bye", 'utf-8'))
	print('I send bye to alice')

###############
print('---------------------------')
print('-------I am divider--------')
print('---------------------------')


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock2bob:
	# Connect to Bob
	sock2bob.connect((HOST, BOB_PORT))

	# Send hello to Bob
	msg_size = len("hello")
	byte_msg_size = struct.pack("i", msg_size)
	sock2bob.sendall( byte_msg_size )
	sock2bob.sendall(bytes("hello", 'utf-8'))
	print('I send hello to Bob')

	# Receive public key from Bob
	msg_size = struct.unpack('i', sock2bob.recv(4))
	BobPubKey = str(sock2bob.recv(int(msg_size[0])), "utf-8")
	print('Bob\'s key :\n', BobPubKey)
	with open('Bob.pem', 'w') as f:
		f.write(BobPubKey)
		f.close()

	# Send AES Session Key to Bob
	with open('Bob.pem', 'rb') as f:
		BobPubKey = serialization.load_pem_public_key(
			f.read(),
			backend=default_backend()
		)
		f.close()
	encryptedAESKey = BobPubKey.encrypt(
		bytes(AESKey),
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA1()),
	        algorithm=hashes.SHA1(),
        	label=None
		)
	)
	msg_size = len(encryptedAESKey)
	byte_msg_size = struct.pack('i', msg_size)
	sock2bob.sendall(byte_msg_size)
	sock2bob.sendall(encryptedAESKey)
	print('I send encrypted AES session key to Bob :\n', str(encryptedAESKey))

	# Send Initial Vector to Bob
	encryptedIV = BobPubKey.encrypt(
		bytes(IV),
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA1()),
	        algorithm=hashes.SHA1(),
        	label=None
		)
	)
	msg_size = len(encryptedIV)
	byte_msg_size = struct.pack('i', msg_size)
	sock2bob.sendall(byte_msg_size)
	sock2bob.sendall(encryptedIV)
	print('I send encrypted Initial Vector to Bob :\n', str(encryptedIV))

	# Send Request to Bob
	h = hashlib.sha256(b"0216023").hexdigest()
	req = '{"Account_ID": "0216023", "Authentication_Code": "' + h + '", "Favorite_Snack": "PineApplePie", "Account_Money": "0", "Remark": "If you have any question, please mail to any TA ASAP.", "Feedback": "How is the midterm exam? Good?", "Favorite_Fruit": "Apple", "Favorite_Song": ["P", "P", "A", "P"]}' + (' ' * 1)
	cipher = Cipher(algorithms.AES(AESKey), modes.CBC(IV), backend=default_backend())
	encryptor = cipher.encryptor()
	encryptedReq = encryptor.update(bytes(req, 'utf-8')) + encryptor.finalize()
	msg_size = len(encryptedReq)
	byte_msg_size = struct.pack('i', msg_size)
	sock2bob.sendall(byte_msg_size)
	sock2bob.sendall(encryptedReq)
	print('I send encrypted request to Bob :\n', str(encryptedReq))

	# Receive Response from Bob
	msg_size = struct.unpack('i', sock2bob.recv(4))
	encryptedRes = sock2bob.recv(int(msg_size[0]))
	print('Received C7 :\n', encryptedRes)
	cipher = Cipher(algorithms.AES(AESKey), modes.CBC(IV), backend=default_backend())
	decryptor = cipher.decryptor()
	res = decryptor.update(encryptedRes) + decryptor.finalize()
	print('Response :\n', str(res))

	# Receive bye from Bob
	msg_size = struct.unpack("i", sock2bob.recv(4))
	received = str(sock2bob.recv(int(msg_size[0])), "utf-8")
	print(received)
