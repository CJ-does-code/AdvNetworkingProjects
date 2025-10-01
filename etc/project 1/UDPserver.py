#!/usr/bin/env python3

#Project 1
#Name: Sriram Krishnamoorthy
#OS: Linux Ubuntu 22.04
#Programming language: Python 3.10.2

from socket import *
import cv2
from PIL import Image
import io
import time
import sys
import argparse
import string
import socket

serverSocket = socket.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) # create client to communicate with the UDP server

serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1) # enable multiple clients to share one address and port
#serverSocket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
serverAddress = "10.34.106.16"
serverSocket.bind((serverAddress, 8080)) # set the server to receive from multiple clients at a time, with outgoing time being 1 second
print("Network started at address ", serverAddress)

packetSize = 1024
clients_in_queue_names = [] # array to keep track of names of clients that contacted server and have not received an acknowledgement back
clients_in_queue_ports = [] # array to keep track of ports of clients that contacted server and have not received an acknowledgement back

received_nothing_yet = True # have we received messages from any clients yet?
while True:
	clientName, clientAddr = serverSocket.recvfrom(1024) # wait to receive message from any client
	clients_in_queue_names.append(clientName) # add to the client names array
	clients_in_queue_ports.append(clientAddr) # add to the client addresses array
	if (clientName): # if received a message, which should be the client name
		if (received_nothing_yet):
			msg = "Found client(s):\n"
			received_nothing_yet = True
		clientmsg = msg + ": PING\n"
		for client in clients_in_queue_names:
			clientPort = clients_in_queue_ports[clients_in_queue_names.index(clientName)]
			serverSocket.sendto(clientmsg.encode(), (clientName, clientPort)) # send back to client address
	full_client_ack_msg = ""
	for client in clients_in_queue_names:
		recvClientName, recvClientAddr = serverSocket.recvfrom(1024) # wait to receive message from any client
		if (recvClientName): # if message is received from a client in the queue
			clientmsg = recvClientName + ": PONG\n"
			full_client_ack_msg += clientmsg
		serverSocket.sendto(full_client_ack_msg.encode(), (recvClientName, recvClientAddr)) # send back to client address
	clients_in_queue_names = []
	clients_in_queue_ports = []	
serverSocket.close()