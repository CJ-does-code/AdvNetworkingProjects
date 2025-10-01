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

# client program
# broadcasts messages to network and all clients
parser = argparse.ArgumentParser(prog='UDPServer.py', description='Network program for address connection.')
parser.add_argument("--network", type=str, help="Network IP address to connect to when receiving message")
parser.add_argument("--name", type=str, help="Name of network to connect to")
args = parser.parse_args()

serverAddress = ("10.34.106.16", 8080)
clientAddress = (args.network, 8080)
clientName = args.name
clientPort = args.network
clientSocket = socket.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) # create client to communicate with the UDP server
clientSocket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1) # enable broadcasting so it can send the message to all clients as well 
broadcast_address = (serverAddress, 65432)

print("Registered with name "+args.network)
message = clientName + "\n"
clientSocket.sendto(message.encode(), serverAddress) # send the name of the client to the network
msg, serverPort = clientSocket.recvfrom(1024)
print(msg)