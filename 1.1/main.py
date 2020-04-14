#!/usr/bin/python

import socket 
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # setar a classe socket para pegar o inet = ipv4 e sock stream para tcp

s.settimeout(5)

host_target = input("Input the IP for the research\n") # Recebe o IP que quer ser analisado como argumento
port_target = int(input("Input the port your want to see if it's open or not\n")) # Recebe a porta que quer ser analisada como argumento 

def scanPort(port):
    if s.connect_ex((host_target,port_target)):
        print("The port is closed") 
    else:
        print("The port is open")

scanPort(port_target)

