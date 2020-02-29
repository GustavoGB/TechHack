import logging  
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import sys

import socket

from scapy.all import *

import ipaddress

#import netaddr import * 

if len(sys.argv) != 3:
    print("Uso: %s alvo portaSocket " % (sys.argv[0]))
    print("O range de portas será dado como input do programa")
    sys.exit(0)

alvo = str(sys.argv[1])
portaSocket = int(sys.argv[2])



portaInicial = int(input("Digite a primeira porta a ser escaneada\n"))
portaFinal = int(input("Digite a última porta a ser escaneada\n"))


tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


destino = (alvo,portaSocket)

print("Escaneando "+alvo+" para portas TCP\n")

if portaInicial == portaFinal:
    portaFinal += 1

if portaInicial > portaFinal:
    print("Porta final deve ser menor que porta inicial a ser escaneada")
    sys.exit(0)


## Escanear a rede
for ips in ipaddress.IPv4Network('192.168.1.0/24'):
    ## Escanear as portas
    for p in range(portaInicial,portaFinal):
        if tcp.connect_ex((alvo,portaSocket)):
            print("The port is closed") 
        else:
            print("This are the open ports")
            print(p)

print("Escaneamento completo!")
    
