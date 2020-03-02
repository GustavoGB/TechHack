import logging  
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import sys

import socket

from scapy.all import *

import ipaddress


if len(sys.argv) != 4:
    print("Uso: %s alvo portaSocket rede" % (sys.argv[0]))
    print("O range de portas será dado como input do programa")
    sys.exit(0)

alvo = ipaddress.IPv4Address(sys.argv[1])
portaSocket = int(sys.argv[2])
rede = ipaddress.ip_network(sys.argv[3])

portaInicial = int(input("Digite a primeira porta a ser escaneada\n"))
portaFinal = int(input("Digite a última porta a ser escaneada\n"))


tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

tcp.settimeout(5)

destino = (alvo,portaSocket)

print("Escaneando "+ str(alvo) +" para portas TCP\n")

if portaInicial == portaFinal:
    portaFinal += 1

if portaInicial > portaFinal:
    print("Porta final deve ser menor que porta inicial a ser escaneada")
    sys.exit(0)


## Escanear a rede
for ips in rede:
    ## Escanear as portas
    for p in range(portaInicial,portaFinal):
        if tcp.connect_ex((str(alvo),portaSocket)):
            print("The port is closed") 
            
        else:
            print("The port number.{0}",p)
            print(p)

print("Escaneamento completo!")
    
