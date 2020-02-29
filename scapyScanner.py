import logging  
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import sys

import socket

from scapy.all import *

##import ipaddress

import netaddr import * 

if len(sys.argv) != 3:
    print("Uso: %s alvo portaSocket " % (sys.argv[0]))
    print("O range de portas será dado como input do programa")
    sys.exit(0)

alvo = str(sys.argv[1])
portaSocket = str(sys.argv[2])

ipInicial = IPAddress(input("Digite o primeiro IP para comecar a varredura\n"))
ipFinal   = IPAddress(input("Digite o ultimo IP para \n"))



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
for ips in range(ipInicial,ipFinal):
    ## Escanear as portas
    for p in range(portaInicial,portaFinal):
        if tcp.connect_ex((alvo,portaSocket)):
            print("The port is closed") 
        else:
            resposta_pacote = sr1(tcp,timeout=0.5,verbose=0) ## 0x12 significa o sinal syn-ack(funcao sr para send)
            if resposta_pacote == 0x12: 
                print('Portas'+str(p)+'estão abertas')
            sr1(tcp,timeout=0.5,verbose=0)  

print("Escaneamento completo!")
    
