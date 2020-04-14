#!/usr/bin/python
import logging  
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
import socket
from scapy.all import *
import ipaddress

def tcpScan(alvo,portaSocket,rede,portaInicial,portaFinal):
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.settimeout(5) # Timeout caso a rede conect
    print("Escaneando "+ str(alvo) +" para portas TCP\n")
    ## Escanear a rede
    for ips in rede:
        ## Escanear as portas
        for p in range(portaInicial,portaFinal):
            if tcp.connect((str(alvo),portaSocket)):
                print("Connect to port number.{0}",p) 
            else:
                # Se as portas estiverem fechadas ira dar um erro de Traceback do proprio script falando que o acesso nao foi permitido
                raise Exception("Connection refused")
                print("The port " + str(p) + " is closed, could't connect")
    print("Escaneamento completo!")

def udpScan(alvo,portaSocket,rede,portaInicial,portaFinal):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(5) # Timeout caso a rede conect
    print("Escaneando "+ str(alvo) +" para portas TCP\n")
    ## Escanear a rede
    for ips in rede:
        ## Escanear as portas
        for p in range(portaInicial,portaFinal):
            if udp.connect((str(alvo),portaSocket)):
                print("Connect to port number.{0}",p) 
            else:
                # Se as portas estiverem fechadas ira dar um erro de Traceback do proprio script falando que o acesso nao foi permitido
                raise Exception("Connection refused")
                print("The port " + str(p) + " is closed, could't connect")
    print("Escaneamento completo!")


## 192.168.0.2 localhost, ver os meus proprios servicos pro teste
  def main():
    if len(sys.argv) != 4:
        print("Uso: %s alvo portaSocket rede" % (sys.argv[0]))
        print("O range de portas será dado como input do programa")
        sys.exit(0)

    alvo = ipaddress.IPv4Address(sys.argv[1])
    portaSocket = int(sys.argv[2])
    rede = ipaddress.ip_network(sys.argv[3])

    portaInicial = int(input("Digite a primeira porta a ser escaneada\n"))
    portaFinal = int(input("Digite a última porta a ser escaneada\n"))

    # Verificar se as portas nao sao iguais
    if portaInicial == portaFinal:
        portaFinal += 1

    elif portaInicial > portaFinal:
        print("Porta final deve ser menor que porta inicial a ser escaneada")
        sys.exit(0)

if __name__ == "__main__":
    main()