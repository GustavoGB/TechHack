# TechHack Roteiro

## Parte 1.1 a
   Encontrar o IP do alvo...

   Para conseguir o IP do alvo, é necessário conectar as duas VMS em uma mesma rede. 
   Dessa forma, utiliza-se o seguinte comando para saber qual sub-rede as duas máquinas estão conectadas. 

   ```bash 
   $ ifconfig 
   ```
   Depois de rodar este comando na máquina do atacante, descobre-se que a sub-rede em que ambos as máquinas estão ligadas é /24 . Já que a máscara encontrada é 255.255.255.0

   Com isso é possível utilizar outro comando que será responsável por mostrar todos os IPs dentro dessa sub-rede /24. 

   ```bash 
   $ netdiscover -r 192.168.0.0/24
   ```

Com a captura de tela do comando, é possível ver quantos endereços IPS estão conectados nesta sub-rede :
![](netdiscover.png)

Dentro da sub-red todos os Vendors são normais como computadores, celulares tabletes etc, porém ao analisar *PCS systemtechnik GmbH* percebe-se que o alvo possivelmente é este HostName. 
    Assim pega-se o IP deste endereço:
    
     IP do alvo: 192.168.0.12   


## Parte 1.1. b

Descobrir qual a versão do sistema operacional do alvo, qual é este sistema e em qual porta este processo está rodando.

Com o IP conseguido anteriormente, **192.168.0.12**, realiza-se uma fase de reconhecimento para conseguir mais informações sobre o alvo em questão.

Com o auxílio da ferramenta telnet consegue-se saber todas as informações desejadas para esta etapa utilizando o comando:

```bash 
   $ telnet 192.168.0.12 21
```

O Telnet nos dirá um pouco mais sobre o IP que está sendo analisado, enquanto o 21 depois significa que realizamos uma conexão com a porta ftp do alvo. Esta porta é extremamente vulnerável devido ao fato do protocolo ftp apresentar vulnerabilidades altas comparadas com o http. 

![](telnet.png)

Com isso conseguimos :

- Porta que este processo está rodando: 220
- O nome : ProFTPD
- Versão do sistema operacional : 1.3.5 Server (Debian)


## Parte 1.1 c

Vamos continuar buscando mais informações sobre o alvo, dessa vez, iremos utlizar o commando **nmap** com o objetivo de descobrir exatamente quais portas do alvo estão abertas para podermos realizar algum tipo de inspeção.

Assim, ao utilizar :

```bash 
   $ nmap -A 192.168.0.12
```
Tem-se a possibilidade de obter mais informações sobre o alvo. 
Este comando é realmente muito poderoso e da muita flexibilidade pro atacante vide o leque de infos que ele adquiriu. A foto abaixo mostra os resultados do comando : 

Primeira foto mostra as portas que estão operando no alvo:


![](nmap.png)

Enquanto a segunda mostra coisas como versão do Host, MAC address versão do kernel utilizado entre outros:


![](nmap2.png)


## Parte 1.1 d

Para finalizar esta etapa foi necessário desenvolver um app simples de escaneamento de portas em um certo range de Ips. Isto é, sabendo um alvo, ainda é necessário acessar um IP inicial e um IP final e verificar as portas do alvo neste meio. Além disso, escolhe-se a porta para realizar a socket na linha de comando, assim como o IP do alvo. Dessa forma, ao rodar o programa teremos 3 argumentos:
- scrappyScanner.py
- Ip alvo (192.168.0.12)
- 80 (porta socket)

Depois disso, o programa pedirá para colocar um IP inicial e um IP final, assim como uma porta inicial e uma porta final para serem varridas.

 ```python
import logging  
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import sys

import socket

from scapy.all import *

if len(sys.argv) != 3:
    print("Uso: %s alvo portaSocket " % (sys.argv[0]))
    print("O range de portas será dado como input do programa")
    sys.exit(0)

alvo = str(sys.argv[1])
portaSocket = str(sys.argv[2])

ipInicial = inet_ntoa(input("Digite o primeiro IP para comecar a varredura\n"))
ipFinal   = inet_ntoa(input("Digite o ultimo IP para comecar varredura \n"))


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
        tcp.connect(destino)
    resposta_pacote = sr1(tcp,timeout=0.5,verbose=0) ## 0x12 significa o sinal syn-ack(funcao sr para send)
    if resposta_pacote == 0x12: 
        print('Portas'+str(p)+'estão abertas')
    sr1(tcp,timeout=0.5,verbose=0)  

print("Escaneamento completo!")

   ```