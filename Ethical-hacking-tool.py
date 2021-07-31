# -*- coding: utf-8 -*-

import nmap
import hashlib
from struct import *
from distlib.compat import raw_input
from scapy.all import *
import socket
import os


def escaner ():
    ns = nmap.PortScanner()
    ip = raw_input("Introduzca la IP que desea escanear: \n")  # 192.168.0.1
    ns.scan(ip, '1-1024', '-v --version-all')

    os.system('clear')

    print(" -- INFORMACION RECOLECTADA --\n")
    print("Estadisticas generales: ")
    print(ns.scanstats())
    print("Informacion adicional: ")
    print(ns.scaninfo())
    print("Tipo de escaneo realizado: ")
    print(ns.command_line())

    print("\n Estado del HOST")
    print("***************")
    print(ns[ip].state())
    print("\n")

    print("Protocolos")
    print("**********")
    print(ns[ip].all_protocols())
    print("\n")

    print("Puertos abiertos")
    print("****************")
    print(ns.csv())
    print("\n")

    print("Nombre del host/router")
    print("**********************")
    print(ns[ip].hostname())


def cracker():
    counter = 1
    objetivo = raw_input("Ingresar el hash MD5: ")  # c893bad68927b457dbed39460e6afd62
    diccionario = raw_input("Ingresar ruta del diccionario a utilizar: ")   # /home/nick/Documentos/Diccionario

    try:
        diccionario = open(diccionario, "r")
    except:
        print("\n Diccionario no encontrado")
        quit()

    os.system('clear')

    for password in diccionario:  # Toma cada password del diccionario.
        filemd5 = hashlib.md5(password.strip().encode('utf-8')).hexdigest()
        print("\n Intentando password numero %d: " %counter)

        counter += 1

        if objetivo == filemd5:
            print("\n Coincidencia encontrada: \n el password es: %s" %password)
            break
        else:
            print("Password no encontrado.")


def sniffer():
    os.system('clear')

    # Convierte un STRING de 6 caracteres de una direccion Ethernet, en un STRING hexadecimal (para dar formato de direccion Mac)

    def eth_addr(a):
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0], a[1], a[2], a[3], a[4], a[5])
        return b

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except socket.error as msg:
        print('ERROR DE SOCKET : ' + str(msg[0]) + ' MENSAJE: ' + msg[1])
        sys.exit()

    # Recibir paquete
    while True:
        packet = s.recvfrom(65565)
        packet = packet[0]

        eth_length = 14
        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])

        print('DESTINO: ' + eth_addr(packet[0:6]) + ' ORIGEN: ' + eth_addr(packet[6:12]) + ' PROTOCOLO: ' + str(
            eth_protocol))

        # IMPRESION DEL HEADER DE LA IPV4
        if eth_protocol == 8:
            ip_header = packet[eth_length:20 + eth_length]
            iph = unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF

            iph_length = ihl * 4

            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])

            print('Version : ' + str(version) + ' Longitud De La Cabecera : ' + str(ihl) + ' TTL : ' + str(
                ttl) + ' Protocolo : ' + str(protocol) + ' Direccion De Origen: ' + str(
                s_addr) + ' Direccion De Destino: ' + str(d_addr))

            # PROTOCOLO TCP
            if protocol == 6:
                t = iph_length + eth_length
                tcp_header = packet[t:t + 20]

                tcph = unpack('!HHLLBBHHH', tcp_header)

                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4

                print(' Puerto Origen: ' + str(source_port) + ' Puerto Destino : ' + str(
                    dest_port) + ' Secuencia: ' + str(sequence) + ' Confirmacion: ' + str(
                    acknowledgement) + ' Logitud De Cabecera TCP: ' + str(tcph_length))

                h_size = eth_length + iph_length + tcph_length * 4
                data_size = len(packet) - h_size

                print("Data: \n")
                data = packet[h_size:]

                print(data)

            # PROTOCOLO ICMP
            elif protocol == 1:
                u = iph_length + eth_length
                icmph_length = 4
                icmp_header = packet[u:u + 4]

                icmph = unpack('!BBH', icmp_header)

                icmp_type = icmph[0]
                code = icmph[1]
                checksum = icmph[2]

                print('Tipo: ' + str(icmp_type) + ' Codigo: ' + str(code) + ' Suma De Verificacion: ' + str(checksum))

                h_size = eth_length + iph_length + icmph_length
                data_size = len(packet) - h_size

                print("Data: \n")
                data = packet[h_size:]

                print(data)

            # PROTOCOLO UDP
            elif protocol == 17:
                u = iph_length + eth_length
                udph_length = 8
                udp_header = packet[u:u + 8]

                udph = unpack('!HHHH', udp_header)

                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]

                print('Puerto Origen: ' + str(source_port) + ' Puerto Destino: ' + str(dest_port) + ' Longitud: ' + str(
                    length) + ' Suma De Verificacion: ' + str(checksum))

                h_size = eth_length + iph_length + udph_length
                data_size = len(packet) - h_size

                print("Data: \n")
                data = packet[h_size:]

                print(data)

            # OTROS PROTOCOLOS
            else:
                print('Protocolo distinto de: TCP/UDP/ICMP')


def menu():
    op = 0

    while op!=1:
        print("------------------------")
        print("     Herramientas: \n")
        print("1. Salir")
        print("2. Escaner")
        print("3. MD5 Hash Cracker")
        print("4. Sniffer")
        print("------------------------")

        op = int(raw_input("Ingresar opcion: "))

        if op == 2:
            escaner()
        if op == 3:
            cracker()
        if op == 4:
            sniffer()

# PRINCIPAL


menu()
