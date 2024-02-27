import socket 
import os
import struct
import sys
import ipaddress
import threading
import time
import argparse
import textwrap



class IP_HEADER:
    def __init__(self, buffer=None):
        header = struct.unpack('<BBHHHBBH4s4s', buffer) #define struct
        
        #** PACKET-STRUCTURE **#
        self.ver = header[0] >> 4 #Version
        self.ihl = header[0] & 0xF #Header length
        self.tos = header[1] #Type of service
        self.len = header[2] #length of packet
        self.id = header[3] #identification
        self.offset = header[4] #fragment offset
        self.ttl = header[5] #time to live
        self.protocol_number = header[6] #protocol number
        self.sum = header[7] #checksum
        self.src = header[8] #source IP
        self.dst = header[9] #destination

        #Convert Ip Addresses to human readable representation
        self.source_addr = ipaddress.ip_address(self.src)
        self.destination_addr = ipaddress.ip_address(self.dst)

        self.protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            2: "IGMP",
            58: "ICMPv6",
            51: "IPV6 AH",
            50: "IPV6 ESP"} 
        
        try:
            self.protocol = self.protocol_map[self.protocol_number]
        except Exception as e:
            print('[!] Exception: ', e)
            print('[!] Invalid Protocol Number Recieved: ', self.protocol_number)
            self.protocol = str(self.protocol_number)



def dump_hex(src, length=16, display=True):
    
    res = []

    for i in range(0, len(src), length):
        chunk = src[i:i+length]

        hexa = ' '.join([f'{byte:02X}' for byte in chunk])

        printable = ''.join([chr(byte) if 32 <= byte < 127 else '.' for byte in chunk])

        width = length * 3
        res.append(f'{i:04x}  {hexa:<{width}}  {printable}')
   
    if display:
        for i in res:
            print(i)

    return res



def sniff(sock, args, filename):

    #enable raw packet inspection if on windows
    if os.name == 'nt':
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    filepath = None
    if args.dump:
        filepath = args.dump + filename


    try:
        while True:
            raw_bytes = sock.recvfrom(65535)[0]
            ip_header = IP_HEADER(raw_bytes[0:20])
            output_str = ''

            if args.verbose:
                
                output_str = ('-- INCOMING PACKET --\n' + 
                    f'\t-Protocol> {ip_header.protocol}\n' +
                    f'\t-Desination> {ip_header.destination_addr}\n' +
                    f'\tSource> {ip_header.source_addr}\n' +
                    f'\tTTL> {ip_header.ttl}\n')
                
                output_str += '\nHEADER:\n'
                header_dmp = dump_hex(raw_bytes[0:20], 16, False)

                for line in header_dmp:
                    output_str += line + '\n'

                output_str += '\nBODY:\n'
                body_offset = ip_header.ihl * 4
                body_dmp = dump_hex(raw_bytes[body_offset:ip_header.len], 16, False)
                
                for line in body_dmp:
                    output_str += line + '\n'

                output_str += '\n-- PACKET END --\n\n'

            else:
                output_str = f'Pkt: proto={ip_header.protocol} dest={ip_header.destination_addr} src={ip_header.source_addr} TTL={ip_header.ttl}\n'

            if args.print:
                print(output_str, end='')

            if filepath:
                with open(filepath, 'a+') as f:
                    f.write(output_str)                


    #Should only trigger if running on windows.
    except KeyboardInterrupt:
        
        if os.name == 'nt':
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        
        sock.close()        



def get_private_ip()->str:
    private_ip = None
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 0))
        
        private_ip = sock.getsockname()[0]

    except socket.error as e:
        print(f'[!] Exception while retrieving private IP: {e}')
        sock.close()
        sys.exit(0)

    sock.close()
    return private_ip



def initialize_socket(host, socket_protocol):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sock.bind((host, 0))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    return sock



def main():

    parser = argparse.ArgumentParser(
        description='-- Urien\'s Packet Sniffer --',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
        sniffpackets.py -d=myfolder/packets/ #dump packets to this folder. ALWAYS INCLUDE TRAILING SLASH.
        sniffpackets.py -v -p #display packets in verbose mode (shows raw bytes and ascii), and print them to the console.
        sniffpackets.py -p #print packet metadata only, no raw bytes.
        
        '''))

    parser.add_argument('-d', '--dump', help='dump packets into this folder. ALWAYS include trailing slash.')
    parser.add_argument('-v', '--verbose', action='store_true', help='display raw bytes of packets')
    parser.add_argument('-p', '--print', action='store_true', help='print packets to the console')

    args = parser.parse_args()

    if not args.dump and not args.print:
        print('[!] Invalid arguments. Packets must be dumped or printed.')
        print('[!] Use sniffpackets.py --help for more information.')
        sys.exit()



    private_ip = get_private_ip()
    if private_ip:
        print('[+] Binding...')
        
        if os.name == 'nt':
            sniff(initialize_socket(private_ip, socket.IPPROTO_IP), args, 'pkts_general')

        else:

            # Due to linux requiring us to specify the raw socket type,
            # we need to handle multiple sockets at once, instead of just one.

            threads = []

            icmp_socket = initialize_socket(private_ip, socket.IPPROTO_ICMP)
            tcp_socket = initialize_socket(private_ip, socket.IPPROTO_TCP)
            udp_socket = initialize_socket(private_ip, socket.IPPROTO_UDP)

            icmp_thread = threading.Thread(
                target=sniff,
                args=(icmp_socket, args, 'pkts_icmp')
            )
            threads.append(icmp_thread)

            tcp_thread = threading.Thread(
                target=sniff,
                args=(tcp_socket, args, 'pkts_tcp')
            )
            threads.append(tcp_thread)

            udp_thread = threading.Thread(
                target=sniff,
                args=(udp_socket, args, 'pkts_udp')
            )
            threads.append(udp_thread)


            for thread in threads:
                thread.daemon = True
                thread.start()
            
            try:
                while True:
                    pass

            except KeyboardInterrupt:
                print('[+] Keyboard Interrupt Recieved. Exiting...')
                icmp_socket.close()
                tcp_socket.close()
                tcp_socket.close()

                return


if __name__ == '__main__':
    main()