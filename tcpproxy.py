from ast import dump
import sys
import socket
import threading


#Filter out non ascii characters. Exclude newline char and carriage return.
PRINTABLE_ASCII = [chr(i) for i in range(32, 127) if chr(i) not in ['\n', '\r']] 
 


def dump_hex(src, length=16, display=True):
    
    if isinstance(src, bytes):
        src = src.decode()
        
    res = list()
    for i in range(0, len(src), length):

        
        txt = str(src[i:i+length]) #slice chunk from i-length (16), exclusive of 16
        printable = ''.join(map(lambda char: char if char in PRINTABLE_ASCII else '.', txt))


        hexa = ' '.join([f'{ord(c):02X}' for c in txt])
        width = length * 3
        res.append(f'{i:04x}  {hexa:<{width}}  {printable}')

   
    if display:
        for i in res:
            print(i)

    return res



def recieve_from(connection_sock)->bytes:
    connection_sock.settimeout(6)
    buff = b''
    
    try:
        while True:
            data = connection_sock.recv(4096)
            if not data:
                break
            buff += data

    except Exception as e:
        pass
    
    return buff



def handle_request(buffer):
    #We can perform packet inspection/modification here, before sending a request
    return buffer



def handle_response(buffer):
    #perform packet modification before responding if needed
    return buffer



def proxy_handler(client_sock, remote_host, remote_port, recieve_first):
    
    remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_sock.connect((remote_host,remote_port))
    
    if recieve_first:
        remote_buffer = recieve_from(remote_sock)
        dump_hex(remote_buffer)
        
    remote_buffer = handle_response(remote_buffer)
    if len(remote_buffer):
        print(f'[+] Sending {len(remote_buffer)} bytes to client...')
        client_sock.send(remote_buffer)
        

    while True:
        
        # Recieve data from the client and proxy it to destination
        local_buffer = recieve_from(client_sock)
        if len(local_buffer):
            print(f'[+] Recieved {len(local_buffer)} bytes from client:')
            dump_hex(local_buffer)
            
            local_buffer = handle_request(local_buffer)
            remote_sock.send(local_buffer)
            print('[+] Sent recieved buffer to remote.')
            

        #Get response from destination and send it to client
        remote_buffer = recieve_from(remote_sock)
        if len(remote_buffer):
            print(f'[+] Recieved {len(remote_buffer)} from remote.')
            dump_hex(remote_buffer)
            
            remote_buffer = handle_response(remote_buffer)
            client_sock.send(remote_buffer)
            print('[+] Proxied buffer back to client.')

        
        # When both client and server are finished, close both connections.
        if not len(local_buffer) or not len(remote_buffer):
            print('[!] Traffic ceased. Closing connections...')
            client_sock.close()
            remote_sock.close()
            break
            


def server_begin(local, local_port, remote_host, remote_port, recieve_first=False):
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    
    try:
        server.bind((local, local_port))
        
    except Exception as e:
        print(f'[!] Exception when binding to {local}:{local_port}.')
        print(f'Exception: {e}')
        sys.exit(0)

    print(f'[+] Bind to {local}:{local_port} successful. Listening...')
    server.listen(5)
    

    while True:
        client_sock, address = server.accept()
        print(f'[+] Connection recieved from {address[0]}:{address[1]}')    
        
        #Start new thread to handle client connection
        proxy_thread = threading.Thread(
            target=proxy_handler,
            args=(client_sock, remote_host, remote_port, recieve_first))
        
        proxy_thread.start()        




def main():
    if len(sys.argv) != 6:
        print("-- TCP PROXY --")
        print("Usage: tcpproxy.py [local host] [local port]", end='')
        print("[remote host] [remote port] [recieve first]")
        print("Example usage: tcpproxy.py 127.0.0.1 5555 10.16.145.1 5555 False")
        sys.exit(0)    

    local_host = sys.argv[1]
    local_port = int(sys.argv[2])
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])
    recieve_first = False
    
    if "True" in sys.argv[5]:
        recieve_first = True

    server_begin(local_host, local_port, remote_host, remote_port, recieve_first)

if __name__ == '__main__':
    main()