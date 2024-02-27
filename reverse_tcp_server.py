import socket
import os
import sys



def relay_commands(client):
    
    try:
        while True:
            command = input('> ')
            client.send(command.encode())
            
            recv_len = 1
            response = ''
            
            #get response
            while True:
                data = client.recv(4096)
                recv_len = len(data)
                response += data.decode()

                if recv_len < 4096 and response:
                    break
            
            if response:
                print(response)

    except KeyboardInterrupt:
        print('[!] Keyboard interrupt recieved. Closing connection...')
        client.close()
        sys.exit(0)



def listen(sock, host:str, port:int):

    try:
        sock.bind((host, port))
        sock.listen(5)

    except Exception as e:
        print(f'[!] Exception encountered: {e}')
        sock.close()
        sys.exit(1)

    print(f'[+] Bind successful. Listening for incoming connections.')
    
    #block main thread until connection is recieved
    client_socket, address = sock.accept()
    print(f'[+] Incoming connection from: {address[0]}:{address[1]}')
    relay_commands(client_socket)



if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: [host] [port]")
        sys.exit(0)

    host:str = sys.argv[1]
    port:int = int(sys.argv[2])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    print(f'[+] Binding to: {host}:{port}...')
    listen(sock, host, port)

