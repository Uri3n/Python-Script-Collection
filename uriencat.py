import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading


FILE_END_SEQUENCE = "\n\t\n\t\t\t"


def RunCommand(cmd):
    cmd = cmd.strip()
    if not cmd:
        return
    
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
    return output.decode()



class UrienCat:

    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    

    #Used only when we are listening
    def handle_request(self, client_socket):
        
        if self.args.execute:
            print(f'executing command: {self.args.execute}')
            output = RunCommand(self.args.execute)
            client_socket.send(output.encode())
        

        elif self.args.upload:
            file_buffer = b''
            
            while True:
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                if not data or '\n' in data.decode():
                    break
                    
            
            with open(self.args.upload, 'wb') as file:
                file.write(file_buffer)
            
            res_msg = f'Saved bytes to file: {self.args.upload}'
            client_socket.send(res_msg.encode())

           
        elif self.args.command: 
            print('Setting up shell...')
            cmd = b''
            
            while True:
                try:
                    client_socket.send(b'ENTER COMMAND: ')
                    while FILE_END_SEQUENCE not in cmd.decode():
                        cmd += client_socket.recv(64)

                    response = RunCommand(cmd.decode())
                    if response:
                        client_socket.send(response.encode())
                    cmd = b''


                except Exception as e:
                    print(f'Server connection terminated: {e}')
                    self.socket.close()
                    sys.exit()


    def listen(self):
        
        print(f'Listening on: {self.args.target}:{self.args.port}')
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(6)
        
        while True:
            client_socket, _ = self.socket.accept()
            handler_thread = threading.Thread(target=self.handle_request, args=(client_socket,))
            handler_thread.start()



    def send(self):
        
        # establish connection
        self.socket.connect((self.args.target, self.args.port))    

        #send buffer
        if self.buffer:
            self.socket.send(self.buffer)
            res = self.socket.recv(1000)
            
            if res:
                print(res.decode())
            return


        try:
            while True:
                recv_len = 1
                response = ''
            
                while recv_len: 
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                
                    #if data < 4096, stop decoding data from the same request 
                    if recv_len < 4096: 
                        break
                   
                
                if response:
                    print(response)
                    buf = input('> ')
                    buf += '\n'
                    self.socket.send(buf.encode())

        except KeyboardInterrupt:
            print('[+] Keyboard interrupt recieved. Exiting...')
            self.socket.close()
            sys.exit()



    def run(self):
        if self.args.listen:
            self.listen()
        
        else:
            self.send()
            



def main():
    
    #create parser object
    parser = argparse.ArgumentParser(
        description='Urien\'s Scuffed Net Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
        uriencat.py -t 192.168.1.22 -p 8083 -l -c                                 //Initialize a command shell                       
        uriencat.py -t 192.168.1.22 -p 8083 -l -u=myfile.txt                      //Upload to a file
        uriencat.py -t 192.168.1.22 -p 8083 -l -e=\"cat /somedirectory/somefile\" //Execute a singular command
        echo 'Hello World' | ./uriencat.py -t 192.148.1.22 -p 8083                //Echo some text to port 8083
        uriencat.py -t 192.168.1.22 -p 8083                                       //Connect to a remote machine
        
        '''))
    
    # Add command line arguments
    parser.add_argument('-c', '--command', action='store_true', help='get shell')
    parser.add_argument('-e', '--execute', help='run shell command')
    parser.add_argument('-l', '--listen', action='store_true', help='set up listener')
    parser.add_argument('-p', '--port', type=int, default=8083, help='listen on this port')
    parser.add_argument('-t', '--target', default='192.168.1.22', help='specified IP')
    parser.add_argument('-u', '--upload', help='file upload')

    args = parser.parse_args()
    buffer = ''
    
    # if we aren't listening for a command from the remote host, 
    # execute the command directly
    
    if not args.listen and args.upload:
        with open(args.upload, 'r') as file:
            buffer = file.read()
            buffer += FILE_END_SEQUENCE
    
    uc = UrienCat(args, buffer.encode())
    uc.run()

if __name__ == '__main__':
    main()
