# Place your imports here
import signal
import socket
import sys
from optparse import OptionParser

# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
    sys.exit(0)

class Proxy: 
    """
    I decided to put the proxy in a class to hopefully make it easier to modify
    for the other assignments
    This class defines a start() method which starts the proxy on the address
    and port and enters an infinite loop waiting for connections.
    It will accept a single connection, then infinitely forward its HTTP requests.
    """
    def __init__(self, address: str, port: str):
        """Initializes a proxy which will listen on the given address and port"""
        self.port = port
        self.address = address

    def start(self):
        """
        The proxy starts listening on the given address and port
        and enters an infinite loop waiting for connections.
        It will accept a single connection, then infinitely forward its HTTP requests.
        """
        
        # create a socket and bind it to the specified port
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.bind((self.address, self.port))
        listen_sock.listen()
        print("Listening!")
        # accept a connection from a client
        # will need a refactor when I add multiple clients
        client_sock, client_addr = listen_sock.accept()
        
        try:
            while True:
                # receive the GET request
                request = b''
                print ("Starting while loop: ")
                while not request.endswith(b"\r\n\r\n"):
                    chunk = client_sock.recv(4096)
                    if not chunk:
                        break
                    request += chunk
                request = request.decode()
                print(request)
                
                # parse the request to extract the URL
                url, method, headers = self.parse_request(request)
                if method != "GET":
                    client_sock.send("HTTP/1.0 501 Not Implemented\r\n\r\n".encode())
                    continue
                elif not url:
                    client_sock.send("HTTP/1.0 400 Bad Request\r\n\r\n".encode())
                    continue
                print("URL: " + url + " Method: " + method + " Headers: " + headers)
                
                # resolve the hostname to an IP address
                url = url.replace("http://", "", 1)
                hostname, path = url.split("/", 1)
                port = 80
                if ":" in hostname:
                    hostname, port = hostname.split(":")
                print("Hostname: " + hostname + " Port: " + str(port) + " Path: " + path)
                try:
                    ip = socket.gethostbyname(hostname)
                except:
                    client_sock.send("HTTP/1.0 400 Bad Request\r\n\r\n".encode())
                    continue
                
                print("Hostname: " + hostname + " IP: " + ip + " Port: " + str(port))
                # create a socket and connect to the server
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((ip, port))
                
                # send the GET request to the server
                request = f"GET /{path} HTTP/1.0\r\nHost: {hostname}\r\n"
                if headers.__contains__("Connection:"):
                    headers = headers.replace("keep-alive", "close")
                else:
                    headers = "Connection: close\r\n" + headers
                request += headers
                request += "\r\n"
                sock.send(request.encode())
                
                # receive the response and pass it back to the client
                response = sock.recv(4096)
                client_sock.send(response)
        except:
            client_sock.close()

    def parse_request(self, request):
        """
        Parses the HTTP request 
        and returns the URL, method, and headers as a tuple
        """
        lines = request.split("\r\n")
        get_line = lines[0]
        parts = get_line.split(" ")
        if len(parts) != 3:
            return None, None, None
        method, url, version = parts
        if version != "HTTP/1.0":
            return None, None, None
        headers = "\r\n".join(lines[1:])
        return url.strip(), method.strip(), headers.strip()


# Start of program execution
# Parse out the command line server address and port number to listen to
parser = OptionParser()
parser.add_option('-p', type='int', dest='serverPort')
parser.add_option('-a', type='string', dest='serverAddress')
(options, args) = parser.parse_args()
port = options.serverPort
address = options.serverAddress
if address is None:
    address = 'localhost'
if port is None:
    port = 2100
    
# Set up signal handling (ctrl-c)
signal.signal(signal.SIGINT, ctrl_c_pressed)

print("About to start proxy")
# Start the proxy on the specified address and port!
proxy = Proxy(address, port)
proxy.start()
print("Proxy started")