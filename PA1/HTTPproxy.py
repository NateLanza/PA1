# Place your imports here
from operator import countOf
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
        print("Listening!", flush = True)
        i = 1
        
        while True:
            # accept a connection from a client
            # will need a refactor when I add multiple clients
            client_sock, client_addr = listen_sock.accept()

            # receive the GET request
            request = b''
            print("Client: ", i, flush = True)
            i += 1
            while not request.endswith(b"\r\n\r\n"):
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                request += chunk
            request = request.decode()
            print(request, flush = True)
            
            # parse the request to extract the URL
            url, method, version, headers = self.parse_request(request)
            print("URL: ", url, "Method: ", method, "Version:", version, "Headers: ", headers, flush = True)
            if method != "GET" or version != "HTTP/1.0":
                print("Method/version not supported", flush = True)
                client_sock.sendall(b"HTTP/1.0 501 Not Implemented\r\n\r\n")
                client_sock.close()
                continue
            elif not url or not "http://" in url:
                print("Bad url", flush = True)
                client_sock.sendall(b"HTTP/1.0 400 Bad Request\r\n\r\n")
                client_sock.close()
                continue
            print("URL: " + url + " Method: " + method + " Headers: " + headers, flush = True)
            
            # resolve the hostname to an IP address
            
            url = url.replace("http://", "", 1)
            if "/" in url:
                hostname, path = url.split("/", 1)
            else:
                hostname = url
                path = ""
            port = 80
            if ":" in hostname:
                hostname, port = hostname.split(":")
            print("Hostname: " + hostname + " Port: " + str(port) + " Path: " + path, flush=True)
            try:
                ip = socket.gethostbyname(hostname)
            except Exception:
                client_sock.sendall(b"HTTP/1.0 400 Bad Request\r\n\r\n")
                client_sock.close()
                continue
            
            print("IP: " + ip, flush = True)
            # create a socket and connect to the server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.connect((ip, int(port)))
            
            # send the GET request to the server
            request = f"GET /{path} HTTP/1.0\r\nHost: {hostname}\r\n"
            if headers.__contains__("Connection:"):
                headers = headers.replace("keep-alive", "close")
            else:
                headers = "Connection: close\r\n" + headers
            request += headers
            request += "\r\n"
            print("Sending request:\n", request, flush = True)
            sock.send(request.encode())
            
            # receive the response and pass it back to the client
            # first, retrieve the response and pass back to client
            try:
                response = sock.recv(4096)
            except Exception:
                client_sock.sendall(b"HTTP/1.0 400 Bad Request\r\n\r\n")
                client_sock.close()
                continue
            
            # Now, make sure we have a Connection: close header
            if not b"Connection: close" in response:
                if b"keep-alive" in response:
                    response.replace(b"keep-alive", b"close")
                elif response.count(b"\r\n") < 3:
                    response = b"Connection: close\r\n" + response
                else:
                    pieces = response.split(b"\r\n", 1)
                    response = pieces[0] + b"\r\nConnection: close\r\n" + pieces[1]
            # Print response for debugging
            try:
                print("Received response, sending to client: \n" + response.decode(), flush = True)
            except Exception:
                pass # In case response can't be decoded; we don't need to print it
            
            client_sock.sendall(response)
            sock.close()
            client_sock.close()
            
    def parse_request(self, request):
        """
        Parses the HTTP request 
        and returns the URL, method, version, and headers as a tuple
        """
        lines = request.split("\r\n")
        get_line = lines[0]
        parts = get_line.split(" ")
        if len(parts) != 3:
            return None, None, None, None
        method, url, version = parts
        headers = None
        headers = "\r\n".join(lines[1:])
        return url.strip(), method.strip(), version.strip(), headers.strip()


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

print("About to start proxy", flush = True)
# Start the proxy on the specified address and port!
proxy = Proxy(address, port)
proxy.start()