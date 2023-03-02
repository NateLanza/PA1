# Place your imports here
import signal
import socket
import sys
import threading
from optparse import OptionParser
from typing import Tuple

# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
    sys.exit(0)

class CommandProcessor:
    """
    This class is responsible for handling commands to the proxy, including caching and blocking
    """

    def __init__(this):
        # The cache, a dictionary
        this.cache = dict()
        this.cacheEnabled = False
        # The blocklist, a set
        this.blocklist = {}
        this.blocklistEnabled = False
        
    def isBlocked(this, hostname: str, port: str = '') -> bool:
        """
        Check if the given hostname and port combination is present in the blocklist.
        Args:
            hostname (str): The hostname to check.
            port (str): The port to check. Default is an empty string.
        Returns:
            bool: True if the hostname and port combination is present in the blocklist, False otherwise.
        """
        if not this.blocklistEnabled:
            return False
        for block in this.blocklist:
            if ":" in block:
                if f"{hostname}:{port}" in block:
                    return True
            else:
                if hostname in block:
                    return True
            
        return False
    
    def inCache(this, hostname: str, port: str, path: str):
        """
        Check if the given hostname, port, and path combination is present in the cache dictionary.
        Args:
        - hostname (str): The hostname to check.
        - port (str): The port to check.
        - path (str): The path to check.
        Returns:
            Union[object, bool]: The cached object corresponding to the hostname, port, and path combination, 
            or False if it is not present in the cache.
        """
        if not this.cacheEnabled:
            return False
        
        key = (hostname, port, path)
        if key in this.cache:
            return this.cache[key]
        
        return False
    
    def cache(this, hostname: str, port: str, path: str, resource: bytes) -> None:
        """
        Store the given hostname, port, path, and resource in the cache dictionary.
        Args:
        - hostname (str): The hostname to store in the cache.
        - port (str): The port to store in the cache.
        - path (str): The path to store in the cache.
        - resource (bytes): The bytes-like object to store in the cache.
        """
        key = (hostname, port, path)
        this.cache[key] = resource
    
    def block(this, string: str) -> None:
        """
        Add the given string to the blocklist.
        Args:
        - string (str): The string to add to the blocklist.
        """
        this.blocklist.add(string)
    
    def isCmd(self, path: str) -> bool:
        """
        Check whether the given path starts with "/proxy".
        Args:
        - path (str): The path to check.
        Returns:
            bool: True if the path starts with "/proxy", False otherwise.
        """
        return path.startswith("proxy") or path.startswith("/proxy")
        
    def processCmd(this, path: str) -> bytes:
        """
        Processes a command from the user
        Args:
        - path: The path for the command
        Returns:
            The byte string response that should be sent to the client.
            This may be a 200 OK response or an error message-
            it is OK to feed poorly formatted client paths to this,
            as long as they pass isCmd()
        Throws:
            Exception: if the path argument is not a command
        """
        if not this.isCmd(path):
            raise Exception("Not a command")
        
        # Split the path into a list of args
        args = path.split("/")
        # Check if the args are valid
        if not this.checkArgs(args):
            return b"HTTP/1.0 400 Bad Request\r\n\r\n"
        
        # Handle the command
        if (args[1] == "cache"):
            if (args[2] == "enable"):
                this.cacheEnabled = True
                return b"HTTP/1.0 200 OK\r\n\r\n"
            elif (args[2] == "disable"):
                this.cacheEnabled = False
                return b"HTTP/1.0 200 OK\r\n\r\n"
            elif (args[2] == "flush"):
                this.cache = {}
                return b"HTTP/1.0 200 OK\r\n\r\n"
        elif (args[1] == "blocklist"):
            if (len(args) == 3):
                if (args[2] == "enable"):
                    this.blocklistEnabled = True
                    return b"HTTP/1.0 200 OK\r\n\r\n"
                elif (args[2] == "disable"):
                    this.blocklistEnabled = False
                    return b"HTTP/1.0 200 OK\r\n\r\n"
                elif (args[2] == "flush"):
                    this.blocklist = {}
                    return b"HTTP/1.0 200 OK\r\n\r\n"
            elif (len(args) == 4):
                if (args[2] == "add"):
                    this.blocklist.add(args[3])
                    return b"HTTP/1.0 200 OK\r\n\r\n"
                elif (args[2] == "remove"):
                    this.blocklist.remove(args[3])
                    return b"HTTP/1.0 200 OK\r\n\r\n"
        
        
    def checkArgs(this, args: list) -> bool:
        """
        Check if the given list of arguments is valid.
        Args:
        - args (list): The list of arguments to check.
        Returns:
            bool: True if the list of arguments is valid, False otherwise.
        """
        if (args[1] == "cache"):
            return len(args) == 3 and \
            (args[2] == "enable" or args[2] == "disable" or args[2] == "flush")
        elif (args[1] == "blocklist"):
            if (len(args) == 3):
                return args[2] == "enable" or args[2] == "disable" or args[2] == "flush"
            elif (len(args) == 4):
                return args[2] == "add" or args[2] == "remove"
        else:
            return False
        
class Proxy: 
    """
    I decided to put the proxy in a class to hopefully make it easier to modify
    for the other assignments
    This class defines a start() method which starts the proxy on the address
    and port and enters an infinite loop waiting for connections.
    It will accept a single connection, then infinitely forward its HTTP requests.
    """
    def __init__(this, address: str, port: str):
        """Initializes a proxy which will listen on the given address and port"""
        this.port = port
        this.address = address
        this.cmd = CommandProcessor()
    
    def start(this):
        """
        The proxy starts listening on the given address and port
        and enters an infinite loop waiting for connections.
        It will accept a single connection, then infinitely forward its HTTP requests.
        """
        
        # create a socket and bind it to the specified port
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.bind((this.address, this.port))
        listen_sock.listen()
        print("Listening!", flush = True)
        i = 1
        
        while True:
            # accept a connection from a client
            client_sock, client_addr = listen_sock.accept()

            print("Client: ", i, flush = True)
            i += 1
            
            client_thread = threading.Thread(target=this.handle_client, args=(client_sock,))
            client_thread.start()
        
    def handle_client(this, client_sock):
        """
        After a client has been accepted and assigned a socket, handles their GET request
        No return value
        
        Args:
            client_sock: the socket connected to the client
        """
        # receive the GET request
        request = b''
        while not request.endswith(b"\r\n\r\n"):
            chunk = client_sock.recv(4096)
            if not chunk:
                break
            request += chunk
        request = request.decode()
        print(request, flush = True)
        
        # parse the request to extract the URL
        url, method, version, headers = this.parseRequest(request)

        # Check for a formatting error
        formatErr = this.checkGETFormat(url, method, version)
        if formatErr:
            client_sock.sendall(formatErr)
            client_sock.close()
            return
                            
        # Convert the URL to an IP and port
        hostname, path, port, error = this.parseURL(url)
        if error:
            client_sock.sendall(f"HTTP/1.0 400 Bad Request ({error})\r\n\r\n".encode())
            client_sock.close()
            return
        
        # Check for commands and blocking
        if this.cmd.isCmd(path):
            client_sock.sendall(this.cmd.processCmd(path))
            client_sock.close()
            return
        elif this.cmd.isBlocked(hostname, port):
            client_sock.sendall(b"HTTP/1.0 403 Forbidden\r\n\r\n")
            client_sock.close()
            return
        
        # Check the cache
        cached = this.cmd.inCache(hostname, port, path)
        if cached:
            client_sock.sendall(cached)
            client_sock.close()
            return
            
        # Check each line of the headers for formatting
        headErr = this.checkHeaderFormat(headers)
        if headErr:
            client_sock.send(headErr)
            client_sock.close()
            return
        
        # Get IP
        ip = this.parseIP(hostname)
        if not ip:
            client_sock.sendall(f"HTTP/1.0 400 Bad Request (Host not found)\r\n\r\n".encode())
            client_sock.close()
            return
        
        print("IP: " + ip, flush = True)
        # create a socket and connect to the server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.connect((ip, int(port)))
        
        # send the GET request to the server
        request = this.makeRequest(path, hostname, headers)
        sock.send(request.encode())
        
        # receive the response and pass it back to the client
        # first, retrieve the response and pass back to client
        try:
            response = b''
            while not response.endswith(b"\r\n\r\n"):
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except Exception:
            client_sock.sendall(b"HTTP/1.0 400 Bad Request\r\n\r\n")
            client_sock.close()
            return
        
        # Print response for debugging
        try:
            print("Received response, sending to client: \n" + response.decode(), flush = True)
        except Exception:
            print("Sending unprintable response\n") # In case response can't be decoded; we don't need to print it
        
        # Cache response
        this.cmd.cache(hostname, port, path, response)
            
        # Send response to client; close sockets
        client_sock.sendall(response)
        sock.close()
        client_sock.close()
        
    ### Helpers for handle_client ###
    
    def makeRequest(this, path: str, hostname: str, headers: str) -> str:
        """
        Constructs a GET request to pass to a server

        Args:
        - path: str, the path of the resource to request
        - hostname: str, the hostname of the server to request from
        - headers: str, the headers to include in the request

        Returns:
        - request: str, the complete GET request as a string
        """
        request = f"GET /{path} HTTP/1.0\r\nHost: {hostname}\r\n"
        if "Connection:" in headers:
            headers = headers.replace("keep-alive", "close")
        else:
            headers = "Connection: close\r\n" + headers
        request += headers
        request += "\r\n"
        
        # Verify we have a complete http request!!
        if not request.endswith("\r\n\r\n"):
            request += "\r\n"

        return request
    
    def checkGETFormat(this, url: str, method: str, version: str):
        """
        Check if the provided URL, HTTP method, and version are in the expected format for a GET request.

        Args:
        - url: A string representing the URL to check.
        - method: A string representing the HTTP method to check (e.g. "GET", "POST", etc.).
        - version: A string representing the HTTP version to check (e.g. "HTTP/1.0", "HTTP/1.1", etc.).

        Returns:
        - False if the URL, method, and version are all in the expected format for a GET request.
        - A byte string containing the appropriate HTTP response text if any of the following errors occur:
          * The URL, method, or version is missing (Bad request).
          * The HTTP method is not supported (Method not supported).
          * The HTTP version is not supported (Bad version).
          * The URL is missing or does not start with "http://" (Bad url).
        """
        if not url or not method or not version:
            return b"HTTP/1.0 400 Bad Request\r\n\r\nBad request"
        elif method != "GET":
            return b"HTTP/1.0 501 Not Implemented\r\n\r\nMethod not supported"
        elif version != "HTTP/1.0":
            return b"HTTP/1.0 400 Bad Request\r\n\r\nBad version"
        elif not url.startswith("http://"):
            return b"HTTP/1.0 400 Bad Request\r\n\r\nBad url"
        else:
            return False

    def parseURL(this, url: str):
        """
        Convert a URL to a hostname, path, and port
        Args:
        - url: A string representing the URL to convert.
        Returns:
        - A tuple containing the following elements:
          * The hostname parsed from the URL.
          * The path parsed from the URL.
          * The port parsed from the URL.
          * False if no error occurred, or a string containing an error message if one occurred.
        """
        url = url.replace("http://", "", 1)
        if "/" in url:
            hostname, path = url.split("/", 1)
        else:
            return (None, None, None, None, "Missing path")
        port = 80
        if ":" in hostname:
            hostname, port = hostname.split(":")
        
    
        return (hostname, path, int(port), False)
    
    def parseIP(this, hostname: str):
        """
        Parse a hostname into an IP. Returns false on failure        
        """
        try:
            return socket.gethostbyname(hostname)
        except Exception:
            return False
            
    def checkHeaderFormat(this, headers: str):
        """
        Check the format of HTTP headers and return False if there is no error, otherwise return the error message.

        Parameters:
        headers (str): A string containing HTTP headers separated by "\r\n".

        Returns:
        False: If there is no error in the headers format.
        str: If there is an error in the headers format, returns "HTTP/1.0 400 Bad Request\r\n\r\n".

        The function checks the format of each header line in the provided string. It returns False if all header lines
        are formatted correctly, otherwise it returns the error message "HTTP/1.0 400 Bad Request\r\n\r\n". The error message
        indicates that there is a problem with the format of the headers in the HTTP request. The function checks for the
        following issues:
        - If a header line does not contain a colon (:) character.
        - If the header field name is missing or empty.
        - If the header field value is missing or empty.
        - If there is no whitespace character after the colon (:) character in the header line.
        """
        for line in headers.split("\r\n"):
            if line.strip():
                if not ":" in line:
                    return b"HTTP/1.0 400 Bad Request\r\n\r\n"
                elif not line.split(":")[0].strip():
                    return b"HTTP/1.0 400 Bad Request\r\n\r\n"
                elif not line.split(":")[1].strip():
                    return b"HTTP/1.0 400 Bad Request\r\n\r\n"
                elif not line[line.find(":") - 1].strip():
                    return b"HTTP/1.0 400 Bad Request\r\n\r\n"
                elif not line[line.find(":") + 1] == " ":
                    return b"HTTP/1.0 400 Bad Request\r\n\r\n"
        return False
    
    def parseRequest(this, request: str):
        """
        Parses an HTTP request string and returns a tuple of the request URL,
        method, version, and headers.

        Args:
            request (str): The HTTP request string to be parsed.

        Returns:
            tuple: A 4-tuple containing the request URL, method, version, and headers.
            Returns (None, None, None, None) if the request is incorrectly formatted.
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