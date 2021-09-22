"""
Needham-Schroeder
@url https://en.wikipedia.org/wiki/Needham–Schroeder_protocol

KDC
@url https://github.com/eminmuhammadi/Needham-Schroeder-KDC
"""
import socket
import sys
import traceback
from threading import Thread
import library as lib

"""
Server in memory db
"""
# dictionary that keeps track of the keys for each user
__USER_KEYS__ = dict()
# dictionary that keeps track of the ids and __CONNECTIONS__ of each user
__CONNECTIONS__ = dict()
# used for giving users unique ids
__NUMBER_OF_USERS__ = 0
# Server hostname
IP = "127.0.0.1"
# Server port
PORT = 5000  

"""
Protocol settings for DH
"""
PublicP = 23
PublicG = 5

"""
KDC Server
"""
def main(ip, port):
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   
    # SO_REUSEADDR flag tells the kernel to reuse a local socket in TIME_WAIT state, 
    # without waiting for its natural timeout to expire
    print("Socket created")

    try:
        soc.bind((ip, port))
    except:
        print("Bind failed. Error : " + str(sys.exc_info()))
        sys.exit()

    soc.listen(5) # queue up to 5 requests
    print("Socket now listening...")

    """
    Fix: infinite loop-do not reset for every requests
    """
    while True:
        connection, address = soc.accept()
        ip, port = str(address[0]), str(address[1])
        
        if connection.getpeername() not in __CONNECTIONS__.keys():
            #delegates a unique id for each joining user
            global __NUMBER_OF_USERS__ 
            __NUMBER_OF_USERS__ += 1
            __CONNECTIONS__[connection.getpeername()] = str(__NUMBER_OF_USERS__).zfill(8)

        # Start threading
        try:
            Thread(target=client_thread, args=(connection, ip, port)).start()
        except:
            print("Thread did not start.")
            traceback.print_exc()

        #printing which user connected
        user = __CONNECTIONS__[connection.getpeername()]
        print("\nUser {} connected with {} on port {}".format(str(user), ip, port))

"""
Client Thread
"""
def client_thread(connection, ip, port, max_buffer_size = 5120):
    is_active = True
    #as soon as a user connects we initiated DH
    diffieHelman(connection)

    """
    Start Commands
    """
    while is_active:
        client_input = receive_input(connection, max_buffer_size)
        user = __CONNECTIONS__[connection.getpeername()]
        print("\nUser {} sent:".format(str(user)), client_input)
        
        # Quit command for exit
        if "quit" in client_input:
            __CONNECTIONS__[connection.getpeername()] = None
            connection.close()
            print("\nUser {} disconnected".format(str(user)))
            # Thread lock
            is_active = False

        # List command for listing users
        elif 'list' in client_input:
            # user wants to see what other users they can connect to
            output = ""

            # if there no users in the list, inform the user
            if len(__CONNECTIONS__) == 1:
                output = "You are the only user"
                connection.send(output.encode())

            # other users
            else:
                # iterate through the connections
                for user in __CONNECTIONS__:
                    if __CONNECTIONS__[connection.getpeername()] == None:
                        pass
                    if user != connection.getpeername():
                        output += str(__CONNECTIONS__[user]) + ": "
                        output += str(user) + "\n"
                    else:
                        output += str(__CONNECTIONS__[user]) + ": "
                        output += "YOU \n"
                connection.send(output.encode())

        # Connect command for connecting to another user
        elif 'connect' in client_input:
            #we need to get the part after "connect|...."
            package = client_input.split("|")[1]

            #find the message you want to send to A
            messageToAlice = needhamSchroeder(package,connection)

            #send to A and now the KDC's job is done
            connection.send(messageToAlice.encode())

        # Data receiving
        else:
            print("User {} sent: {}".format(str(user), client_input))
            connection.sendall("-".encode("utf8"))

"""
Needham-Schroeder protocol implementation for KDC
"""
def needhamSchroeder(package, packageConnection):
    #receinving the contents from step 1
    #package is IDA||IDB||N1
    IDa = package[:8]
    IDaAsInt = int(IDa)
    IDaAsBinary = bin(IDaAsInt)[2:].zfill(8)
    
    IDb = package[8:16]
    IDbAsInt = int(IDa)
    IDbAsBinary = bin(IDaAsInt)[2:].zfill(8)
    nonce = package[16:]

    AsKey = __USER_KEYS__[IDa]
    BsKey = __USER_KEYS__[IDb]

    Ks = lib.generate.nonceGenerator()
    T = lib.generate.nonceGenerator()
    #creating the smaller envelope
    messageToBeEncrypted = Ks + IDaAsBinary + T
    encryptedMessage = lib.general.encrypt(messageToBeEncrypted,BsKey)

    #creating the bigger envelop
    nextMessage = Ks + IDbAsBinary + T + encryptedMessage
    finalEncryptedMessage = lib.general.encrypt(nextMessage,AsKey)

    return finalEncryptedMessage

"""
Diffie-Hellman
For initiating DH with each connected user
"""
def diffieHelman(client):
    print("Initiating Diffie Hellman Connection with client..")

    # print(__CONNECTIONS__)
    user = __CONNECTIONS__[client.getpeername()]

    # client.send(user.encode())
    #send the public P and public G to the client
    message = "{}|{}|{}".format(user,PublicP,PublicG)
    client.send(message.encode())
    
    #generate 10 bit key for KDC
    #call this a
    a = lib.generate.random10bit()

    # calcualtes the first step
    # A = g^a mod p
    # send that to the client
    A = (PublicG**a)%PublicP
    client.send(str(A).encode())

    # receives the client calculation
    B = int(client.recv(1024).decode('utf8'))
    # do final calculation to get shared key
    # S = B^a mod p
    S = (B**a)%PublicP
    __USER_KEYS__[user] = bin(S)[2:].zfill(10)
    print("Established key = {}".format(__USER_KEYS__[user]))

# wrapper for making sure incoming input is good
def receive_input(connection, max_buffer_size):
    client_input = connection.recv(max_buffer_size)
    client_input_size = sys.getsizeof(client_input)

    if client_input_size > max_buffer_size:
        print("The input size is greater than expected {}".format(client_input_size))

    # decode and strip end of line
    decoded_input = client_input.decode("utf8").rstrip()  
    return decoded_input

if __name__ == "__main__":
    main(IP, PORT)