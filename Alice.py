import socket
import sys
import library as lib

"""
Alice's configurations
"""
# for the purpose of this assignment, both clients know these
__BOB_IP__   = "127.0.0.1"
__BOB_PORT__ = 5010

__KDC_IP__   = "127.0.0.1"
__KDC_PORT__ = 5000

"""
Alices's in memory db
"""
__KDC_KEY__ = None
__MY_ID__   = None

# method for printing the options for the client
def printMenuOptions():
    print("Options:")
    print("\t Enter 'quit' to exit")
    print("\t Enter 'list' to list established secure users")
    print("\t Enter 'connect|id to connect to id")

"""
Connection with KDC
"""
def main(ip, port):
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Error handling
    try:
        soc.connect((ip, port))
    except:
        print("Connection error with KDC")
        sys.exit()

    # create the key and use it in function call
    Key = lib.generate.random10bit()
    diffieHelman(soc, Key)

    """
    Start Commands
    """
    while True:
        # print the user options
        printMenuOptions()

        # input
        message = input(" -> ")

        # exit
        if message == "quit":
            break

        # connect to a user init fixed on server-side
        if 'connect' in message:
            print("trying to connect")
            otherUser = message.split("|")[1]
            #this is for the server-side backend
            message = 'connect|' + __MY_ID__ + otherUser + lib.generate.nonceGenerator()
            
        soc.send(message.encode("utf8"))

        # connect a user
        if 'connect' in message:
            #go up to the NS method and start the interaction
            needhamSchroeder(soc)

        # showing the user available other users to connect to
        if message == "list":
            soc.send(message.encode("utf8"))
            userList = soc.recv(1024).decode('utf8')
            print(userList)
        
        if soc.recv(5120).decode("utf8") == "-":
            pass   # null operation
        
    soc.send(b'--quit--')

"""
Needham-Schroeder protocol implementation for Alice
"""
def needhamSchroeder(soc):
    # receiving the package from step 2
    message = soc.recv(1024).decode('utf8')

    # decrypting the message
    decrypedMessage = lib.general.decrypt(message,__KDC_KEY__)
    Ks = decrypedMessage[0:10]
    # IDb = decrypedMessage[10:18]
    # T = decrypedMessage[18:28

    smallEncryption = decrypedMessage[28:]

    """
    Connection with Alice and Bob(server)
    """
    # now we connect to the harcoded channel client 2 is waiting for us to connect to
    BobSocket = socket.socket()
    BobSocket.connect((__BOB_IP__, __BOB_PORT__))

    # sending over step 3 to Bob
    BobSocket.send(smallEncryption.encode())

    # receiving step 4 from Bob
    newNonce = BobSocket.recv(1024).decode()

    # decrypting step 4
    decryptedNonce = lib.general.decrypt(newNonce, Ks)

    # turning it into and int
    changedNonce = int(decryptedNonce, 2)

    # subtracting 1: this si the F function that is predetermined by Alice and Bob
    changedNonce = changedNonce - 1

    # turning it back into a binary string
    changedNonce = bin(changedNonce)[2:].zfill(10)

    # encrypting f(nonce)
    encryptedNonce = lib.general.encrypt(changedNonce, Ks)

    # sending step 5 to Bob
    BobSocket.send(encryptedNonce.encode())
    
    # if Bob received the anticipated differentiation in nonce value
    # using the same encryption/decryption key..... 
    # We now have a secure chat!
    if BobSocket.recv(1024).decode() == "VERIFIED":
        while message != 'q':

            message = input("Enter the message to send Bob (will be encrypted after) -> ")
            # encrypting the message using DES
            finalEncryptedMessage = lib.general.encrypt(message, Ks)

            # encrypting the message
            # sending the message
            BobSocket.send(finalEncryptedMessage.encode())

            #receiving the response from the other user
            data = BobSocket.recv(1024).decode()

            # decrypting the other user's message
            decryptedMessage = lib.general.decrypt(data,Ks)

            if not data:
                break

            print ("Bob said: {}".format(str(decryptedMessage)))

"""
Diffie-Hellman implementation for Alice
method that runs that diffie helman exchange for the client
"""
def diffieHelman(kdc, PrivateKey):    
    # note b is the private key
    # receive public G and P from server
    message = kdc.recv(1024).decode('utf8')
    message = message.split("|")

    publicP, publicG = int(message[1]),int(message[2])
    
    global __MY_ID__
    __MY_ID__ = message[0]

    # receives the first calculation
    # call this X
    A = int(kdc.recv(1024).decode('utf8'))

    # generate 10 bit key for KDC
    # call this a
    # now it's time for the client to do their step
    # B = g^b mod p
    b = lib.generate.random10bit()
    B = (publicG**b)%publicP

    # now we send this to the server
    kdc.send(str(B).encode())

    # now we do the final calculation
    # S = A^b mod p
    S = (A**b)%publicP

    global __KDC_KEY__
    __KDC_KEY__ = bin(S)[2:].zfill(10)

    print("Established key = ", str(S))

if __name__ == "__main__":
    main(__KDC_IP__, __KDC_PORT__)