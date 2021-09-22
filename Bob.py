import socket
import sys
import library as lib

"""
Alice's configurations
"""
# for the purpose of this assignment, both clients know these
__MY_IP__   = "127.0.0.1"
__MY_PORT__ = 5010

__KDC_IP__   = "127.0.0.1"
__KDC_PORT__ = 5000

"""
Bob's in memory db
"""
__KDC_KEY__ = None
__MY_ID__   = None

# method for printing the options for the client
def printMenuOptions():
    print("Options:")
    print("\t Enter 'quit' to exit")
    print("\t Enter 'wait' wait for a connection")

"""
Connection with KDC
"""
def main(host, port):
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Error handling
    try:
        soc.connect((host, port))
    except:
        print("Connection error")
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

        message = input(" -> ")

        # exit
        if message == "quit":
            break

        soc.send(message.encode("utf8"))

        # showing the user available other users to Bob
        if message == "list":
            soc.send(message.encode("utf8"))
            userList = soc.recv(1024).decode('utf8')
            print(userList)

        # wait for a connection
        if 'wait' in message:
            MySocket = socket.socket()
            MySocket.bind((__MY_IP__, __MY_PORT__))

            print("Waiting for connection.....")
            # listens for a user to connect
            MySocket.listen(1)

            # getting the user's connection info
            conn, addr = MySocket.accept()
            print ("Connection from: {}".format(str(addr)))

            # this means that Alice has initiated NS with the KDC and has now
            # sent us an encrypted envelope with a session key
            package = conn.recv(1024).decode()

            #we decrypte it
            decryptedPackage = lib.general.decrypt(package, __KDC_KEY__)
            Ks = decryptedPackage[:10]
            # IDa = decryptedPackage[10:18]
            # nonce = decryptedPackage[18:]

            # now we send back an an encrypted nonce
            newNonce = lib.generate.nonceGenerator()
            encryptedNonce = lib.general.encrypt(newNonce, Ks)
            conn.send(encryptedNonce.encode())

            # we get an encrypted altered nonce from A
            incomingChangedNonce = conn.recv(1024).decode()
            changedIncomingNonce = lib.general.decrypt(incomingChangedNonce,Ks)

            # if the difference is what we expect (pre-determined), then....
            # we now have a secure encrypted communication!
            if int(changedIncomingNonce,2) == int(newNonce, 2) - 1:
                conn.send("VERIFIED".encode())

                """
                Communication with Alice
                """
                while True:
                    data = conn.recv(1024).decode()

                    # Decrypt the data
                    decryptedMessage = lib.general.decrypt(data, Ks)
                    if not data:
                        break
                    print("Alice said: {}".format(decryptedMessage))

                    message = input("Enter the message to send Alice (will be encrypted after) -> ")

                    # encrypting the message using DES
                    finalEncryptedMessage = lib.general.encrypt(message, Ks)

                    # prints the pretty loading bar
                    # sending the message
                    conn.send(finalEncryptedMessage.encode())

        if soc.recv(5120).decode("utf8") == "-":
            pass   # null operation

    soc.send(b'--quit--')

"""
Diffie-Hellman implementation for Bob
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

    # printing here is only for the sake of this assignment
    # would not get done in real life
    print("Established key = {}".format(str(S)))


if __name__ == "__main__":
    main(__KDC_IP__, __KDC_PORT__)