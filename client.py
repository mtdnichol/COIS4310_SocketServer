import random
import socket
import string
import threading
import json

from packet import Packet, PacketType

"""
    Chat Room Client
    
    Completed: Feb.10.2020
    Written By: Michael Nichol & Bobby Horth
    
    Purpose:
    The purpose of this application is to connect to a localhost server, and allow the user
    chat with other connected clients through a series of commands.  For simplicity, the client
    must be on the same computer of the server, but this can be changed to the same LAN by
    changing the 'SERVER' variable to the IP of the server host computer on the same network.
    
    Parameters:
        - None
"""
PORT = 54004  # Port is decided from last 4 digits of SID + 50000
DISCONNECT_MESSAGE = "bye"  # Disconnect message determines when a user leaves the chat room
SERVER = socket.gethostbyname(socket.gethostname())  # IP address of the server the client is attempting to connect to
ADDR = (SERVER, PORT)  # Address, port tuple


# =======================================================
# Routine Name: sendPacket
# Author: Michael Nichol & Bobby Horth
# Date: 24.2.2020
# Purpose: Encodes and sends a generated packet from the client to the server
# Parameters:
#   - data: packet contents
#   - destination: packet destination
#   - type: packet type
# =======================================================
def sendPacket(data: str, destination: str, pType: PacketType):
    global CURRENT_PACKET, USERNAME, PACKETS_SENT
    # Create packet from provided arguments, enciphers the packet
    packet = Packet.createPacket(rot47(data), USERNAME, destination, pType, encryptionType="ROT47")
    # Store last packet sent in case it needs to be resent
    CURRENT_PACKET = packet
    # Increment packet count
    PACKETS_SENT += 1
    # corrupt every 6th packet
    if PACKETS_SENT % 6 == 0:
        packet = packet.copy()
        # Just fill data with random character garbage
        packet['data'] = ''.join(random.choices(string.ascii_letters, k=10))

    # Send packet to the client
    to_send = json.dumps(packet)
    client.send(to_send.encode())


# =======================================================
# Routine Name: sendPacket
# Author: Michael Nichol & Bobby Horth
# Date: 24.2.2020
# Purpose: Resends the last sent packet to the client
# =======================================================
def resendPacket():
    global CURRENT_PACKET, RESEND_PACKET
    # Mark that we've resent the packet
    RESEND_PACKET = False
    # Resend the last packet
    to_send = json.dumps(CURRENT_PACKET)
    client.send(to_send.encode())


# =======================================================
# Routine Name: awaitSend
# Author: Michael Nichol & Bobby Horth
# Date: 24.2.2020
# Purpose: Continuous loop that waits for messages the client sends to the server
# Parameters:
#   - canSend a lock object representing whether the write thread can send a message
# =======================================================
def awaitSend(canSend):
    global CONNECTED, RESEND_PACKET, CURRENT_PACKET, USERNAME
    # Initially acquire the canSend lock since we know we're allowed to send
    canSend.acquire()

    # User enters their preferred username
    USERNAME = input("Enter username: ")
    # Send username to server
    sendPacket(USERNAME, "", PacketType.username)

    # Wait until the lock is released so we know we can send another packet
    canSend.acquire()

    while CONNECTED:
        # If RESEND_PACKET boolean is true the read thread is telling us the last packet got corrupted and we must
        # resend
        if RESEND_PACKET:
            # Resend the packet and wait until we can send another packet via thread lock
            resendPacket()
            canSend.acquire()
            continue

        # User enters their message
        msg = input(USERNAME + ": ")

        # If message is the disconnect keyword, last message is sent and loop is terminated
        if msg == DISCONNECT_MESSAGE:
            CONNECTED = False
            sendPacket("", "", PacketType.disconnect)
            print("\n\nYou have disconnected from the chat.\n\n")  # Debug
            break
        elif msg == "who":
            sendPacket("", "", PacketType.clientList)
        elif msg.count(":"):
            identifier = msg[:msg.index(":")]  # Splits the string at the first colon to acquire message identifier

            if identifier == "all":
                sendPacket(msg[msg.index(":") + 1:], "", PacketType.broadcast)
            else:
                sendPacket(msg[msg.index(":") + 1:], msg[:msg.index(":")], PacketType.privateMessage)
        else:
            print("Invalid command.")
            continue

        # We just sent a packet so wait until the read thread tells us we can send another
        canSend.acquire()


# =======================================================
# Routine Name: awaitRecieve
# Author: Michael Nichol & Bobby Horth
# Date: 24.2.2020
# Purpose: Continuous loop that waits for messages the server sends to the client
# Parameters:
#   - canSend a lock object representing whether the write thread can send a message
# =======================================================
def awaitReceive(canSend):
    global CONNECTED, RESEND_PACKET, CURRENT_PACKET
    while CONNECTED:
        jsonString = client.recv(1024).decode()
        if jsonString is None or jsonString == "":
            break

        while jsonString.find("}") != -1:
            bracketPos = jsonString.find("}")
            data = jsonString[:bracketPos + 1]
            jsonString = jsonString[bracketPos + 1:]

            packet = json.loads(data)  # Gets the packet from the server message
            packet_length = len(packet)

            if packet['encryptionType'] == "ROT47":
                packet['data'] = rot47(packet['data'])  # Decrypts the message using ROT47

            if packet_length:  # Checks if the message has substance
                verb = packet['verb']  # Obtains the verb from the packet to determine action

                # Below statement determines proper action, and formats output client-side
                if verb == "broadcast":
                    print(f"(Broadcast) {packet['sender']}: {packet['data']}")
                elif verb == "private message":
                    print(f"{packet['sender']}" + "-->You: " + packet['data'])
                elif verb == "client list":
                    data_length = len(packet['data'])
                    if data_length:
                        print("List of Online Clients")
                        print(f">> {packet['data']}")
                    else:
                        print("This chat room is empty")
                elif verb == "disconnect":
                    print(f"{packet['sender']} has disconnected from the chat...")
                elif verb == "user not found":
                    print("Destination or command not found...")
                elif verb == "valid packet":
                    # Since we've received an acknowledgement from the server, let the write thread send another packet by
                    # releasing the lock
                    canSend.release()
                elif verb == "corrupted packet":
                    # Since we've received an non-acknowledgement from the server, tell the write thread to resend the last
                    # packet and release the lock
                    RESEND_PACKET = True
                    canSend.release()
                else:  # Default case simply prints the data
                    print(packet["data"])


def rot47(message):
    newString = []
    for index in range(len(message)):  # Iterates over the string
        charNum = ord(message[index])  # Finds the unicode value

        if 32 < charNum < 127:  # If character is a ASCII value, rotate
            newString.append(chr(33 + ((charNum+14) % 94)))
        else:  # Otherwise, append as is
            newString.append(message[index])

    return "".join(newString)


client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Creates the socket connection with the server
client.connect(ADDR)
CONNECTED = True  # Represents whether or not the client is connected
RESEND_PACKET = False  # Represents whether or not the write thread should resend the last packet
CURRENT_PACKET = None  # Stores the last send packet
USERNAME = ""  # Stores the client's username
PACKETS_SENT = 0  # Counts the total number of sent packets

print("Welcome to the Chat Room\n"
      "All messages must be have prefix arg:message\n"
      "Arguments are:\n"
      " - 'all' send a message to the whole group\n"
      " - 'username' send a message to an individual\n"
      " - 'who' get a list of all connected client names\n"
      )
print(f"Enter {DISCONNECT_MESSAGE} to disconnect from the group chat\n")

# Create a shared lock that determines whether or not the write thread can send a packet
canSend = threading.Lock()

# Begin separate read and write threads for the client, so the tasks are done simultaneously
sendThread = threading.Thread(target=awaitSend, args=(canSend,))
recvThread = threading.Thread(target=awaitReceive, args=(canSend,))

sendThread.start()  # Threads for the local client are started
recvThread.start()
