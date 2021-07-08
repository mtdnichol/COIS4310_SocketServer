"""
PROJECT REQUIREMENTS

RFC
Packet Header
Port #
Use static port #: 4004 + 50000

Server code runs forever, and only terminated by ^C when done testing application
Client code runs until user enters "bye"

Requirements:
 - Server is started and waits for client connections
 - Client connects to server and passes a clientUsername
        - Accepts input as destination:message or bye as exit
 - When client joins, a message is broadcast to all users, "clientUsername has joined the conversation"
 - When client disconnects, a message is broadcast to all users, "clientUsername has left the conversation"
 - Clients should be able to:
        - send a message to whole group (prefix text with "all:")
        - send a message to a individual (prefix text with "clientUsername:")
        - get a list of all connected client names ("who:")
        - disconnect from the group chat.
"""
import hashlib
import socket
import threading
import json
from packet import Packet, PacketType

"""
    Chat Room Server
    
    Completed: Feb.10.2020
    Written By: Michael Nichol & Bobby Horth
    
    Purpose:
    The purpose of this application is to host a server that allows any number of clients to
    connect and interact with each other through a series of approved commands.  The server runs
    indefinitely until closed.  The server reads packets and directs messages to a subset of
    approved clients.
    
    Parameters:
        - None
"""

PORT = 54004  # Port is decided from last 4 digits of SID + 50000
SERVER = socket.gethostbyname(socket.gethostname())  # Gets the IP address of the current system
ADDR = (SERVER, PORT)  # Address, port tuple
DISCONNECT_MESSAGE = "bye"  # Disconnect message determines when a user leaves the chat room

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Creates server socket
server.bind(ADDR)  # Binds the server socket to the port

users = {}  # Dictionary to store (clientUsername, connection) username user pair


# =======================================================
# Routine Name: handle_client
# Author: Michael Nichol & Bobby Horth
# Date: 24.2.2020
# Purpose: Handles all interaction between client and server
# Parameters:
#   - client: the users socket connection
#   - addr: the address of the client
# =======================================================
def handle_client(client, addr):
    clientUsername = getClientUsername(client)  # Gets the client clientUsername from their first input

    for username, user in users.items():  # Notifies all online user that a new user has entered the chat
        sendPacket(user, Packet.createPacket(f"{clientUsername} has connected to the chat on {addr}", clientUsername,
                                             username, PacketType.broadcast))

    users[clientUsername] = client  # Adds the clientUsername, connection to online users dictionary

    sendPacket(client, Packet.createPacket("", "", clientUsername, PacketType.acknowledge))  # Sends acknowledgement

    # Loop and accept packets from the client
    while True:
        jsonString = client.recv(1024).decode()
        if jsonString is None or jsonString =="":
            continue

        while jsonString.find("}") != -1:
            bracketPos = jsonString.find("}")
            data = jsonString[:bracketPos + 1]
            jsonString = jsonString[bracketPos + 1:]

            packet = json.loads(data)
            print(packet)
            packet_length = len(packet)

            if packet_length:  # Checks if the message has substance
                # Check packet for corruption
                checksum = hashlib.md5(packet['data'].encode('utf-8')).hexdigest()
                if checksum != packet['checksum']:
                    # If packet is corrupted, log some info and request resend from client
                    print(f"Packet {packet['id']} from {packet['sender']} was corrupted, requesting resend")
                    sendPacket(client, Packet.createPacket("", "server", clientUsername, PacketType.corrupted))
                    continue

                verb = packet["verb"]

                if verb == "disconnect":
                    del users[clientUsername]  # Removes the user from the dictionary of online participants
                    for username, user in users.items():  # Notifies all online user that a user has left the chat.
                        if username == clientUsername:
                            continue
                        sendPacket(user, Packet.createPacket("", clientUsername, username, PacketType.disconnect))
                    break  # Exits the connection loop

                elif verb == "broadcast":
                    for username, user in users.items():  # Iterates over every online user, username->clientUsername,
                        # user->connection
                        if username == clientUsername:  # Sends message to each user that isn't the one who sent it
                            continue
                        sendPacket(user,
                                   Packet.createPacket(packet["data"], clientUsername, username, PacketType.broadcast, encryptionType=packet["encryptionType"]))
                elif verb == "client list":
                    # Create a comma separated string over all client usernames excluding the sender
                    currentConnections = ", ".join(username for username in filter(lambda name: name != packet['sender'],
                                                                                   users.keys()))
                    sendPacket(client,
                               Packet.createPacket(currentConnections, "server", clientUsername, PacketType.clientList))
                elif packet["destination"] in users:  # Checks if the user exists in online users
                    meta = users[packet["destination"]]  # Gets the users connection
                    sendPacket(meta, packet)  # forwards the message to the client
                else:  # Doesn't meet any of the above requirements, message is invalid
                    sendPacket(client, Packet.createPacket("", "server", clientUsername, PacketType.userNotFound))

                # Send acknowledgement packet
                sendPacket(client, Packet.createPacket("", "server", clientUsername, PacketType.acknowledge))

    client.close()


# =======================================================
# Routine Name: sendPacket
# Author: Michael Nichol & Bobby Horth
# Date: 24.2.2020
# Purpose: Sends a packet to the provided client
# Parameters:
#   - client: the users to send the packet to
#   - packet: the packet to send
# =======================================================
def sendPacket(client, packet):
    to_send = json.dumps(packet)
    client.send(to_send.encode())


# =======================================================
# Routine Name: start
# Author: Michael Nichol & Bobby Horth
# Date: 3.2.2020
# Purpose: Starts the server, and listens for new connections when a client connects
# Parameters:
# Functions, Routines, Libraries
# Modification History
# =======================================================
def start():
    server.listen()  # Listens on the port for new client connections
    while True:
        conn, addr = server.accept()  # Gets the client socket and address when they connect
        thread = threading.Thread(target=handle_client, args=(conn, addr))  # Creates a thread for the user
        thread.start()  # Starts thread, all client interaction is through handle_client method


# =======================================================
# Routine Name: getClientUsername
# Author: Michael Nichol & Bobby Horth
# Date: 3.2.2020
# Purpose: Gets the clientUsername from the message the user submits
# Parameters:
#   - conn: user socket connection
# Functions, Routines, Libraries
# Modification History
# =======================================================
def getClientUsername(conn):
    packet = json.loads(conn.recv(1024).decode())  # Gets the string object from JSON format
    print(packet)  # Log to server
    packet_length = len(packet)  # Gets the length of the transferred string

    if packet_length:  # Checks if the message has substance
        return packet["sender"]

    return ""  # Default user


print("Server started on " + SERVER + ":" + str(PORT))  # DEBUG
start()  # Starts the server
