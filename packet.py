"""
    Chat Room Packet

    Completed: Feb.10.2020
    Written By: Michael Nichol & Bobby Horth

    Purpose:
    The purpose of this file is to outline the structure and formatting of packets and approved
    types to be transferred between clients and the server

    Parameters:
        - None
"""

import hashlib


# =======================================================
# Routine Name: PacketType
# Author: Michael Nichol & Bobby Horth
# Date: 24.2.2020
# Purpose: A mach enumerable class.  Collection of tuples with id's and strings
# Parameters:
#   - none
# =======================================================
class PacketType:
    username = (1, "username")
    broadcast = (2, "broadcast")
    privateMessage = (3, "private message")
    clientList = (4, "client list")
    disconnect = (5, "disconnect")
    userNotFound = (6, "user not found")
    acknowledge = (7, "valid packet")
    corrupted = (8, "corrupted packet")


# =======================================================
# Routine Name: Packet
# Author: Michael Nichol & Bobby Horth
# Date: 24.2.2020
# Purpose: Packet object meant to be created and sent in JSON format as a dictionary
# Parameters:
#   - data: Message contents to be transferred
#   - sender: Display name of the client who sent the message
#   - destination: Display name of the client who receives the message
#   - pType: String value of the packet type being sent
# =======================================================
class Packet:
    @staticmethod
    def createPacket(data: str, sender: str, destination: str, pType: PacketType, encryptionType = ""):
        return {"id": pType[0], "version": 3, "data": data, "sender": sender, "destination": destination,
                "verb": pType[1],
                "checksum": hashlib.md5(data.encode('utf-8')).hexdigest(),
                "encryptionType": encryptionType
                }
