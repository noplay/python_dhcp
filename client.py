import socket
import struct
from uuid import getnode as get_mac
from random import randint

def getMacInBytes():
    mac = str(hex(get_mac()))
    mac = mac[2:]
    while len(mac) < 12:
        mac = '0' + mac
    macb = b''
    for i in range(0, 12, 2):
        m = int(mac[i:i + 2], 16)
        macb += struct.pack('!B', m)
    return macb


class DHCPDiscover:
    def __init__(self):
        self.transactionID = b''
        for i in range(4):
            t = randint(0, 255)
            self.transactionID += struct.pack('!B', t)

    def buildPacket(self):
        macb = getMacInBytes()
        packet = b''
        packet += b'\x01'  # Message type: Boot Request (1)
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0
        packet += self.transactionID  # Transaction ID
        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x80\x00'  # Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        # packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += macb
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  # Server host name not given
        packet += b'\x00' * 125  # Boot file name not given
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
        packet += b'\x35\x01\x01'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        # packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        packet += b'\x3d\x06' + macb
        packet += b'\x37\x03\x03\x01\x06'  # Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'  # End Option
        return packet


if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # 广播
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        s.bind(('', 6800))
    except Exception as e:
        print("port 68 is in use")
        s.close()
        exit()

    discoverPacket = DHCPDiscover()
    s.sendto(discoverPacket.buildPacket(), ('<broadcast>', 67))

    # receiving DHCPOffer packet
    s.settimeout(2)
    while 1:
        data = s.recvfrom(1024)
        if not data:
            break
        print(data)

    s.close()  # we close the socket

    input('press any key to quit...')
    exit()