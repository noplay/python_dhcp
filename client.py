# *-* coding:utf-8 *-*
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
        print(macb)
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


# dhcp offer 解包
class DHCPOffer:
    def __init__(self, data, transID):
        self.data = data
        self.transID = transID
        self.offerIP = ''
        self.nextServerIP = ''
        self.DHCPServerIdentifier = ''
        self.leaseTime = ''
        self.router = ''
        self.subnetMask = ''
        self.DNS = []
        self.unpack()

    def unpack(self):
        if self.data[4:8] == self.transID:
            self.offerIP = '.'.join(map(lambda x: str(x), data[16:20]))
            self.nextServerIP = '.'.join(map(lambda x: str(x), data[20:24]))  # c'est une option
            self.DHCPServerIdentifier = '.'.join(map(lambda x: str(x), data[245:249]))
            self.leaseTime = str(struct.unpack('!L', data[251:255])[0])
            self.router = '.'.join(map(lambda x: str(x), data[257:261]))
            self.subnetMask = '.'.join(map(lambda x: str(x), data[263:267]))
            dnsNB = int(data[268] / 4)
            for i in range(0, 4 * dnsNB, 4):
                self.DNS.append('.'.join(map(lambda x: str(x), data[269 + i:269 + i + 4])))

    def printOffer(self):
        key = ['DHCP Server', 'Offered IP address', 'subnet mask', 'lease time (s)', 'default gateway']
        val = [self.DHCPServerIdentifier, self.offerIP, self.subnetMask, self.leaseTime, self.router]
        for i in range(4):
            print('{0:20s} : {1:15s}'.format(key[i], val[i]))

        print('{0:20s}'.format('DNS Servers') + ' : ', end='')
        if self.DNS:
            print('{0:15s}'.format(self.DNS[0]))
        if len(self.DNS) > 1:
            for i in range(1, len(self.DNS)):
                print('{0:22s} {1:15s}'.format(' ', self.DNS[i]))


class DHCPRequest:
    def __init__(self, transID, reqIp):
        self.transID = transID
        self.reqAddr = reqIp

    def requestPackage(self):
        macb = getMacInBytes()
        packet = b''
        packet += b'\x03'  # Message type: Boot Request (1)
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0
        packet += self.transID  # Transaction ID
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
        packet += b'\x35\x01\x03'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        # packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        packet += b'\x3d\x07\x01' + macb
        packet += b'\x32\x04' + self.reqAddr  # request ip addr
        packet += b'\x0c\x02\x74\x74'
        # packet += b'\x37\x03\x03\x01\x06'  # Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'  # End Option
        return packet


if __name__ == '__main__':

    serverPort = 57
    clientPort = 68

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # 广播
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('', clientPort))
    except Exception as e:
        print("port " + clientPort + " is in use")
        s.close()
        exit()

    discoverPacket = DHCPDiscover()
    s.sendto(discoverPacket.buildPacket(), ('<broadcast>', serverPort))  # 发送discovery包

    # receiving DHCPOffer packet
    s.settimeout(2)
    try:
        while True:
            data = s.recv(1024)
            print("=========offer============")
            print(data)  # 接收到offer包
            print("=========offer end============")
            offer = DHCPOffer(data, discoverPacket.transactionID)
            if offer.offerIP:
                print("ip:" + offer.offerIP)
                dhcprequest = DHCPRequest(discoverPacket.transactionID, data[16:20])
                s.sendto(dhcprequest.requestPackage(), ('<broadcast>', serverPort))  # 发送request包

                while True:
                    dd = s.recv(1024)  # 接收到ack包
                    print("=============ack===============")
                    print(dd)
                    print("=============ack end===============")
                break
    except socket.timeout as e:
        print(e)

    s.close()  # we close the socket
    input('press any key to quit...')
    exit()
