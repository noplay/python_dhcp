#!/usr/local/bin/python3

# *-* coding:utf-8 *-*

import socket


class DHCPOFFER:
    def __init__(self, mac, tranid):
        self.transID = tranid
        self.macAddr = mac

    def offerPackage(self):
        packet = b''
        packet += b'\x02'  # Message type: Boot Request (1)
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0
        packet += self.transID  # Transaction ID
        packet += b'\x00\x02'  # Seconds elapsed: 0
        packet += b'\x00\x00'  # Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += b'\xc0\xa8\x01\x10'  # Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
        packet += b'\xc0\xa8\x01\x01'  # Relay agent IP address: 0.0.0.0
        # packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += self.macAddr
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  # Server host name not given
        packet += b'\x00' * 125  # Boot file name not given
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
        packet += b'\x35\x01\x02'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        # packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        # dhcp 公共 结束 选项开始

        packet += b'\x01\x04\xff\xff\xff\x00'  # netmask
        packet += b'\x03\x04\xc0\xa8\x01\x01'  # 网关
        packet += b'\x06\x04\xca\xcf\xf0\xe1'  # dns
        packet += b'\x33\x04\x00\x03\xf4\x80'  # lease time
        packet += b'\x3a\x04\x00\x03\xf4\x80'  # renewal time
        packet += b'\x3b\x04\x00\x03\xf4\x80'  # rebinding time
        packet += b'\x36\x04\xc0\xa8\x01\x01'  # dhcp server identifier
        packet += b'\xff'  # End Option
        return packet


class DHCPACK:
    def __init__(self, transid):
        self.transID = transid

    def ackPackage(self):
        packet = b''
        packet += b'\x02'  # Message type: Boot Request (1)
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0
        packet += self.transID  # Transaction ID
        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x00\x00'  # Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += b'\xc0\xa8\x01\x10'  # Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
        packet += b'\xc0\xa8\x01\x01'  # Relay agent IP address: 0.0.0.0

        packet += b'\x00\x26\x9e\x04\x1e\x9b'  # Client MAC address: 00:26:9e:04:1e:9b
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000

        packet += b'\x00' * 67  # Server host name not given
        packet += b'\x00' * 125  # Boot file name not given
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP

        # option
        packet += b'\x35\x01\x05'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        # packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        # dhcp 公共 结束 选项开始

        packet += b'\x01\x04\xff\xff\xff\x00'  # netmask
        packet += b'\x03\x04\xc0\xa8\x01\x01'  # 路由
        packet += b'\x06\x04\xca\xcf\xf0\xe1'  # dns
        packet += b'\x33\x04\x00\x03\xf4\x80'  # lease time
        packet += b'\x3a\x04\x00\x03\xf4\x80'  # renewal time
        packet += b'\x3b\x04\x00\x03\xf4\x80'  # rebinding time
        packet += b'\x36\x04\xc0\xa8\x01\x01'  # dhcp server identifier
        packet += b'\xff'  # End Option
        return packet


if __name__ == '__main__':

    serverPort = 57
    clientPort = 68

    addr = ('', serverPort)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 广播
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(addr)
    except Exception as e:
        print("port " + serverPort + " is in use")
        s.close()
        exit()

    while 1:
        data = s.recv(1024)
        if not data:
            break
        print("==============discovery==============")
        print(data)
        print("==============discovery end==============")
        tid = data[4:8]
        mac = data[28:34]
        dhcpOffer = DHCPOFFER(mac, tid)
        offerPack = dhcpOffer.offerPackage()
        s.sendto(offerPack, ('<broadcast>', clientPort))  # 发送offer包
        while 1:
            d = s.recv(1024)  # 接收到request 包
            if not d:
                break

            print("================request===============")
            print(d)
            print("================request end===============")

            acktid = data[4:8]
            dhcpACK = DHCPACK(acktid)
            s.sendto(dhcpACK.ackPackage(), ('<broadcast>', clientPort))  # 发送ack包

