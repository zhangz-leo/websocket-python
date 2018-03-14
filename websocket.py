#!/usr/bin/env python
# -*- coding:utf-8 -*-
import socket
import base64
import hashlib
import struct


class websocket():
    connect_str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    response = '''\
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: {0}\r\n
'''

    def __init__(self, host='localhost', port=10101):
        '''初始化'''
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind((host, port))
        self.s.listen(50)

    def estab_websocket(self):
        '''建立websocket连接'''
        conn, addr = self.s.accept()
        data = conn.recv(1024)
        data = str(data, encoding='utf8')
        arr = data.split("\r\n")
        headers = {}
        request_line = arr[0].split(' ')
        for i in arr[1:-2]:
            key = i.split(": ")[0]
            val = i.split(": ")[1]
            headers[key] = val

        # 检查web端发来的请求是否合乎规范
        if request_line[0] == 'GET' and\
            request_line[2] in ['HTTP/1.1', 'HTTP/2.0'] and\
            'websocket' in headers['Upgrade'] and \
            'Upgrade' in headers['Connection'] and \
            len(base64.b64decode(headers['Sec-WebSocket-Key'])) == 16 and \
                '13' in headers['Sec-WebSocket-Version']:

            key = self.websocket_key(headers['Sec-WebSocket-Key'])
            response1 = self.response.format(key)
            # 返回握手信息
            conn.send(bytes(response1, encoding='utf8'))
            return (conn, addr)
        else:
            print('建立连接失败')
            return self.close_websocket(conn)

    def websocket_key(self, recv):
        '''对WebSocket-Key进行编码'''
        byte = '{0}{1}'.format(recv, self.connect_str).encode()
        sha1_byte = hashlib.sha1(byte).digest()
        b64 = base64.b64encode(sha1_byte)
        key = b64.decode()
        return key


    def send_handle(self, data):
        '''将要发送的文本进行编码'''
        payload_data = bytes(data, encoding='utf8')
        data_len=len(payload_data)


        if len(payload_data)<126:
            payload_len = struct.pack('B',data_len)
        elif len(payload_data)<0xFFFF:
            payload_len=struct.pack('!BH',126,data_len)
        else:
            payload_len=struct.pack('!BQ',127,data_len)
        # 使用struct模块处理二进制数

        data_frames = b'\x81'+payload_len+payload_data
        return data_frames

    def recv_handle(self, conn, data):
        '''通过解掩码负载数据得到文本内容'''
        if bytes.fromhex(format(data[0] & 0xFF, 'x')) == b'\x88':
            return self.close_websocket(conn)   

        # 计算数据位置偏差值，取出掩码和负载数据
        data_size = data[1] & 127
        if data_size==0 :
            return ''
        elif data_size<126:
            offset=0         
        elif data_size ==126:
            data_size = int(data[2:4].hex(),16)& 0xFFFF
            offset=2
        elif data_size ==127:
            data_size = int(data[2:10].hex(),16)
            offset=8
        else:
            return self.close_websocket(conn)
        mask_end=6+offset
        mask = data[2+offset:mask_end]
        payload_data = data[mask_end:] 
        mask_data = b''

        # 对负载数据进行解掩码
        for i in range(0, len(payload_data)):
            j = i % 4
            mask_data += bytes.fromhex(format(payload_data[i] ^ mask[j], '02x'))
        return mask_data.decode()

    def close_websocket(self, conn):
        '''关闭websocket连接'''

        # 发送连接关闭操作码
        conn.send(b'\x88\x00')
        conn.close()
        print('Websocket 连接关闭')
        return False

    def send(self, conn, msg):
        '''发送'''
        data = self.send_handle(msg)
        conn.send(data)

    def recv(self, conn):
        '''接收'''
        data = conn.recv(1024)
        recv_data = self.recv_handle(conn, data)
        return recv_data

