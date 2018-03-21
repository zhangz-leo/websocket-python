#!/usr/bin/env python
# -*- coding:utf-8 -*-
import socket
import base64
import hashlib
import struct
import asyncio


class websocket_conn():
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer

    def send_handle(self, data):
        '''handle data before send'''
        payload_data = bytes(data, encoding='utf8')
        data_len = len(payload_data)

        if len(payload_data) < 126:
            payload_len = struct.pack('B', data_len)
        elif len(payload_data) < 0xFFFF:
            payload_len = struct.pack('!BH', 126, data_len)
        else:
            payload_len = struct.pack('!BQ', 127, data_len)


        data_frames = b'\x81'+payload_len+payload_data
        return data_frames

    def xor_mask(self, mask, payload_data):
        '''unmask payload_data'''
        mask_data = b''
        for i in range(0, len(payload_data)):
            j = i % 4
            mask_data += bytes.fromhex(
                format(payload_data[i] ^ mask[j], '02x'))
        return mask_data.decode('utf8')

    def close_websocket(self, writer):
        writer.write(b'\x88\x00')

    def send(self, msg):
        data = self.send_handle(msg)
        self.writer.write(data)

    async def get_key_data(self):
        '''get masking_key and payload_data'''
        data_size = await self.reader.read(1)
        data_size = int(data_size.hex(), 16) &0x7f
        if data_size == 0:
            raise Exception('payload_data is empty')
        elif data_size < 126:
            pass
        elif data_size == 126:
            data_size = await  self.reader.read(2)
        elif data_size == 127:
            data_size = await  self.reader.read(8)

        mask = await self.reader.read(4)
        if type(data_size) == bytes:
            data_size = int(data_size.hex(), 16)
        payload_data = await self.reader.read(data_size)
        return (mask,payload_data)

    async def loop(self, connect_callback, message_callback, close_callback):
        if connect_callback:
            connect_callback(self)
        next_step=True
        while next_step:
            code = await self.reader.read(1)
            if code == b'\x88':
                if close_callback:
                    close_callback(self)
                self.close_websocket(self.writer)
                return
            mask,payload_data= await self.get_key_data()
            data = self.xor_mask(mask, payload_data)
            if message_callback:
                next_step = message_callback(self, data)
            if not next_step ==False:
                next_step=True
            elif close_callback:
                    self.close_websocket(self.writer)

class websocket():

    connect_str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    response = '''\
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: {0}\r\n
'''

    def __init__(self, host='localhost', port=10101):
        self.host = host
        self.port = port
        self.connect_callback = None
        self.message_callback = None
        self.close_callback = None

    def byte2str(self, data):
        return str(data, encoding='utf8')

    async def estab_websocket(self, reader, writer):
        data = await reader.readline()
        request_line = self.byte2str(data).split(' ')
        headers = {}

        while True:
            data = await reader.readline()
            data = self.byte2str(data).split(': ')
            if len(data) >= 2:
                key = data[0]
                val = data[1].rstrip()
                headers[key] = val
            else:
                break

    
        if request_line[0] == 'GET' and\
            request_line[2].rstrip() in ['HTTP/1.1', 'HTTP/2.0'] and\
            'websocket' in headers['Upgrade'] and \
            'Upgrade' in headers['Connection'] and \
            len(base64.b64decode(headers['Sec-WebSocket-Key'])) == 16 and \
                '13' in headers['Sec-WebSocket-Version']:

            key = self.websocket_key(headers['Sec-WebSocket-Key'])
            response1 = self.response.format(key)
    
            writer.write(bytes(response1, encoding='utf8'))
        else:
            raise Exception('_Fail the WebSocket Connection_')

    def websocket_key(self, key):
        byte = '{0}{1}'.format(key, self.connect_str).encode()
        sha1_byte = hashlib.sha1(byte).digest()
        b64 = base64.b64encode(sha1_byte)
        key = b64.decode()
        return key

    async def recv(self, reader, writer):
        self.reader = reader
        self.writer = writer
        await self.estab_websocket(reader, writer)
        conn = websocket_conn(reader, writer)
        await conn.loop(self.connect_callback, self.message_callback, self.close_callback)

    def on(self, name, callback):
        if name == 'message':
            self.message_callback = callback
        elif name == 'connect':
            self.connect_callback = callback
        elif name == 'close':
            self.close_callback = callback
        else:
            raise Exception('the method {0} is not exists'.format(name))

    def start(self):
        loop = asyncio.get_event_loop()
        coroutine = asyncio.start_server(
            self.recv, self.host, self.port, loop=loop)
        loop.run_until_complete(coroutine)
        loop.run_forever()

if __name__=='__main__':
    def message(conn, data):
        conn.send(data)

    def close(conn):
        pass

    def connect(conn):
        pass

    server = websocket()
    server.on('message', hello)
    server.start()
