"""Bounded UDP DNS front end protecting the pinned upstream DNS decoder.

Accepts one uncompressed IN/TXT tunnel question, with optional well-formed
EDNS0 OPT. Other valid questions receive authoritative NXDOMAIN. Malformed
wire messages are discarded before reaching the upstream C decoder.
"""
import argparse
import ipaddress
import json
import re
import selectors
import socket
import struct
import time


def question(packet):
    if not 12 <= len(packet) <= 4096:
        raise ValueError('Unsupported DNS wire message length')
    identifier, flags, qd, an, ns, ar = struct.unpack('!6H', packet[:12])
    if flags & 0xf800 or qd != 1 or an or ns or ar > 1:
        raise ValueError('Unsupported DNS query structure')
    labels, offset, total = [], 12, 1
    while True:
        if offset >= len(packet):
            raise ValueError('Truncated name')
        size = packet[offset]
        offset += 1
        if size == 0:
            break
        if size > 63 or offset + size > len(packet):
            raise ValueError('Invalid DNS label')
        total += size + 1
        if total > 255:
            raise ValueError('DNS name too long')
        labels.append(packet[offset:offset+size].decode('ascii').lower())
        offset += size
    if offset + 4 > len(packet):
        raise ValueError('Truncated question')
    kind, cls = struct.unpack('!HH', packet[offset:offset+4])
    offset += 4
    question_end = offset
    if ar:
        if offset + 11 > len(packet) or packet[offset] != 0:
            raise ValueError('Invalid OPT owner')
        kind_opt, size, ttl, length = struct.unpack('!HHIH', packet[offset+1:offset+11])
        if kind_opt != 41 or size < 512 or (ttl >> 16) & 255:
            raise ValueError('Unsupported EDNS OPT')
        offset += 11
        end = offset + length
        if end != len(packet):
            raise ValueError('Truncated EDNS data')
        options = 0
        while offset < end:
            options += 1
            if options > 16:
                raise ValueError('Too many EDNS options')
            if offset + 4 > end:
                raise ValueError('Truncated EDNS option')
            _, size = struct.unpack('!HH', packet[offset:offset+4])
            offset += 4 + size
            if offset > end:
                raise ValueError('Truncated EDNS value')
    if offset != len(packet):
        raise ValueError('Trailing DNS data')
    return identifier, flags, labels, kind, cls, question_end


def permitted(packet, domain):
    try:
        _, _, labels, kind, cls, _ = question(packet)
        suffix = domain.lower().rstrip('.').split('.')
        data = labels[:-len(suffix)]
        return (kind == 16 and cls == 1 and len(labels) > len(suffix)
                and labels[-len(suffix):] == suffix and bool(data)
                and all(re.fullmatch('[a-z2-7]+', label) for label in data))
    except (ValueError, UnicodeError, struct.error):
        return False


def run(config):
    backend = ('127.0.0.1', int(config['backend_port']))
    domain = config['domain']
    peers = {}
    selector = selectors.DefaultSelector()
    front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_host = str(ipaddress.IPv4Address(config.get('listen_host', '0.0.0.0')))
    front.bind((listen_host, int(config['listen_port'])))
    front.setblocking(False)
    selector.register(front, selectors.EVENT_READ, None)
    maximum = 4096

    def discard(address):
        peer = peers.pop(address)
        selector.unregister(peer[0])
        peer[0].close()

    try:
        while True:
            now = time.monotonic()
            for address, (_, used) in list(peers.items()):
                if now - used > 10:
                    discard(address)
            for key, _ in selector.select(timeout=1):
                sock = key.fileobj
                try:
                    if key.data is None:
                        packet, address = front.recvfrom(65535)
                        if not permitted(packet, domain):
                            try:
                                identifier, flags, _, _, _, end = question(packet)
                                response = struct.pack('!6H', identifier, 0x8403 | (flags & 0x100), 1, 0, 0, 0) + packet[12:end]
                                front.sendto(response, address)
                            except (ValueError, UnicodeError, struct.error):
                                pass
                            continue
                        if address not in peers:
                            if len(peers) >= maximum:
                                discard(min(peers, key=lambda value: peers[value][1]))
                            peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            peer.connect(backend)
                            peer.setblocking(False)
                            peers[address] = (peer, now)
                            selector.register(peer, selectors.EVENT_READ, address)
                        peer, _ = peers[address]
                        peers[address] = (peer, now)
                        peer.send(packet)
                    else:
                        packet = sock.recv(65535)
                        front.sendto(packet, key.data)
                        peers[key.data] = (sock, now)
                except (OSError, BlockingIOError):
                    if key.data is not None and key.data in peers:
                        discard(key.data)
    finally:
        for address in list(peers):
            discard(address)
        selector.close()
        front.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('config')
    arguments = parser.parse_args()
    with open(arguments.config) as source:
        run(json.load(source))
