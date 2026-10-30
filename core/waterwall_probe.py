"""Standalone loopback-only nonce echo/probe for WaterWall TCP/UDP tunnel verification."""
import asyncio
import socket
import sys

class Echo(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def __init__(self, done=None):
        self.done = done
        self.seen = set()

    def datagram_received(self, data, address):
        self.transport.sendto(data, address)
        self.seen.add(data)

async def echo(port):
    async def handle(reader, writer):
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()

    done = asyncio.Event()
    loop = asyncio.get_running_loop()
    try:
        loop.add_reader(sys.stdin.fileno(), done.set)
    except Exception:
        pass
    try:
        server = await asyncio.start_server(handle, '127.0.0.1', port)
        transport, _ = await loop.create_datagram_endpoint(
            lambda: Echo(), local_addr=('127.0.0.1', port)
        )
    except OSError as error:
        print(f'BUSY {error}', flush=True)
        return
    print('READY', flush=True)
    try:
        await done.wait()
    finally:
        server.close()
        await server.wait_closed()
        transport.close()

def reach(port):
    """Prove the live backend accepted the tunnel connection without binding its port.

    A banner, or a peer that stays open, means the service is there. An immediate
    close is the same failure as a nonce that comes back empty.
    """
    with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
        sock.settimeout(2)
        try:
            sock.sendall(b'\x00')
        except OSError as error:
            raise RuntimeError(f'WaterWall reach write failed on port {port}: {error}') from error
        try:
            data = sock.recv(16)
        except socket.timeout:
            print('WATERWALL_PROBE_OK')
            return
        if data:
            print('WATERWALL_PROBE_OK')
            return
    raise RuntimeError(f'WaterWall reach closed on port {port}: got 0 bytes')

def probe(port, nonce, protocols=('tcp', 'udp')):
    payload = (nonce.encode() * 1024)[:32768]
    if 'tcp' in protocols:
        with socket.create_connection(('127.0.0.1', port), timeout=5) as s:
            s.settimeout(5)
            s.sendall(payload)
            data = b''
            while len(data) < len(payload):
                chunk = s.recv(min(4096, len(payload) - len(data)))
                if not chunk:
                    break
                data += chunk
            if data != payload:
                raise RuntimeError(f'WaterWall TCP nonce mismatch: got {len(data)} bytes, expected {len(payload)}')

    if 'udp' in protocols:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.connect(('127.0.0.1', port))
            for i in range(8):
                packet = str(i).encode() + payload[:1000]
                s.send(packet)
                reply = s.recv(2048)
                if reply != packet:
                    raise RuntimeError(f'WaterWall UDP nonce mismatch on packet {i}')

    print('WATERWALL_PROBE_OK')

if __name__ == '__main__':
    if len(sys.argv) < 3:
        raise ValueError('Usage: waterwall_probe.py echo <port> | probe <port> <nonce>')
    if sys.argv[1] == 'echo':
        asyncio.run(echo(int(sys.argv[2])))
    elif sys.argv[1] == 'probe':
        protocols = ('tcp', 'udp')
        if len(sys.argv) > 4 and sys.argv[4] == 'tcp-only':
            protocols = ('tcp',)
        probe(int(sys.argv[2]), sys.argv[3], protocols)
    elif sys.argv[1] == 'reach':
        reach(int(sys.argv[2]))
    else:
        raise ValueError(f'Unknown action: {sys.argv[1]}')
