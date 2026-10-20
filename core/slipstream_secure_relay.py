"""Authenticated TCP/UDP forwarding inside Slipstream's TCP byte stream.

Standalone stdlib agent: both TLS peers require a dedicated per-link trust
certificate. The upstream DNS carrier is treated as an untrusted transport.
No plaintext fallback exists. All destinations are restricted to the saved
port allowlist; callers cannot choose an arbitrary backend host.
"""
import argparse
import json
import queue
import time
import select
import socket
import ssl
import struct
import sys
import threading

MAGIC = b'LDS1'
MAX_DATAGRAM = 65507


class TLSStream:
    """Serialize OpenSSL calls while allowing independent read/write progress.

    SSLSocket operations release the GIL. Two forwarding threads must not
    enter the same SSL object concurrently. Nonblocking calls keep the lock
    short; readiness waits happen outside it so a waiting reader cannot stop
    an outbound request.
    """
    def __init__(self, stream):
        self.stream=stream
        self.lock=threading.Lock()
        self.timeout=60
        stream.setblocking(False)

    def settimeout(self, timeout):
        self.timeout=timeout

    def _deadline(self):
        return None if self.timeout is None else time.monotonic()+self.timeout

    def _wait(self, writing, deadline):
        remaining=None if deadline is None else max(0,deadline-time.monotonic())
        if remaining==0:raise socket.timeout('TLS I/O timed out')
        readable,writable,_=select.select([] if writing else [self.stream],[self.stream] if writing else [],[],remaining)
        if not readable and not writable:raise socket.timeout('TLS I/O timed out')

    def recv(self, size):
        deadline=self._deadline()
        while True:
            try:
                with self.lock:return self.stream.recv(size)
            except ssl.SSLWantReadError:
                self._wait(False,deadline)
            except ssl.SSLWantWriteError:
                self._wait(True,deadline)

    def sendall(self, payload):
        pending=memoryview(payload)
        deadline=self._deadline()
        while pending:
            try:
                with self.lock:sent=self.stream.send(pending)
                if not sent:raise EOFError('TLS stream closed while writing')
                pending=pending[sent:]
            except ssl.SSLWantReadError:
                self._wait(False,deadline)
            except ssl.SSLWantWriteError:
                self._wait(True,deadline)

    def shutdown(self, how):
        with self.lock:self.stream.shutdown(how)

    def close(self):
        with self.lock:self.stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def exact(connection, length):
    data = bytearray()
    while len(data) < length:
        chunk = connection.recv(length - len(data))
        if not chunk:
            raise EOFError('Relay stream closed')
        data.extend(chunk)
    return bytes(data)


def context(config, server=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=config['peer_cert'])
    ctx.load_cert_chain(config['cert'], config['key'])
    return ctx


def bridge(left, right):
    """Drain SSL buffered data as well as socket readability."""
    def copy(source, destination):
        try:
            while True:
                chunk = source.recv(65536)
                if not chunk:
                    break
                destination.sendall(chunk)
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                destination.shutdown(socket.SHUT_WR)
            except OSError:
                pass
    thread = threading.Thread(target=copy, args=(left, right), daemon=True)
    thread.start()
    copy(right, left)
    thread.join(timeout=2)


def report_tls_error(scope, error):
    if isinstance(error, ssl.SSLError):
        # Log only the TLS reason, never traffic, certificates or configuration.
        print('Relay '+scope+' TLS error: '+str(error.reason),file=sys.stderr,flush=True)


def framed_tcp(plain, secure):
    """Logical FIN inside TLS preserves delayed replies without TLS shutdown."""
    plain.settimeout(None)
    secure.settimeout(None)
    def abort():
        for stream in (plain,secure):
            try:stream.shutdown(socket.SHUT_RDWR)
            except OSError:pass
    def receive():
        try:
            while True:
                size=struct.unpack('!I',exact(secure,4))[0]
                if size>65536:raise ValueError('Oversized TCP frame')
                if not size:
                    plain.shutdown(socket.SHUT_WR)
                    return
                plain.sendall(exact(secure,size))
        except (OSError,EOFError,ValueError) as error:
            report_tls_error('TCP receive',error)
            abort()
    reader=threading.Thread(target=receive,daemon=True)
    reader.start()
    try:
        while True:
            payload=plain.recv(65536)
            secure.sendall(struct.pack('!I',len(payload))+payload)
            if not payload:break
    except (OSError,EOFError,ValueError) as error:
        report_tls_error('TCP send',error)
        abort()
    finally:
        reader.join()


def connect_carrier(config):
    raw = socket.create_connection((config.get('carrier_host', '127.0.0.1'), int(config['carrier_port'])), timeout=10)
    try:
        wrapped = TLSStream(context(config).wrap_socket(raw, server_hostname=config.get('server_name', 'vxlb-slipstream')))
        wrapped.settimeout(60)
        return wrapped
    except BaseException:
        raw.close()
        raise


def serve_connection(raw, config, tls_context):
    try:
        raw.settimeout(10)
        with TLSStream(tls_context.wrap_socket(raw, server_side=True)) as connection:
            connection.settimeout(60)
            header = exact(connection, 7)
            magic, protocol, port = struct.unpack('!4sBH', header)
            if magic != MAGIC:
                return
            if protocol == 3 and port == 0:
                # Authenticated transport challenge; never opens a backend port.
                size = struct.unpack('!H', exact(connection, 2))[0]
                if not 1 <= size <= 256:
                    return
                connection.sendall(exact(connection, size))
                return
            if port not in {int(p) for p in config['ports']} or protocol not in (1, 2, 4):
                return
            if protocol in (1, 4):
                with socket.create_connection((config.get('target_host', '127.0.0.1'), port), timeout=10) as target:
                    target.settimeout(60)
                    if protocol == 4:
                        framed_tcp(target, connection)
                    else:
                        bridge(connection, target)
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
                    target.settimeout(10)
                    target.connect((config.get('target_host', '127.0.0.1'), port))
                    udp_server(connection, target, config)
    except (OSError, ssl.SSLError, EOFError, ValueError):
        raw.close()


def client_tcp(raw, config, port):
    try:
        raw.settimeout(60)
        with raw, connect_carrier(config) as carrier:
            carrier.sendall(struct.pack('!4sBH', MAGIC, 4, port))
            framed_tcp(raw, carrier)
    except (OSError, ssl.SSLError, EOFError):
        raw.close()


def udp_frames(connection, stop, activity, idle):
    """Keep partial frames across timeouts; expire only genuinely idle flows."""
    def read(size):
        result = bytearray()
        while len(result) < size:
            if stop.is_set() or time.monotonic() - activity[0] >= idle:
                raise EOFError('UDP session expired')
            try:
                chunk = connection.recv(size - len(result))
            except socket.timeout:
                continue
            if not chunk:
                raise EOFError('UDP session closed')
            result.extend(chunk)
        return bytes(result)
    while not stop.is_set():
        length = struct.unpack('!H', read(2))[0]
        if length > MAX_DATAGRAM:
            raise ValueError('Oversized datagram')
        payload = read(length)
        activity[0] = time.monotonic()
        yield payload


def udp_server(connection, target, config):
    stop = threading.Event()
    activity = [time.monotonic()]
    idle = max(1, min(600, int(config.get('udp_idle_timeout', 60))))
    connection.settimeout(1)
    target.settimeout(1)
    def requests():
        try:
            for payload in udp_frames(connection, stop, activity, idle):
                target.send(payload)
        except (OSError, EOFError, ValueError) as error:
            report_tls_error('UDP server receive',error)
        finally:
            stop.set()
    worker = threading.Thread(target=requests, daemon=True)
    worker.start()
    try:
        while not stop.is_set() and time.monotonic() - activity[0] < idle:
            try:
                payload = target.recv(MAX_DATAGRAM)
            except socket.timeout:
                continue
            connection.sendall(struct.pack('!H', len(payload)) + payload)
            activity[0] = time.monotonic()
    finally:
        stop.set()
        worker.join(timeout=2)


class UDPSession:
    """One authenticated stream and stable backend socket per client flow."""
    def __init__(self, listener, address, config, port):
        self.listener, self.address = listener, address
        self.config, self.port = config, port
        self.pending = queue.Queue(maxsize=64)
        self.lock = threading.Lock()
        self.queued_bytes = 0
        self.stop = threading.Event()
        self.activity = [time.monotonic()]

    def enqueue(self, payload):
        with self.lock:
            if self.stop.is_set() or self.queued_bytes + len(payload) > 65536:
                return
            try:
                self.pending.put_nowait(payload)
            except queue.Full:
                return
            self.queued_bytes += len(payload)
            self.activity[0] = time.monotonic()

    def run(self):
        idle = max(1, min(600, int(self.config.get('udp_idle_timeout', 60))))
        try:
            with connect_carrier(self.config) as carrier:
                carrier.sendall(struct.pack('!4sBH', MAGIC, 2, self.port))
                carrier.settimeout(1)
                def replies():
                    try:
                        for payload in udp_frames(carrier, self.stop, self.activity, idle):
                            self.listener.sendto(payload, self.address)
                    except (OSError, EOFError, ValueError) as error:
                        report_tls_error('UDP client receive',error)
                    finally:
                        self.stop.set()
                reader = threading.Thread(target=replies, daemon=True)
                reader.start()
                try:
                    while not self.stop.is_set() and time.monotonic() - self.activity[0] < idle:
                        try:
                            payload = self.pending.get(timeout=0.2)
                        except queue.Empty:
                            continue
                        with self.lock:
                            self.queued_bytes -= len(payload)
                        carrier.sendall(struct.pack('!H', len(payload)) + payload)
                finally:
                    self.stop.set()
                    reader.join(timeout=2)
        except (OSError, EOFError, ValueError):
            pass
        finally:
            self.stop.set()


def run(config):
    listeners = []
    sessions = {}
    sessions_lock = threading.Lock()
    semaphore = threading.BoundedSemaphore(int(config.get('max_connections', 128)))

    def dispatch(function, *arguments):
        if not semaphore.acquire(blocking=False):
            if function in (serve_connection, client_tcp):
                arguments[0].close()
            return
        def worker():
            try:
                function(*arguments)
            finally:
                semaphore.release()
        threading.Thread(target=worker, daemon=True).start()

    try:
        if config['role'] == 'server':
            tls_context = context(config, server=True)
            listener = socket.socket()
            listeners.append(listener)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, 'TCP_MAXSEG'):
                listener.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1360)
            listener.bind(('127.0.0.1', int(config['listen_port'])))
            listener.listen(128)
            while True:
                raw, _ = listener.accept()
                dispatch(serve_connection, raw, config, tls_context)
        elif config['role'] == 'client':
            context(config)  # Validate trust files before opening public ports.
            mapping = {}
            for value in config['ports']:
                port = int(value)
                for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                    listener = socket.socket(socket.AF_INET, kind)
                    listeners.append(listener)
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    if kind == socket.SOCK_STREAM and hasattr(socket, 'TCP_MAXSEG'):
                        listener.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1360)
                    host = '127.0.0.1' if port in {int(value) for value in config.get('loopback_ports', [])} else config.get('listen_host', '0.0.0.0')
                    listener.bind((host, port))
                    if kind == socket.SOCK_STREAM:
                        listener.listen(128)
                    mapping[listener] = (kind, port)
            while True:
                ready, _, _ = select.select(listeners, [], [])
                for listener in ready:
                    kind, port = mapping[listener]
                    if kind == socket.SOCK_STREAM:
                        raw, _ = listener.accept()
                        dispatch(client_tcp, raw, config, port)
                    else:
                        data, address = listener.recvfrom(MAX_DATAGRAM)
                        key = (port, address)
                        with sessions_lock:
                            session = sessions.get(key)
                            if session is None or session.stop.is_set():
                                if not semaphore.acquire(blocking=False):
                                    continue
                                session = UDPSession(listener, address, config, port)
                                sessions[key] = session
                                def udp_worker(flow=session, flow_key=key):
                                    try:
                                        flow.run()
                                    finally:
                                        with sessions_lock:
                                            if sessions.get(flow_key) is flow:
                                                del sessions[flow_key]
                                        semaphore.release()
                                threading.Thread(target=udp_worker, daemon=True).start()
                            session.enqueue(data)
        else:
            raise ValueError('Unknown relay role')
    finally:
        with sessions_lock:
            for session in sessions.values():
                session.stop.set()
        for listener in listeners:
            listener.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('config')
    arguments = parser.parse_args()
    with open(arguments.config) as source:
        run(json.load(source))
