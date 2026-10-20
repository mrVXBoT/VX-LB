"""UDP session framing and resource limits shared by DNS and HTTP carriers."""
import socket
import struct
import threading
import time
import pytest
from core.slipstream_secure_relay import UDPSession, udp_frames


def test_udp_partial_frame_survives_read_timeout_and_empty_datagram():
    receiver,sender=socket.socketpair()
    receiver.settimeout(0.01)
    stop=threading.Event();activity=[time.monotonic()]
    def fragmented():
        sender.sendall(b'\x00')
        time.sleep(0.04)
        sender.sendall(b'\x03abc\x00\x00')
    writer=threading.Thread(target=fragmented);writer.start()
    try:
        frames=udp_frames(receiver,stop,activity,1)
        assert next(frames)==b'abc'
        assert next(frames)==b''
    finally:
        stop.set();writer.join(timeout=2);receiver.close();sender.close()


def test_udp_oversized_frame_rejected_before_payload_read():
    receiver,sender=socket.socketpair()
    try:
        sender.sendall(struct.pack('!H',65535))
        with pytest.raises(ValueError,match='Oversized'):
            next(udp_frames(receiver,threading.Event(),[time.monotonic()],1))
    finally:
        receiver.close();sender.close()


@pytest.mark.parametrize('payload,count,expected',[ (b'x',100,64), (b'x'*32768,3,2)])
def test_udp_flow_queue_is_bounded_by_count_and_bytes(payload,count,expected):
    flow=UDPSession(None,('127.0.0.1',1234),{},1234)
    for _ in range(count):flow.enqueue(payload)
    assert flow.pending.qsize()==expected
    assert flow.queued_bytes==expected*len(payload)
    flow.stop.set();flow.enqueue(b'late')
    assert flow.pending.qsize()==expected


def test_tls_read_wait_does_not_hold_openssl_lock_or_block_outbound_data():
    from core.slipstream_secure_relay import TLSStream
    import ssl
    incoming,peer=socket.socketpair();waiting=threading.Event()
    class FakeTLS:
        def setblocking(self,value):incoming.setblocking(value)
        def recv(self,size):
            try:return incoming.recv(size)
            except BlockingIOError:
                waiting.set();raise ssl.SSLWantReadError()
        def send(self,data):return peer.send(data)
        def fileno(self):return incoming.fileno()
        def close(self):incoming.close();peer.close()
    stream=TLSStream(FakeTLS());stream.settimeout(1);received=[]
    reader=threading.Thread(target=lambda:received.append(stream.recv(1)),daemon=True)
    reader.start()
    try:
        assert waiting.wait(1)
        stream.sendall(b'x')
        reader.join(timeout=2)
        assert not reader.is_alive() and received==[b'x']
    finally:stream.close()


def test_tls_operations_from_two_threads_never_enter_same_ssl_object_together():
    from core.slipstream_secure_relay import TLSStream
    class FakeTLS:
        active=False
        def setblocking(self,value):assert value is False
        def operation(self):
            assert not self.active,'Concurrent OpenSSL call'
            self.active=True
            try:time.sleep(0.002)
            finally:self.active=False
        def recv(self,size):self.operation();return b'x'
        def send(self,data):self.operation();return len(data)
    stream=TLSStream(FakeTLS());errors=[]
    def exercise(operation):
        try:
            for _ in range(20):operation()
        except BaseException as error:errors.append(error)
    threads=[threading.Thread(target=exercise,args=(lambda:stream.recv(1),)),threading.Thread(target=exercise,args=(lambda:stream.sendall(b'x'),))]
    for thread in threads:thread.start()
    for thread in threads:thread.join(timeout=2)
    assert not errors and not any(thread.is_alive() for thread in threads)
