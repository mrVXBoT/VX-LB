"""Wire-level DNS guard checks, including the malformed input found in VM."""
import struct
import pytest
from core.slipstream_dns_guard import question, permitted


def query(labels=('mzxw6ytb', 'tunnel', 'example', 'com'), kind=16, extra=b'', ar=0):
    name = b''.join(bytes([len(value)]) + value.encode() for value in labels) + b'\0'
    return struct.pack('!6H', 123, 0x100, 1, 0, 0, ar) + name + struct.pack('!HH', kind, 1) + extra


def test_realistic_txt_question_and_edns0_are_forwardable():
    assert permitted(query(), 'tunnel.example.com')
    opt = b'\0' + struct.pack('!HHIH', 41, 1232, 0, 0)
    assert permitted(query(extra=opt, ar=1), 'tunnel.example.com')


@pytest.mark.parametrize('packet', [b'lab-rate-test', b'', bytes(12), query()+b'garbage',
                                    query(extra=b'\0', ar=1), query()[:-1],
                                    struct.pack('!6H', 1, 0, 1, 0, 0, 0)+b'\xc0\x0c\0\x10\0\x01'])
def test_malformed_dns_never_reaches_upstream_decoder(packet):
    assert not permitted(packet, 'tunnel.example.com')
    with pytest.raises((ValueError, UnicodeError)):
        question(packet)


def test_valid_unrelated_query_is_not_forwarded_as_tunnel_payload():
    assert not permitted(query(kind=1), 'tunnel.example.com')
    assert not permitted(query(labels=('mzxw6ytb', 'other', 'example', 'com')), 'tunnel.example.com')
    assert not permitted(query(labels=('not-valid-base32', 'tunnel', 'example', 'com')), 'tunnel.example.com')
