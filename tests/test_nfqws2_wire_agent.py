"""Packet evidence distinguishes actual mechanisms from a working carrier."""
import socket
import struct
import pytest
from core.nfqws2_wire_agent import Observer,hello_names
from core.tls_record_carrier import split_hello


def config(mode):return dict(id='a'*32,profile=mode,local='192.0.2.1',peer='192.0.2.2',carrier_port=443,fake_sni='example.com')


def hello(name=b'example.com'):
    host=b'\0'+len(name).to_bytes(2,'big')+name
    extension=len(host).to_bytes(2,'big')+host
    extensions=b'\0\0'+len(extension).to_bytes(2,'big')+extension
    body=b'\x03\x03'+b'r'*32+b'\0'+b'\0\x02\x13\x01'+b'\x01\0'+len(extensions).to_bytes(2,'big')+extensions
    handshake=b'\x01'+len(body).to_bytes(3,'big')+body
    return b'\x16\x03\x01'+len(handshake).to_bytes(2,'big')+handshake


def frame(payload=b'',seq=1001,flags=24,ttl=64,md5=False,source='192.0.2.1',urgent=0):
    options=b'\x13\x12'+b'x'*16+b'\x01\x01' if md5 else b''
    tcp=struct.pack('!HHIIBBHHH',55000,443,seq%(1<<32),0,((20+len(options))//4)<<4,flags,1024,0,urgent)+options+payload
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),1,0x4000,ttl,6,0,socket.inet_aton(source),socket.inet_aton('192.0.2.2'))
    return b'\0'*12+b'\x08\x00'+ip+tcp


def observer(mode):
    result=Observer(config(mode));result.feed(frame(seq=1000,flags=2));return result


def test_fake_requires_real_sni_extension_and_md5_option():
    value=observer('fake-sni')
    value.feed(frame(hello(),md5=False));assert not value.result()['passed']
    value.feed(frame(hello(b'other.example')+b'example.com',md5=True));assert not value.result()['passed']
    value.feed(frame(hello(),md5=True));assert value.result()['passed']
    assert hello_names(hello())=={b'example.com'}


def test_ttl_requires_configured_sni_and_reduced_bounded_ttl():
    value=observer('hop-ttl-injection');value.feed(frame(hello(),ttl=64));assert not value.result()['passed']
    value.feed(frame(hello(b'other.example'),ttl=6));assert not value.result()['passed']
    value.feed(frame(hello(),ttl=6));assert value.result()['passed']


def test_state_profile_requires_both_urgent_data_and_out_of_window_rst():
    value=observer('tcp-state-desync');value.feed(frame(hello(),flags=56,urgent=3))
    value.feed(frame(seq=2000,flags=4));assert not value.result()['passed']
    value.feed(frame(seq=1001-10000,flags=4));assert value.result()['passed']


def test_split_accepts_the_in_order_two_byte_record_seen_on_the_wire():
    source=hello()
    whole=observer('split-tls');whole.feed(frame(source))
    assert not whole.result()['passed']
    data=split_hello(source[:5],source[5:])
    value=observer('split-tls');value.feed(frame(data))
    result=value.result()
    assert result['passed'] and result['observations']['tcp_reordered'] is False
    assert result['observations']['client_hello_records'][0]==2


def test_http_header_name_must_actually_change_and_authorization_is_not_reported():
    value=observer('l7-header-mutation')
    prefix=b'CONNECT link-'+b'a'*32+b':443 HTTP/1.1\r\n'
    value.feed(frame(prefix+b'Host: link\r\n\r\n'));assert not value.result()['passed']
    fresh=observer('l7-header-mutation');fresh.feed(frame(prefix+b'hOsT: link\r\nProxy-Authorization: secret\r\n\r\n'))
    result=fresh.result();assert result['passed']
    assert 'secret' not in repr(result) and 'Proxy-Authorization' not in repr(result)


def test_unrelated_source_or_existing_flow_cannot_prove_profile():
    value=Observer(config('fake-sni'))
    value.feed(frame(hello(),md5=True));assert not value.result()['passed']
    value.feed(frame(seq=1000,flags=2,source='192.0.2.9'))
    value.feed(frame(hello(),md5=True,source='192.0.2.9'));assert not value.result()['passed']
