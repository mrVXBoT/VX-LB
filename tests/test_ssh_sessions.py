import unittest
from unittest.mock import MagicMock,patch
from core.ssh_client import SSHManager
from core.transport_change import check

class SessionTests(unittest.TestCase):
    def setUp(self):
        self.socket_factory = patch('core.ssh_client.socket.socket').start()
        self.addCleanup(patch.stopall)

    def test_connect_enables_keepalive(self):
        client=MagicMock()
        with patch('core.ssh_client.paramiko.SSHClient',return_value=client):
            ssh=SSHManager('192.0.2.1',password='fixture-only')
            self.assertTrue(ssh.connect()[0])
            client.get_transport.return_value.set_keepalive.assert_called_once_with(20)
            import socket
            self.socket_factory.return_value.setsockopt.assert_called_once_with(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1360)
            self.assertIs(client.connect.call_args.kwargs['sock'], self.socket_factory.return_value)

    def test_transient_handshake_is_retried_and_failed_client_closed(self):
        first, second = MagicMock(), MagicMock()
        import paramiko
        first.connect.side_effect = paramiko.SSHException('No existing session')
        with patch('core.ssh_client.paramiko.SSHClient', side_effect=[first, second]), patch('core.ssh_client.time.sleep'):
            ssh = SSHManager('192.0.2.1')
            self.assertTrue(ssh.connect()[0])
        first.close.assert_called_once()
        second.close.assert_not_called()

    def test_rejected_password_is_not_retried(self):
        import paramiko
        client = MagicMock()
        client.connect.side_effect = paramiko.AuthenticationException('bad password')
        with patch('core.ssh_client.paramiko.SSHClient', return_value=client) as factory:
            self.assertFalse(SSHManager('192.0.2.1').connect()[0])
        factory.assert_called_once()
        client.close.assert_called_once()

    def test_inactive_connection_reconnects_before_command(self):
        old=MagicMock();old.get_transport.return_value.is_active.return_value=False
        new=MagicMock();stdout=MagicMock();stderr=MagicMock()
        stdout.read.return_value=b'active';stderr.read.return_value=b'';stdout.channel.recv_exit_status.return_value=0
        new.exec_command.return_value=(MagicMock(),stdout,stderr)
        ssh=SSHManager('192.0.2.1');ssh.client=old
        def reconnect():ssh.client=new;return True,'ok'
        with patch.object(ssh,'connect',side_effect=reconnect):
            self.assertEqual(ssh.execute('systemctl is-active test'),(0,'active',''))
        old.close.assert_called_once()
        old.exec_command.assert_not_called()

    def test_restart_timeout_allows_systemd_stop_deadline(self):
        ssh=MagicMock();ssh.execute.return_value=(0,'','')
        check(ssh,'systemctl restart backpack-test.service')
        ssh.execute.assert_called_once_with('systemctl restart backpack-test.service',timeout=100)

    def test_same_host_uses_authenticated_loopback_ssh(self):
        from core import transport_change as change
        client=MagicMock();client.connect.return_value=(True,'ok')
        with patch.object(change.subprocess,'check_output',return_value=b'[{"addr_info":[{"local":"95.211.93.38"}]}]'),patch.object(change,'SSHManager',return_value=client) as factory:
            change.connect({'ip':'95.211.93.38','port':2255,'username':'root','password':'fixture-only'})
            factory.assert_called_once_with('127.0.0.1',2255,'root','fixture-only')

    def test_execute_closes_channel_and_retries_transient_failure(self):
        ssh=SSHManager('192.0.2.1')
        client=MagicMock()
        channel1=MagicMock()
        client.exec_command.side_effect=[Exception('channel open failed'),(MagicMock(),MagicMock(channel=channel1,read=MagicMock(return_value=b'ok')),MagicMock(read=MagicMock(return_value=b'')))]
        channel1.recv_exit_status.return_value=0
        def fake_connect():
            ssh.client=client
            return True,'ok'
        with patch.object(ssh,'connect',side_effect=fake_connect):
            code,out,_=ssh.execute('echo test')
        self.assertEqual(code,0)
        self.assertEqual(out,'ok')
        channel1.close.assert_called_once()

