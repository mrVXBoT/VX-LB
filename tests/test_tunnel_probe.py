import unittest
from unittest.mock import patch, MagicMock
from core import transport_change as change
from core.tunnel_probe import add_probe_route, TunnelProbe

class ProbeTests(unittest.TestCase):
    def test_http_profiles_use_managed_connect_not_backpack_configs(self):
        from core.load_balancer import LoadBalancerManager
        from core.tunnel import build_iran_config, build_kharej_config
        with patch('core.http_transport.create', return_value=(True,'managed',{})) as create, patch('core.load_balancer.SSHManager') as ssh:
            for transport in ('http','https'):
                self.assertTrue(LoadBalancerManager.create_pool('qa-http',{'ip':'192.0.2.1'},[{'ip':'192.0.2.2'}],transport,['443'])[0])
                self.assertEqual(create.call_args.kwargs['transport'],transport)
                with self.assertRaises(ValueError):build_iran_config(22000,transport,'token',['443'])
                with self.assertRaises(ValueError):build_kharej_config('192.0.2.2',22000,transport,'token')
            ssh.assert_not_called()

    def test_stream_configs_clamp_mss_on_both_sides_of_a_blackholed_mtu_path(self):
        import tomllib
        from core.tunnel import build_iran_config, build_kharej_config
        for transport in ('tcp', 'stealth', 'wss', 'ws'):
            server = tomllib.loads(build_iran_config(22000, transport, 'test-token', ['443']))
            client = tomllib.loads(build_kharej_config('192.0.2.1', 22000, transport, 'test-token'))
            self.assertEqual(server['server']['mss'], 1360)
            self.assertEqual(client['client']['mss'], 1360)

    def test_loopback_mapping_preserves_existing_routes(self):
        config='[server]\ntransport="tcp"\nports = ["443", "2255=127.0.0.1:22"]\ntoken="unchanged"\n'
        result=add_probe_route(config,32100,32200)
        self.assertIn('"127.0.0.1:32100=127.0.0.1:32200"',result)
        self.assertIn('"2255=127.0.0.1:22"',result)
        self.assertIn('token="unchanged"',result)
        with self.assertRaises(RuntimeError):add_probe_route('transport="tcp"',32100,32200)

    def test_nonce_probe_does_not_depend_on_user_connections(self):
        ssh=MagicMock();ssh.execute.return_value=(0,'','')
        probe=TunnelProbe(ssh,MagicMock());probe.listen_port=32100
        self.assertTrue(probe.verify())
        command=ssh.execute.call_args.args[0]
        self.assertIn('LD-BP-PROBE:',command)
        self.assertIn('127.0.0.1',command)

    def test_wrong_response_is_not_success(self):
        ssh=MagicMock();ssh.execute.return_value=(2,'','')
        probe=TunnelProbe(ssh,MagicMock());probe.listen_port=32100
        with patch.object(change.time,'monotonic',side_effect=[0,0,50]),patch.object(change.time,'sleep'):
            self.assertFalse(probe.verify())

    def test_probe_route_is_removed_after_failure(self):
        probe=MagicMock();probe.listen_port=32100;probe.backend_port=32200;probe.verify.return_value=False
        context=MagicMock();context.__enter__.return_value=probe
        contents=['[server]\nports=["443"]\ntransport="tcp"','[client]\ntransport="tcp"']
        with patch.object(change,'TunnelProbe',return_value=context),patch.object(change,'write_and_restart') as write,patch.object(change,'verify_control',return_value=True):
            self.assertFalse(change.install_and_verify('ir','kh','unit','path',contents))
            self.assertEqual(write.call_args.args[-1],contents)
            self.assertIn('127.0.0.1:32100',write.call_args_list[1].args[-1][0])

    def test_control_channel_requires_current_process_success(self):
        def command(ssh,cmd):
            if 'MainPID' in cmd:return '123'
            if 'ExecMainStartTimestamp' in cmd:return 'Sun 2026-10-11 21:00:00 UTC'
            self.assertIn('_PID=123',cmd)
            self.assertIn('--since',cmd)
            return 'control channel established successfully\nfailed to receive control channel response: timeout'
        ssh=MagicMock();ssh.execute.return_value=(0,'control channel established successfully\nfailed to receive control channel response: timeout','')
        with patch.object(change,'active',return_value=True),patch.object(change,'check',side_effect=command):
            self.assertFalse(change.verify_control(ssh,ssh,'unit',timeout=0))

    def test_restore_attempts_both_endpoints_if_first_fails(self):
        with patch.object(change,'apply_file',side_effect=[RuntimeError('offline'),None]) as apply,patch.object(change,'check'):
            with self.assertRaises(RuntimeError):change.write_and_restart('ir','kh','unit','path',['old-ir','old-kh'])
            self.assertEqual(apply.call_count,2)

    def test_real_probe_requires_full_multi_packet_round_trip(self):
        import socket, threading, subprocess
        for corrupt in (False, True):
            listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
            received=[]
            def echo():
                with listener.accept()[0] as connection:
                    connection.settimeout(3);data=b''
                    while len(data)<65537:
                        chunk=connection.recv(65537-len(data))
                        if not chunk:break
                        data+=chunk
                    received.append(len(data))
                    response=b'LD-BP-PROBE:'+data
                    if corrupt:response=response[:-1]+b'!'
                    connection.sendall(response)
            thread=threading.Thread(target=echo,daemon=True);thread.start()
            ssh=MagicMock()
            def execute(command,timeout):
                result=subprocess.run(command,shell=True,capture_output=True,timeout=timeout)
                return result.returncode,result.stdout.decode(),result.stderr.decode()
            ssh.execute.side_effect=execute
            probe=TunnelProbe(ssh,MagicMock());probe.listen_port=listener.getsockname()[1]
            try:
                with patch('core.tunnel_probe.time.monotonic',side_effect=[0,0,99]),patch('core.tunnel_probe.time.sleep'):
                    self.assertEqual(probe.verify(timeout=1),not corrupt)
                thread.join(3)
                self.assertEqual(received,[65537])
            finally:listener.close()

    def test_control_and_data_failures_have_distinct_diagnostics(self):
        contents=['[server]\nports=["443"]','[client]']
        for control_ok in (False,True):
            diagnostics=[];probe=MagicMock();probe.listen_port=32100;probe.backend_port=32200;probe.verify.return_value=False
            context=MagicMock();context.__enter__.return_value=probe
            with patch.object(change,'TunnelProbe',return_value=context),patch.object(change,'write_and_restart'),patch.object(change,'verify_control',return_value=control_ok):
                self.assertFalse(change.install_and_verify('ir','kh','unit','path',contents,diagnostics=diagnostics))
            self.assertEqual(len(diagnostics),1)
            self.assertIn('۶۴ کیلوبایت' if control_ok else 'برقرار نشد',diagnostics[0])
