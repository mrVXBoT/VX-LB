import unittest
from unittest.mock import MagicMock,patch
from core.tunnel_readiness import control_connected
from core.tunnel import setup_tunnel_node
from core.watchdog import TelemetryWatchdog

class ReadinessTests(unittest.TestCase):
    def state(self,events,active=True,sockets=''):
        ssh=MagicMock()
        ssh.execute.side_effect=[
            (0,f'ActiveState={"active" if active else "inactive"}\nMainPID=123\nExecMainStartTimestamp=Mon 2026-10-12 17:00:00 UTC\n',''),
            (0,events,''),
            (0,sockets,''),
        ]
        return control_connected(ssh,'backpack-test.service')
    def test_active_process_without_control_is_not_ready(self):
        self.assertFalse(self.state('server started successfully'))
        self.assertFalse(self.state('failed to receive control channel response: timeout'))
    def test_missing_control_log_can_use_the_live_socket(self):
        self.assertTrue(self.state('server started successfully', sockets='ESTAB 0 0 192.0.2.1:22414 192.0.2.2:40000 users:(("backpack",pid=123,fd=5))'))
        self.assertFalse(self.state('control channel established\ncontrol channel closed', sockets='ESTAB 0 0 192.0.2.1:22414 192.0.2.2:40000 users:(("backpack",pid=123,fd=5))'))
    def test_latest_current_process_event_wins(self):
        self.assertFalse(self.state('control channel established\ncontrol channel closed'))
        self.assertTrue(self.state('failed to receive control channel response\ncontrol channel established'))
    def test_failed_deployment_probe_is_not_success_and_cleans_both_sides(self):
        ir,kh=MagicMock(),MagicMock()
        for ssh in (ir,kh):ssh.write_file.return_value=True;ssh.execute.return_value=(0,'','')
        with patch('core.transport_change.install_and_verify',return_value=False),patch('core.tunnel.stop_and_remove_tunnel') as cleanup:
            ok,_=setup_tunnel_node(ir,kh,'test','tcp',22414,['2255'],'test-token')
            self.assertFalse(ok)
            self.assertEqual(cleanup.call_count,2)
    def test_kharej_write_failure_removes_the_iran_service(self):
        ir,kh=MagicMock(),MagicMock()
        ir.write_file.return_value=True
        ir.execute.return_value=(0,'','')
        kh.write_file.return_value=False
        with patch('core.tunnel.stop_and_remove_tunnel') as cleanup:
            ok,message=setup_tunnel_node(ir,kh,'test','tcp',22414,['2255'],'test-token')
        self.assertFalse(ok)
        self.assertIn('Kharej',message)
        self.assertEqual(cleanup.call_count,2)
    def test_quiet_tunnel_with_a_live_control_channel_stays_routable(self):
        w=TelemetryWatchdog()
        with patch('core.watchdog.SSHManager') as ssh,patch('core.watchdog.control_connected',return_value=True),patch.object(w,'get_node_telemetry',return_value={}),patch.object(w,'save_node_telemetry'):
            ssh.return_value.connect.return_value=(True,'')
            ssh.return_value.execute.side_effect=[(0,'BP_CLOCK 1800000000 2027-01-15 00:00:00\n',''),(0,'','')]
            result=w.analyze_node_health('pool',{'ip':'192.0.2.1','node_name':'test'},['2255'])
        self.assertEqual(result[0],'READY')
    def test_disconnected_tunnel_never_becomes_idle(self):
        w=TelemetryWatchdog()
        with patch('core.watchdog.SSHManager') as ssh,patch('core.watchdog.control_connected',return_value=False),patch.object(w,'save_node_telemetry'):
            ssh.return_value.connect.return_value=(True,'')
            result=w.analyze_node_health('pool',{'ip':'192.0.2.1','node_name':'test'},['2255'])
        self.assertEqual(result[0],'DOWN')
    def test_port_edits_preserve_repaired_node_transport(self):
        from core.load_balancer import LoadBalancerManager
        for action in ('add','remove'):
            pool={'name':'pool','transport':'pck','client_ports':['2255','444'],
                  'nodes':[{'node_name':'test','server_name':'test','ip':'192.0.2.1',
                            'tunnel_port':22414,'token':'dummy','transport':'tcp'}]}
            with patch('core.load_balancer.get_pools',return_value={'pool':pool}),patch('core.load_balancer.SSHManager') as manager,patch('core.load_balancer.save_pool'),patch('core.load_balancer.time.sleep'),patch.object(LoadBalancerManager,'check_port_conflicts',return_value=(True,'')):
                manager.return_value.connect.return_value=(True,'')
                manager.return_value.execute.return_value=(0,'active','')
                manager.return_value.write_file.return_value=True
                manager.from_server.return_value=manager.return_value
                if action=='add': ok,_=LoadBalancerManager.add_client_ports('pool',['2256'])
                else: ok,_=LoadBalancerManager.remove_client_port('pool','444')
                self.assertTrue(ok)
                config=manager.return_value.write_file.call_args.args[1]
                self.assertIn('transport = "tcp"',config)
