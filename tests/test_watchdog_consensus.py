import time
import unittest
from unittest.mock import patch
from core.watchdog import TelemetryWatchdog

class ConsensusTests(unittest.TestCase):
    def evaluate(self, events, previous=None, ports=('8443',), sockets='', epoch=1800000000):
        stamp=time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(epoch))
        logs='\n'.join(f'[{stamp}] {event} | port={port} | client={peer} | {detail}' for event,port,peer,detail in events)
        logs+=f'\nBP_CLOCK {epoch} {stamp}'
        w=TelemetryWatchdog()
        with patch('core.watchdog.time.time',return_value=epoch), patch('core.watchdog.SSHManager') as ssh, patch.object(w,'get_node_telemetry',return_value={'port_details':previous or {}}), patch.object(w,'save_node_telemetry'):
            ssh.return_value.connect.return_value=(True,'')
            ssh.return_value.execute.side_effect=[(0,logs,''),(0,sockets,'')]
            return w.analyze_node_health('pool',{'ip':'192.0.2.1'},list(ports))
    def failures(self, count=3, port='8443'):
        return [('SESSION_CLOSED_STALLED',port,f'192.0.2.{i+10}:1000','bytes_ack=0') for i in range(count)]
    def test_hundreds_of_lines_from_two_clients_never_filter(self):
        r=self.evaluate(self.failures(2)*200)
        self.assertEqual(r[0],'DEGRADED')
        self.assertEqual(r[3]['8443']['independent_clients'],2)
        self.assertIn('2 unique',r[3]['8443']['reason'])
    def test_new_independent_failures_in_three_rounds_confirm(self):
        prev={}
        for i in range(3):
            r=self.evaluate(self.failures(),prev,epoch=1800000000+i*30)
            prev=r[3]
            self.assertEqual(r[0],'FILTERED' if i==2 else 'DEGRADED')
    def test_same_closed_failures_do_not_advance_confirmation(self):
        r=self.evaluate(self.failures())
        # Previous evidence has the same timestamp as the reread log.
        prev=r[3]; prev['8443']['checked_epoch']-=30
        r=self.evaluate(self.failures(),prev)
        self.assertEqual(r[3]['8443']['failure_checks'],1)
    def test_success_overrides_earlier_failure_and_resets_streak(self):
        events=self.failures()+[('USER_SESSION_ACTIVE','8443','192.0.2.10:1000','bytes_rx=9000 bytes_ack=9000')]
        r=self.evaluate(events)
        self.assertEqual(r[0],'DEGRADED')
        self.assertEqual(r[3]['8443']['failure_checks'],0)
        self.assertIsNotNone(r[3]['8443']['last_success_epoch'])
    def test_failed_port_does_not_filter_entire_node(self):
        prev={}
        for i in range(3):
            r=self.evaluate(self.failures(),prev,ports=('8443','443'),epoch=1800000000+i*30);prev=r[3]
        self.assertEqual(r[3]['8443']['status'],'FILTERED')
        self.assertEqual(r[0],'DEGRADED')
    def test_live_counters_must_progress_between_checks(self):
        sock='ESTAB 0 0 192.0.2.1:8443 192.0.2.20:1000\n cubic bytes_received:9000 bytes_acked:9000'
        r=self.evaluate([],sockets=sock)
        self.assertEqual(r[0],'IDLE')
        r=self.evaluate([],r[3],sockets=sock.replace('9000','10000'),epoch=1800000030)
        self.assertEqual(r[0],'HEALTHY')
    def test_stall_and_close_are_one_connection(self):
        events=[('TRANSPORT_STALL_DETECTED','8443','192.0.2.10:1000',''),('SESSION_CLOSED_STALLED','8443','192.0.2.10:1000','')]
        r=self.evaluate(events)
        self.assertIn('1 unique connection',r[3]['8443']['reason'])
    def test_real_reader_preserves_success_beyond_400_lines_and_rotation(self):
        import tempfile, pathlib, shlex, subprocess
        now=int(time.time())
        stamp=time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(now))
        with tempfile.TemporaryDirectory() as directory:
            base=pathlib.Path(directory)/'connections.log'
            pathlib.Path(str(base)+'.1').write_text(f'[{stamp}] USER_SESSION_ACTIVE | port=8443 | client=192.0.2.30:1000 | bytes_rx=10000 bytes_ack=10000\n')
            base.write_text('\n'.join(f'[{stamp}] SESSION_CLOSED_STALLED | port=8443 | client=192.0.2.10:1000 | bytes_ack=0' for _ in range(600)))
            def execute(command):
                if command.startswith('ss '): return 0,'',''
                script=shlex.split(command)[2].replace('/var/log/vxlb-user-connections.log',str(base))
                result=subprocess.run(['python3','-c',script],capture_output=True,text=True,check=True)
                return 0,result.stdout,result.stderr
            w=TelemetryWatchdog()
            with patch('core.watchdog.SSHManager') as ssh,patch.object(w,'get_node_telemetry',return_value={}),patch.object(w,'save_node_telemetry'):
                ssh.return_value.connect.return_value=(True,'')
                ssh.return_value.execute.side_effect=execute
                result=w.analyze_node_health('pool',{'ip':'192.0.2.1'},['8443'])
            self.assertIsNotNone(result[3]['8443']['last_success_epoch'])
            self.assertEqual(result[3]['8443']['failure_checks'],0)
