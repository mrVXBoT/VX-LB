import time
import unittest
from unittest.mock import patch
from core.watchdog import TelemetryWatchdog

class WatchdogFreshnessTests(unittest.TestCase):
    node = {'ip':'192.0.2.1'}

    def analyze(self, logs='', sockets='', previous=None, connected=True):
        watchdog = TelemetryWatchdog()
        with patch('core.watchdog.SSHManager') as manager, \
             patch.object(watchdog,'get_node_telemetry',return_value=previous or {}), \
             patch.object(watchdog,'save_node_telemetry') as save:
            manager.return_value.connect.return_value = (connected,'test')
            manager.return_value.execute.side_effect = [(0,logs,''),(0,sockets,'')]
            result = watchdog.analyze_node_health('pool',self.node,['8443'])
            self.assertEqual(save.call_args.args[2],result[0])
            return result

    def test_idle_does_not_retain_healthy_or_recursive_reason(self):
        old = {'status':'HEALTHY','reason':'Retaining active status: '*500}
        first = self.analyze(previous=old)
        second = self.analyze(previous={'status':first[0],'reason':first[1]})
        self.assertEqual(first[0],'IDLE')
        self.assertEqual(second[0],'IDLE')
        self.assertLess(len(first[1]),200)
        self.assertNotIn('Retaining active',second[1])

    def test_unreachable_node_does_not_retain_health(self):
        self.assertEqual(self.analyze(previous={'status':'HEALTHY'},connected=False)[0],'DOWN')

    def test_remote_timezone_keeps_fresh_stalls_in_window(self):
        stamp = '2026-10-12 12:00:00'
        local_parse = time.mktime(time.strptime(stamp,'%Y-%m-%d %H:%M:%S'))
        epoch = int(local_parse+12600)
        logs = '\n'.join(f'[{stamp}] SESSION_CLOSED_STALLED | port=8443 | client=192.0.2.{i}:1000 | bytes_ack=0' for i in range(10,13))
        logs += f'\nBP_CLOCK {epoch} {stamp}'
        with patch('core.watchdog.time.time',return_value=epoch+20):
            result = self.analyze(logs=logs,previous={'status':'HEALTHY'})
        self.assertEqual(result[0],'DEGRADED')
        self.assertEqual(result[3]['8443']['failure_checks'],1)

    def test_one_way_socket_is_not_bidirectional_health(self):
        socket = 'ESTAB 0 0 192.0.2.1:8443 192.0.2.20:1000\n cubic bytes_received:50000 bytes_acked:0'
        self.assertEqual(self.analyze(sockets=socket)[0],'IDLE')

    def test_stalled_socket_overrides_old_healthy_totals(self):
        socket = 'ESTAB 0 20000 192.0.2.1:8443 192.0.2.20:1000\n cubic bytes_received:50000 bytes_acked:50000 backoff:4'
        self.assertEqual(self.analyze(sockets=socket)[0],'DEGRADED')

    def test_legacy_false_filter_does_not_enter_cooldown(self):
        result = self.analyze(previous={'status':'FILTERED','status_since':time.strftime('%Y-%m-%d %H:%M:%S')})
        self.assertEqual(result[0],'IDLE')
