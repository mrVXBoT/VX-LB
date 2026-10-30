import unittest
from unittest.mock import patch

from core.link_latency import extract, positive_ms, stamp
from core.watchdog import TelemetryWatchdog


class LatencyHelperTests(unittest.TestCase):
    def test_extract_uses_the_smallest_positive_sample(self):
        self.assertIsNone(positive_ms(True))
        self.assertIsNone(positive_ms(0))
        self.assertIsNone(extract({'link': {'latency_ms': -1}, '443': {'status': 'DOWN'}}))
        self.assertEqual(extract({'link': {'latency_ms': 8}, '443': {'status': 'HEALTHY', 'latency_ms': 2.25}}), 2.2)

    def test_stamp_fills_only_port_details_that_lack_a_sample(self):
        details = {'443': {'status': 'HEALTHY', 'latency_ms': 4}, '80': {'status': 'DEGRADED'}}
        stamp(details, 9)
        self.assertEqual(details['443']['latency_ms'], 4)
        self.assertEqual(details['80']['latency_ms'], 9.0)
        stamp(details, None)
        self.assertEqual(details['80']['latency_ms'], 9.0)

    def test_watchdog_saves_the_tunnel_sample_on_the_node(self):
        captured = {}

        def atomic_update(fn):
            data = {}
            fn(data)
            captured.update(data)

        with patch('core.watchdog.atomic_update', atomic_update):
            TelemetryWatchdog.save_node_telemetry(
                'pool', '192.0.2.1', 'HEALTHY', 'ok', [],
                {'443': {'status': 'HEALTHY', 'latency_ms': 2.2}, 'link': {'latency_ms': 9}},
            )
        self.assertEqual(captured['node_telemetry']['pool:192.0.2.1']['latency_ms'], 2.2)

    def test_backpack_socket_rtt_reaches_the_port(self):
        stamp = '2026-10-30 12:00:00'
        import time
        epoch = int(time.mktime(time.strptime(stamp, '%Y-%m-%d %H:%M:%S')))
        logs = f'BP_CLOCK {epoch} {stamp}'
        sockets = 'ESTAB 0 0 192.0.2.1:8443 192.0.2.20:1000\n cubic rtt:2.5/1 bytes_received:100 bytes_acked:100'
        watchdog = TelemetryWatchdog()
        with patch('core.watchdog.time.time', return_value=epoch + 5), \
             patch('core.watchdog.SSHManager') as ssh, \
             patch('core.watchdog.load_data', return_value={'pools': {}}), \
             patch.object(watchdog, 'get_node_telemetry', return_value={}), \
             patch.object(watchdog, 'save_node_telemetry'):
            ssh.return_value.connect.return_value = (True, '')
            ssh.return_value.execute.side_effect = [(0, logs, ''), (0, sockets, '')]
            result = watchdog.analyze_node_health('pool', {'ip': '192.0.2.1'}, ['8443'])
        self.assertEqual(result[3]['8443']['latency_ms'], 2.5)


if __name__ == '__main__':
    unittest.main()
