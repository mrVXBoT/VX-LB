import unittest
from unittest.mock import patch
from core.cloudflare import CloudflareManager

class DnsSnapshotTests(unittest.TestCase):
    def test_error_is_not_reported_as_empty_verified_dns(self):
        manager = CloudflareManager('fake', 'fake')
        with patch.object(manager, '_request', return_value={'success': False}):
            self.assertEqual(manager.record_snapshot('edge.example.test'), {'success': False, 'records': []})

    def test_records_are_sanitized_and_query_encoded(self):
        manager = CloudflareManager('fake', 'fake')
        with patch.object(manager, '_request', return_value={'success': True, 'result': [{'content': '192.0.2.1', 'proxied': True, 'id': 'private-record'}]}) as request:
            self.assertEqual(manager.record_snapshot(' EDGE.EXAMPLE.TEST '), {'success': True, 'records': [{'content': '192.0.2.1', 'proxied': True}]})
            request.assert_called_once_with('GET', '?name=edge.example.test&type=A&per_page=100&page=1')

    def test_later_page_failure_does_not_publish_partial_records(self):
        manager = CloudflareManager('fake', 'fake')
        with patch.object(manager, '_request', side_effect=[{'success': True, 'result': [{'content': '192.0.2.1'}], 'result_info': {'total_pages': 2}}, {'success': False}]):
            self.assertEqual(manager.record_snapshot('edge.example.test'), {'success': False, 'records': []})
