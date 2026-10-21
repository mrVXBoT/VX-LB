"""Exercise profile creation through HTTP and the real Cloudflare URL builder."""
import io
import json
import threading
import time
from http.client import HTTPConnection
from urllib.parse import parse_qs, urlparse

import pytest

from core.cloudflare import CloudflareManager
from core import web_server as web


@pytest.fixture
def provider(monkeypatch):
    calls = []
    state = {'verify_ok': True, 'fail_page': None}

    def urlopen(request, timeout):
        parsed = urlparse(request.full_url)
        calls.append(request)
        assert request.get_method() == 'GET'
        if parsed.path == '/client/v4/user/tokens/verify':
            payload = {'success': state['verify_ok'], 'errors': [{'message': 'Invalid token'}]}
        elif parsed.path == '/client/v4/zones':
            page = int(parse_qs(parsed.query)['page'][0])
            payload = {'success': page != state['fail_page'],
                       'result': [{'id': f'zone-{page}', 'name': f'example{page}.test'}],
                       'result_info': {'total_pages': 2, 'total_count': 2},
                       'errors': [{'message': 'Zone discovery unavailable'}]}
        else:
            payload = {'success': False, 'errors': [{'message': 'No route for that URI'}]}
        return io.BytesIO(json.dumps(payload).encode())

    monkeypatch.setattr('core.cloudflare.urllib.request.urlopen', urlopen)
    return calls, state


@pytest.mark.parametrize('zone_id', [None, 'existing-zone'])
def test_zone_discovery_uses_zones_endpoint_for_every_page(provider, zone_id):
    calls, _ = provider
    result = CloudflareManager('fixture-only-token', zone_id).list_zones(name='EXAMPLE.TEST', status='active')
    assert result['success'], result
    assert len(result['zones']) == 2
    assert [parse_qs(urlparse(c.full_url).query)['page'] for c in calls] == [['1'], ['2']]
    assert all(urlparse(c.full_url).path == '/client/v4/zones' for c in calls)
    assert all(parse_qs(urlparse(c.full_url).query)['name'] == ['example.test'] for c in calls)


@pytest.fixture
def profile_api(monkeypatch, provider):
    profiles = {}
    monkeypatch.setattr(web, 'save_cf_profile', lambda pid, value: profiles.update({pid: value}))
    monkeypatch.setattr(web, 'get_cf_profile', profiles.get)
    monkeypatch.setattr(web, 'cf_audit', lambda *args, **kwargs: None)
    bearer = 'profile-api-test-only'
    web.AUTH_TOKENS[bearer] = time.time() + 60
    server = web.ThreadedHTTPServer(('127.0.0.1', 0), web.LDWebRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def create(auth=True):
        connection = HTTPConnection('127.0.0.1', server.server_port, timeout=10)
        headers = {'Content-Type': 'application/json'}
        if auth:
            headers['Authorization'] = 'Bearer ' + bearer
        connection.request('POST', '/api/cloudflare/profiles', json.dumps({
            'action': 'create', 'label': 'My DNS', 'token': 'fixture-only-token'
        }), headers)
        response = connection.getresponse()
        result = response.status, json.loads(response.read())
        connection.close()
        return result

    yield create, profiles
    server.shutdown()
    server.server_close()
    thread.join(timeout=3)
    web.AUTH_TOKENS.pop(bearer, None)


def test_create_profile_discovers_zones_and_does_not_return_token(profile_api):
    create, profiles = profile_api
    status, response = create()
    assert status == 201, response
    assert len(response['zones']) == 2
    assert 'fixture-only-token' not in json.dumps(response)
    assert profiles[response['profile']['id']]['token'] == 'fixture-only-token'


def test_failed_discovery_does_not_save_partial_profile(profile_api, provider):
    _, state = provider
    state['fail_page'] = 2
    create, profiles = profile_api
    status, response = create()
    assert status == 502, response
    assert not profiles


def test_invalid_token_does_not_discover_zones_or_save_profile(profile_api, provider):
    calls, state = provider
    state['verify_ok'] = False
    create, profiles = profile_api
    assert create()[0] == 400
    assert len(calls) == 1
    assert not profiles


def test_unauthenticated_profile_creation_does_not_contact_provider(profile_api, provider):
    calls, _ = provider
    create, profiles = profile_api
    assert create(auth=False)[0] == 401
    assert not calls
    assert not profiles
