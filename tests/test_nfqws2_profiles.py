"""Input boundaries and optional real pinned-binary argument verification."""
import os
import hashlib
from pathlib import Path
import subprocess
import pytest
from core.nfqws2_profiles import build,MODES,COMPONENT_SHA256


def test_profiles_require_their_actual_carriers_and_inbound_capture():
    profiles={mode:build(mode,45101,443,'/etc/ldbp/spoof/test') for mode in MODES}
    assert profiles['split-tls'].carrier=='tls_records'
    assert profiles['l7-header-mutation'].carrier=='http_connect'
    assert profiles['tcp-state-desync'].incoming_queue
    assert profiles['hop-ttl-injection'].incoming_queue
    assert not profiles['fake-sni'].incoming_queue
    assert len({p.arguments for p in profiles.values()})==5
    oob=profiles['tcp-state-desync'].arguments
    assert '--filter-l7=tls' not in oob
    assert oob.index('--lua-desync=oob:urp=2')<oob.index('--payload=tls_client_hello')


@pytest.mark.parametrize('changes',[{'mode':'hyperion-x'},{'queue':0},{'queue':True},{'carrier_port':'443 --debug=1'},{'directory':'/etc/../root'},{'fake_sni':'a:repeats=1000'},{'fake_sni':'a\nexample.com'},{'ttl_delta':16}])
def test_invalid_inputs_cannot_become_packet_engine_options(changes):
    values=dict(mode='fake-sni',queue=45101,carrier_port=443,directory='/etc/ldbp/spoof/test')
    values.update(changes)
    with pytest.raises(ValueError):build(**values)


@pytest.mark.parametrize('mode',sorted(MODES))
def test_pinned_engine_accepts_profile_arguments_without_opening_queue(mode):
    base=os.environ.get('LDBP_NFQWS2_QA_BASE')
    if not base:pytest.skip('Set explicit pinned-binary QA directory for engine validation')
    for name,expected in COMPONENT_SHA256.items():
        assert hashlib.sha256((Path(base)/name).read_bytes()).hexdigest()==expected
    binary=Path(base)/'nfqws2'
    args=build(mode,45101,443,base).arguments
    result=subprocess.run([str(binary),'--dry-run',*args],capture_output=True,text=True,timeout=10)
    assert result.returncode==0,result.stdout+result.stderr
    assert 'command line parameters verified' in result.stdout
