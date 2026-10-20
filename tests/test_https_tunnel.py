import copy
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch
from core import https_tunnel as https


class HttpsConfigTests(unittest.TestCase):
    def node(self,mode='xhttp'):
        p=https.profile(mode,{'server_name':'tunnel.example.com'})
        return {'node_name':'ldh'+'a'*16,'https':{'profile':p,'uuid':str(uuid.uuid4()),'path':'/private-path','private_key':'A'*43,
                'public_key':'B'*43,'short_id':'a'*16,'outer_port':8443,'probe_local':22501,'probe_remote':22502}}

    def test_validation_and_fail_closed_configuration(self):
        for value in ('127.0.0.1','localhost','x;echo hi','*.example.com','example.com/abc'):
            with self.assertRaises(ValueError):https.domain(value)
        for value in ('relative/file','/tmp/../secret','/tmp/a\nExecStart=/bin/sh'):
            with self.assertRaises(ValueError):https.absolute(value)
        node=self.node();ir,kh=https.configs(node,'192.0.2.1',['443','2053'])
        self.assertFalse(ir['outbounds'][0]['streamSettings']['tlsSettings']['allowInsecure'])
        self.assertEqual(ir['outbounds'][0]['streamSettings']['tlsSettings']['minVersion'],'1.3')
        self.assertNotIn('freedom',[out['protocol'] for out in ir['outbounds']])
        self.assertEqual(kh['outbounds'][0]['protocol'],'blackhole')
        allowed=kh['routing']['rules'][0]
        self.assertEqual(allowed['ip'],['127.0.0.1/32'])
        self.assertEqual(allowed['port'],'443,2053,22502')
        self.assertEqual(ir['inbounds'][-1]['listen'],'127.0.0.1')
        self.assertNotIn('privateKey',json.dumps(ir))
        self.assertIn('DynamicUser=yes',https.service(node))
        self.assertIn('LoadCredential=tls-key:',https.service(node,iran=False))
        self.assertNotIn('LoadCredential=tls-key:',https.service(node,iran=True))

    def test_unverified_modes_are_rejected(self):
        with self.assertRaises(ValueError):https.profile('reality',{'server_name':'cover.example.com'})

    def test_carrier_mss_survives_fragmentation_and_xmux(self):
        for mode in ('xhttp', 'xhttps', 'nova'):
            node = self.node(mode)
            node['transport'] = mode
            iran, kharej = https.configs(node, '192.0.2.1', ['443'])
            self.assertEqual(iran['outbounds'][0]['streamSettings']['sockopt']['tcpMaxSeg'], 1360)
            self.assertEqual(kharej['inbounds'][0]['streamSettings']['sockopt']['tcpMaxSeg'], 1360)
            self.assertFalse(iran['outbounds'][0]['mux']['enabled'])
            if mode == 'nova':
                fragment = next(out for out in iran['outbounds'] if out['tag'] == 'fragment-out')
                self.assertEqual(fragment['streamSettings']['sockopt']['tcpMaxSeg'], 1360)

    def test_cleanup_only_removes_owned_firewall_rules_even_after_abandon(self):
        from unittest.mock import Mock
        node=self.node();marker=node['node_name']
        peer=Mock();peer.execute.return_value=(0,'-A INPUT -p tcp --dport 443 -m comment --comment unrelated -j ACCEPT\n-A INPUT -p tcp --dport 30303 -m comment --comment '+marker+' -j ACCEPT','')
        https.firewall(peer,node,['443'],True,remove=True)
        commands=[call.args[0] for call in peer.execute.call_args_list]
        self.assertEqual(len(commands),2)
        self.assertIn('--dport 30303',commands[1]);self.assertNotIn('unrelated',commands[1]);self.assertNotIn('-F',commands[1])

    def test_bad_input_never_connects(self):
        with patch.object(https,'connect') as connect:
            self.assertFalse(https.create('bad;name',{},[],'xhttp',['443'],{})[0])
            connect.assert_not_called()


class HttpsLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.node=HttpsConfigTests().node()
        self.node.update(ip='192.0.2.1',name='iran',server_name='iran',engine='xray',transport='xhttp',provisioning=False)
        self.kh={'ip':'192.0.2.2','name':'kharej'}
        self.pool={'name':'one','engine':'xray','transport':'xhttp','camouflage':self.node['https']['profile'],
                   'nodes':[self.node],'kharej_server':self.kh,'client_ports':['443']}
        self.data={'pools':{'one':self.pool}}
        for item in (patch.object(https,'get_pools',lambda:copy.deepcopy(self.data['pools'])),
                     patch.object(https,'atomic_update',lambda fn:fn(self.data))):
            item.start();self.addCleanup(item.stop)
        from core.load_balancer import LoadBalancerManager
        item=patch.object(LoadBalancerManager,'check_port_conflicts',return_value=(True,''));item.start();self.addCleanup(item.stop)

    def test_failed_auth_and_incomplete_cleanup_preserve_member(self):
        self.pool['nodes']=[]
        from unittest.mock import Mock
        peers=[Mock(),Mock()]
        with patch.object(https,'connect',side_effect=peers),patch.object(https,'execute',return_value=''), \
             patch.object(https,'write'),patch.object(https,'free_port',side_effect=[8443,22501,22502]), \
             patch.object(https,'test_config'),patch.object(https,'firewall'), \
             patch.object(https,'verify',side_effect=RuntimeError('certificate rejected')), \
             patch.object(https,'clean',side_effect=[None,RuntimeError('host unreachable')]):
            ok,message=https.add('one',{'ip':'192.0.2.1','name':'iran'})
        self.assertFalse(ok)
        self.assertEqual(len(self.pool['nodes']),1)
        self.assertTrue(self.pool['nodes'][0]['provisioning'])
        job=self.pool['node_additions']['192.0.2.1']
        self.assertEqual(job['status'],'failed')
        self.assertNotIn('https',job);self.assertNotIn('uuid',job)
        for peer in peers:peer.close.assert_called_once()

    def test_status_does_not_publish_https_credentials(self):
        from core import web_server
        handler=object.__new__(web_server.LDWebRequestHandler)
        handler.path='/api/status';handler._is_authenticated=lambda:True
        responses=[];handler._send_json=lambda value:responses.append(value)
        with patch.object(web_server,'load_data',return_value=self.data), \
             patch.object(web_server,'get_pools',return_value=self.data['pools']), \
             patch.object(web_server,'get_servers',return_value=[]), \
             patch.object(web_server,'get_dashboard_domain_config',return_value={}), \
             patch.object(web_server,'TelemetryWatchdog') as watchdog:
            watchdog.get_node_telemetry.return_value={}
            watchdog.return_value.is_daemon_running.return_value=False
            watchdog.return_value.get_daemon_pid.return_value=0
            handler.do_GET()
        serialized=json.dumps(responses)
        self.assertNotIn(self.node['https']['uuid'],serialized)
        self.assertNotIn(self.node['https']['path'],serialized)
        self.assertNotIn(self.node['https']['profile']['key'],serialized)
        self.assertEqual(responses[0]['pools'][0]['nodes'][0]['https']['server_name'],'tunnel.example.com')

    def test_restart_does_not_run_backpack_recovery(self):
        from core import transport_change
        self.pool['transport_change']={'status':'changing'}
        with patch.object(transport_change,'load_data',return_value=self.data), \
             patch.object(transport_change,'atomic_update',lambda fn:fn(self.data)), \
             patch.object(transport_change.threading,'Thread') as thread:
            transport_change.recover_changes();thread.assert_not_called()
        self.assertEqual(self.pool['transport_change']['status'],'rollback_failed')


    def test_delete_requires_both_endpoints_before_mutation(self):
        from unittest.mock import Mock
        peer=Mock()
        with patch.object(https,'connect',side_effect=[peer,RuntimeError('offline')]),patch.object(https,'clean') as clean:
            self.assertFalse(https.remove('one','192.0.2.1')[0]);clean.assert_not_called()
        self.assertEqual(len(self.pool['nodes']),1);peer.close.assert_called_once()

    def test_unverified_rollback_stays_locked(self):
        from unittest.mock import Mock
        with patch.object(https,'connect',side_effect=[Mock(),Mock()]),patch.object(https,'test_config'), \
             patch.object(https,'firewall'),patch.object(https,'execute'), \
             patch.object(https,'verify',side_effect=[RuntimeError('new path failed'),RuntimeError('restore failed')]):
            self.assertFalse(https.change_ports('one',['443','2053'])[0])
        self.assertEqual(self.pool['client_ports'],['443'])
        self.assertEqual(self.pool['transport_change']['status'],'rollback_failed')
        with patch.object(https,'connect',side_effect=RuntimeError('offline')):
            self.assertFalse(https.change_ports('one',['443'],recovery=True)[0])
        self.assertEqual(self.pool['transport_change']['status'],'rollback_failed')


def free_port():
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


@unittest.skipUnless(os.environ.get('VX_LB_XRAY_BINARY'),'Set VX_LB_XRAY_BINARY to run actual TLS data tests')
class HttpsNetworkTests(unittest.TestCase):
    def test_xhttp_tls_and_identity_failure(self):self.exercise('xhttp')

    def exercise(self,mode):
        binary=os.environ['VX_LB_XRAY_BINARY'];workers=[];sockets=[];capture=bytearray();stop=threading.Event()
        root=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix='vxlb-https-') as folder:
            folder=Path(folder)
            probe_script=root/'core/https_probe.py'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(folder/'key.pem'),'-out',str(folder/'cert.pem'),
                            '-days','2','-subj','/CN=tunnel.test','-addext','subjectAltName=DNS:tunnel.test'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            p=https.profile(mode,{'server_name':'tunnel.test','certificate':str(folder/'cert.pem'),'key':str(folder/'key.pem'),'binary':binary})
            outer,inner,entry,probe_local,probe_remote=[free_port() for _ in range(5)]
            node={'node_name':'ldh'+'a'*16,'https':{'profile':p,'uuid':str(uuid.uuid4()),'path':'/testing-private-path','outer_port':outer,
                                                 'probe_local':probe_local,'probe_remote':probe_remote}}
            ir,kh=https.configs(node,'127.0.0.1',[str(entry)])
            ir['log']['loglevel']=kh['log']['loglevel']='info'
            kh['inbounds'][0]['listen']='127.0.0.1';kh['inbounds'][0]['port']=inner
            for inbound in ir['inbounds']:inbound['listen']='127.0.0.1'
            # A byte-recording underlay proxy proves payload confidentiality;
            # it is not a TLS terminator and knows no TLS private key.
            listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('127.0.0.1',outer));listener.listen();listener.settimeout(.2);sockets.append(listener)
            def pump(source,target):
                try:
                    while chunk:=source.recv(65536):capture.extend(chunk);target.sendall(chunk)
                except OSError:pass
                finally:
                    try:target.shutdown(socket.SHUT_WR)
                    except OSError:pass
            def accept():
                while not stop.is_set():
                    try:left,_=listener.accept()
                    except socket.timeout:continue
                    except OSError:break
                    try:
                        right=socket.create_connection(('127.0.0.1',inner),timeout=3);right.settimeout(None)
                    except OSError:left.close();continue
                    sockets.extend((left,right))
                    threading.Thread(target=pump,args=(left,right),daemon=True).start()
                    threading.Thread(target=pump,args=(right,left),daemon=True).start()
            threading.Thread(target=accept,daemon=True).start()
            def start(config,name,trust=True):
                path=folder/(name+'.json');path.write_text(json.dumps(config))
                check=subprocess.run([binary,'run','-test','-config',str(path)],capture_output=True,text=True)
                self.assertEqual(check.returncode,0,check.stderr+check.stdout)
                env=dict(os.environ)
                if trust:env['SSL_CERT_FILE']=str(folder/'cert.pem')
                log=open(folder/(name+'.log'),'w+');self.addCleanup(log.close)
                process=subprocess.Popen([binary,'run','-config',str(path)],stdout=log,stderr=log,env=env);workers.append(process)
                return process
            try:
                server=start(kh,'server');client=start(ir,'client');time.sleep(.4)
                echo=subprocess.Popen(['python3',str(root/'core/https_probe.py'),'echo',str(probe_remote)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);workers.append(echo)
                self.assertEqual(echo.stdout.readline().strip(),'READY')
                nonce='CONFIDENTIAL-'+uuid.uuid4().hex
                result=subprocess.run(['python3',str(probe_script),'probe',str(probe_local),nonce],capture_output=True,text=True,timeout=15)
                self.assertEqual(result.returncode,0,result.stderr)
                echo.wait(timeout=3)
                self.assertNotIn(nonce.encode(),capture)
                self.assertIn(b'tunnel.test',capture)
                self.assertEqual(capture[0],22) # TLS Handshake record
                # Keep a healthy backend during negative tests; otherwise a
                # connection failure would say nothing about authentication.
                echo2=subprocess.Popen(['python3',str(root/'core/https_probe.py'),'echo',str(probe_remote)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);workers.append(echo2)
                self.assertEqual(echo2.stdout.readline().strip(),'READY')
                # A valid TLS channel with the wrong application identity must fail.
                client.terminate();client.wait(timeout=3)
                wrong=copy.deepcopy(ir);wrong['outbounds'][0]['settings']['vnext'][0]['users'][0]['id']=str(uuid.uuid4())
                client=start(wrong,'wrong-identity');time.sleep(.2)
                result=subprocess.run(['python3',str(probe_script),'probe',str(probe_local),'bad-identity'],capture_output=True,text=True,timeout=15)
                self.assertNotEqual(result.returncode,0)
                # The same channel must reject an untrusted server certificate.
                client.terminate();client.wait(timeout=3)
                invalid=copy.deepcopy(ir)
                client=start(invalid,'untrusted-peer',trust=False);time.sleep(.2)
                result=subprocess.run(['python3',str(probe_script),'probe',str(probe_local),'bad-cert'],capture_output=True,text=True,timeout=15)
                self.assertNotEqual(result.returncode,0)
                self.assertIsNone(echo2.poll(),'Unauthenticated traffic reached the nonce backend')
                client.terminate();client.wait(timeout=3)
                wrong_name=copy.deepcopy(ir);wrong_name['outbounds'][0]['streamSettings']['tlsSettings']['serverName']='wrong.test'
                client=start(wrong_name,'wrong-hostname');time.sleep(.2)
                result=subprocess.run(['python3',str(probe_script),'probe',str(probe_local),'wrong-name'],capture_output=True,text=True,timeout=15)
                self.assertNotEqual(result.returncode,0);self.assertIsNone(echo2.poll())
                client.terminate();client.wait(timeout=3)
                # Correct credentials cannot turn the server into an open proxy.
                forbidden=free_port()
                denied_backend=subprocess.Popen(['python3',str(root/'core/https_probe.py'),'echo',str(forbidden)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);workers.append(denied_backend)
                self.assertEqual(denied_backend.stdout.readline().strip(),'READY')
                malicious=copy.deepcopy(ir);malicious['inbounds'][-1]['settings']['port']=forbidden
                client=start(malicious,'forbidden-target');time.sleep(.2)
                result=subprocess.run(['python3',str(probe_script),'probe',str(probe_local),'forbidden'],capture_output=True,text=True,timeout=15)
                self.assertNotEqual(result.returncode,0);self.assertIsNone(denied_backend.poll())
                client.terminate();client.wait(timeout=3)
                client=start(ir,'outage-client');time.sleep(.2)
                server.terminate();server.wait(timeout=3)
                result=subprocess.run(['python3',str(probe_script),'probe',str(probe_local),'OUTAGE-PLAINTEXT'],capture_output=True,text=True,timeout=15)
                self.assertNotEqual(result.returncode,0)
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                    udp.settimeout(.7);udp.connect(('127.0.0.1',probe_local));udp.send(b'NO-RAW-FALLBACK')
                    with self.assertRaises(TimeoutError):udp.recv(1024)
                self.assertIsNone(echo2.poll())
                print('PASS: actual '+mode+' TCP+UDP, encrypted wire capture, wrong identity/peer rejection and forbidden-target blocking')
            except Exception:
                for log in folder.glob('*.log'):print(log.name+': '+'\n'.join(line for line in log.read_text().splitlines() if not any(word.lower() in line.lower() for word in ('AuthKey','PrivateKey','PublicKey','SessionId')))[-6000:])
                raise
            finally:
                stop.set()
                for sock in sockets:
                    try:sock.close()
                    except OSError:pass
                for process in workers:
                    if process.poll() is None:process.terminate()
                for process in workers:
                    try:process.wait(timeout=3)
                    except subprocess.TimeoutExpired:process.kill();process.wait()
                    for stream in (process.stdin,process.stdout,process.stderr):
                        if stream:stream.close()

if __name__=='__main__':unittest.main()
