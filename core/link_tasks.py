"""Durable admission for explicit selected-pair standalone link deployment."""
import threading
import ipaddress
import time
import uuid

from core.storage import load_data, atomic_update
from core.transport_change import mutation_lock, busy
from core.pool_tasks import worker_job
from core.private_link_manager import PrivateLinkManager
from core import private_link_runtime


def update(identity, **fields):
    def save(data):
        data['link_tasks'][identity].update(fields, updated_at=time.time())
    atomic_update(save)


def start_matrix(pairs, port=51820, mtu=1400):
    with mutation_lock():
        data = load_data()
        if busy(data):
            return False, 'عملیات دیگری در حال اجراست'
        try:
            if not isinstance(pairs, list) or not 1 <= len(pairs) <= 50:
                raise ValueError('یک تا ۵۰ زوج مشخص انتخاب کنید')
            if any(not isinstance(pair, (list, tuple)) or len(pair) != 2 or not all(isinstance(ip, str) for ip in pair) for pair in pairs):
                raise ValueError('هر زوج باید IP ایران و خارج داشته باشد')
            if len({tuple(pair) for pair in pairs}) != len(pairs):
                raise ValueError('زوج تکراری انتخاب شده است')
            for pair in pairs:
                for ip in pair:ipaddress.IPv4Address(ip)
            from core.validation import validate_port
            port, mtu = int(validate_port(port)), int(mtu)
            if not 1 <= port <= 65535-len(pairs)+1 or not 576 <= mtu <= 1440:
                raise ValueError('پورت پایه یا MTU معتبر نیست')
            irans, outsides = data.get('iran_servers', []), data.get('kharej_servers', [])
            identity = uuid.uuid4().hex
            job = dict(id=identity, kind='matrix', status='queued', total=len(pairs), completed=0,
                       links=[], failed=[], message='در صف ساخت لینک‌های انتخاب‌شده', updated_at=time.time())
            def reserve_and_admit(current):
                links = PrivateLinkManager.create_matrix_topology(irans, outsides, 'wireguard', pairs,
                    params={'tunnel_port':port, 'mtu':mtu}, _data=current)
                job['links'] = [link['link_name'] for link in links]
                current.setdefault('link_tasks', {})[identity] = dict(job)
            atomic_update(reserve_and_admit)
        except (ValueError, TypeError, RuntimeError, KeyError) as error:
            return False, str(error)
        try:
            threading.Thread(target=run, args=(identity,), daemon=True).start()
        except Exception:
            update(identity, status='failed', message='شروع عملیات ناموفق بود؛ طرح‌های رزروشده را بررسی کنید')
            return False, 'عملیات شروع نشد؛ طرح‌های لینک حفظ شده‌اند'
        return True, job


def start_delete(name):
    with mutation_lock():
        data=load_data()
        if busy(data):
            return False, 'عملیات دیگری در حال اجراست'
        if name not in data.get('custom_links', {}):
            return False, 'لینک یافت نشد'
        identity=uuid.uuid4().hex
        job=dict(id=identity, kind='delete', status='queued', links=[name], total=1, completed=0, failed=[], message='در صف حذف لینک', updated_at=time.time())
        def admit(current):
            current.setdefault('link_tasks', {})[identity]=job
        atomic_update(admit)
        try:
            threading.Thread(target=run,args=(identity,),daemon=True).start()
        except Exception:
            update(identity,status='failed',message='حذف شروع نشد')
            return False,'حذف شروع نشد'
        return True,job


def run(identity):
    with mutation_lock(), worker_job(identity):
        job=load_data().get('link_tasks',{}).get(identity,{})
        if job.get('status')!='queued':
            return
        try:
            update(identity,status='running',message='در حال اجرای عملیات لینک‌ها')
            failed=[]
            completed=0
            for name in job['links']:
                update(identity,current_link=name)
                ok,_=private_link_runtime.delete(name) if job['kind']=='delete' else private_link_runtime.provision(name)
                if ok:completed+=1
                else:failed.append(name)
                update(identity,completed=completed,failed=failed)
            update(identity,status='failed' if failed else 'succeeded',message='بعضی لینک‌ها کامل نشدند؛ وضعیت منابع را بررسی کنید' if failed else 'عملیات لینک‌ها پایان یافت',current_link='')
        except Exception:
            update(identity,status='failed',message='عملیات قطع شد؛ وضعیت لینک و منابع دو سمت را بررسی کنید')


def recover():
    def save(data):
        for job in data.get('link_tasks',{}).values():
            if job.get('status') in ('queued','running'):
                job.update(status='failed',message='ری‌استارت پنل عملیات را قطع کرد؛ نصب خودکار تکرار نشد',updated_at=time.time())
        for link in data.get('custom_links',{}).values():
            if link.get('status') in ('provisioning','deleting'):
                link.update(status='cleanup_failed',error='عملیات قطع شده؛ مالکیت منابع برای بررسی و پاک‌سازی حفظ شد')
    atomic_update(save)
