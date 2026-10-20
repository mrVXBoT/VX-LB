"""Durable, asynchronous node provisioning progress (no credentials in jobs)."""
import threading
import time
import uuid
from core.storage import load_data, atomic_update
from core.transport_change import mutation_lock, busy
from core.load_balancer import LoadBalancerManager

ACTIVE = {'queued', 'running'}

def update(pool, ip, **fields):
    def write(data):
        data['pools'][pool]['node_additions'][ip].update(fields, updated_at=time.time())
    atomic_update(write)

def start(pool, server):
    # Web requests already hold this lock; it is reentrant in this process.
    data = load_data()
    if busy(data): return False, 'عملیات دیگری در جریان است؛ پس از پایان آن دوباره تلاش کنید'
    entry = data.get('pools', {}).get(pool)
    ip = server['ip']
    if not entry: return False, 'استخر یافت نشد'
    if any(n['ip'] == ip for n in entry.get('nodes', [])):
        return False, 'این سرور قبلاً عضو استخر است'
    job = {'id': uuid.uuid4().hex, 'ip': ip, 'name': server['name'],
           'status': 'queued', 'message': 'در صف افزودن به استخر', 'updated_at': time.time()}
    def write(data): data['pools'][pool].setdefault('node_additions', {})[ip] = job
    atomic_update(write)
    try:
        threading.Thread(target=run, args=(pool, dict(server)), daemon=True).start()
    except Exception:
        update(pool, ip, status='failed', message='عملیات شروع نشد؛ دوباره تلاش کنید')
        return False, 'عملیات شروع نشد'
    return True, job

def run(pool, server):
    ip = server['ip']
    with mutation_lock():
        try:
            update(pool, ip, status='running', message='در حال آماده‌سازی سرور')
            def progress(message):
                if message.startswith('Connecting to Kharej'): label = 'اتصال به سرور خارج'
                elif message.startswith('Connecting to new Iran'): label = 'اتصال به سرور ایران'
                elif message.startswith('Deploying tunnel'): label = 'راه‌اندازی تونل و سرویس‌های دو سمت'
                elif 'monitor' in message.lower(): label = 'آماده‌سازی پایش سرور ایران'
                else: label = 'در حال راه‌اندازی نود'
                update(pool, ip, message=label)
            ok, message = LoadBalancerManager.add_node(pool, server, callback=progress)
            update(pool, ip, status='succeeded' if ok else 'failed',
                   message='نود به استخر اضافه شد' if ok else 'افزودن نود ناموفق بود',
                   error='' if ok else message)
        except Exception as error:
            update(pool, ip, status='failed', message='افزودن نود کامل نشد', error=str(error))

def recover():
    def write(data):
        for pool in data.get('pools', {}).values():
            for job in pool.get('node_additions', {}).values():
                if job.get('status') in ACTIVE:
                    job.update(status='failed', message='راه‌اندازی پنل عملیات را قطع کرد؛ وضعیت نود را بررسی کنید',
                               error='ممکن است سرویس بخشی از تونل نصب شده باشد؛ پیش از تلاش مجدد وضعیت سرورها را بررسی کنید')
    atomic_update(write)
