"""Persisted progress for asynchronous web node removal."""
import threading
import time
import uuid
from core.storage import load_data, atomic_update
from core.transport_change import mutation_lock, busy
from core.load_balancer import LoadBalancerManager

ACTIVE = {'queued', 'running'}

def update(pool, ip, **fields):
    def write(data):
        jobs = data['pools'][pool].setdefault('node_removals', {})
        jobs[ip].update(fields, updated_at=time.strftime('%Y-%m-%d %H:%M:%S'))
    atomic_update(write)

def start(pool, ip, force=False):
    data = load_data()
    if busy(data): return False, 'عملیات دیگری در جریان است یا نیاز به رسیدگی دارد'
    entry = data.get('pools', {}).get(pool)
    if not entry or not any(n['ip'] == ip for n in entry.get('nodes', [])):
        return False, 'نود در این استخر یافت نشد'
    job = {'id': uuid.uuid4().hex, 'status':'queued', 'message':'حذف در صف اجرا است', 'ip':ip, 'force': force}
    def write(data): data['pools'][pool].setdefault('node_removals', {})[ip] = job
    atomic_update(write)
    try:
        threading.Thread(target=run, args=(pool, ip, force), daemon=True).start()
    except Exception:
        update(pool, ip, status='failed', message='اجرای حذف شروع نشد؛ دوباره تلاش کنید')
        return False, 'اجرای حذف شروع نشد؛ دوباره تلاش کنید'
    return True, job

def run(pool, ip, force=False):
    with mutation_lock():
        try:
            update(pool, ip, status='running', message='در حال آماده‌سازی حذف نود')
            messages = {'Tearing down tunnel from Kharej server...':'در حال حذف تانل سمت خارج',
                        'Tearing down tunnel from Iran server...':'در حال حذف تانل سمت ایران'}
            try:
                ok, message = LoadBalancerManager.remove_node(pool, ip, callback=lambda m:update(pool, ip, message=messages.get(m,m)), force=force)
            except TypeError:
                ok, message = LoadBalancerManager.remove_node(pool, ip, callback=lambda m:update(pool, ip, message=messages.get(m,m)))
            update(pool, ip, status='succeeded' if ok else 'failed', message='نود از استخر حذف شد' if ok else message)
        except Exception as error:
            update(pool, ip, status='failed', message='حذف کامل نشد: '+str(error))

def recover():
    # A server restart cannot prove completion of an interrupted remote deletion.
    def write(data):
        for pool in data.get('pools', {}).values():
            for job in pool.get('node_removals', {}).values():
                if job.get('status') in ACTIVE:
                    job.update(status='failed', message='عملیات با راه‌اندازی مجدد وب قطع شد؛ وضعیت نود را بررسی و دوباره تلاش کنید')
    atomic_update(write)
