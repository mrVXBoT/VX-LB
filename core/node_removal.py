"""Persisted progress for asynchronous web node removal."""
import inspect
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

def start(pool, ip, force=False, forget=False):
    # Reject promptly while an SSH operation holds the mutation lock.
    if busy(load_data()):
        return False, 'عملیات دیگری در جریان است یا نیاز به رسیدگی دارد'
    with mutation_lock():
        data = load_data()
        if busy(data):
            return False, 'عملیات دیگری در جریان است یا نیاز به رسیدگی دارد'
        entry = data.get('pools', {}).get(pool)
        if not entry or not any(n['ip'] == ip for n in entry.get('nodes', [])):
            return False, 'نود در این استخر یافت نشد'
        job = {'id': uuid.uuid4().hex, 'status': 'queued', 'phase': 'queued',
               'created_at': time.time(), 'message': 'حذف در صف اجرا است',
               'ip': ip, 'force': force, 'forget': forget}
        def write(data):
            data['pools'][pool].setdefault('node_removals', {})[ip] = job
        atomic_update(write)
        try:
            threading.Thread(target=run, args=(pool, ip, force, forget, job['id']), daemon=True).start()
        except Exception:
            update(pool, ip, status='failed', message='اجرای حذف شروع نشد؛ دوباره تلاش کنید')
            return False, 'اجرای حذف شروع نشد؛ دوباره تلاش کنید'
        return True, job


def run(pool, ip, force=False, forget=False, job_id=None):
    with mutation_lock():
        data = load_data()
        job = data.get('pools', {}).get(pool, {}).get('node_removals', {}).get(ip, {})
        if job.get('status') != 'queued' or (job_id is not None and job.get('id') != job_id):
            return
        def scrub(message):
            from core.pool_workflow import public_change_job
            return public_change_job({'message': str(message)}, data)['message']
        try:
            update(pool, ip, status='running', phase='preparing', started_at=time.time(), message='در حال آماده‌سازی حذف نود')
            messages = {'Tearing down tunnel from Kharej server...': ('removing_kharej', 'در حال حذف تونل سمت خارج'),
                        'Tearing down tunnel from Iran server...': ('removing_iran', 'در حال حذف تونل سمت ایران')}
            def progress(message):
                phase, label = messages.get(message, ('cleaning', 'در حال پاک‌سازی سرویس‌ها و منابع نود'))
                update(pool, ip, phase=phase, message=label)
            if forget:
                ok, message = LoadBalancerManager.forget_node(pool, ip)
            else:
                remove = LoadBalancerManager.remove_node
                parameters = inspect.signature(remove).parameters
                options = {'callback': progress}
                if 'force' in parameters or any(p.kind == p.VAR_KEYWORD for p in parameters.values()):
                    options['force'] = force
                # Never retry a mutation because its implementation raised TypeError.
                ok, message = remove(pool, ip, **options)
            update(pool, ip, status='succeeded' if ok else 'failed',
                   cleanup_pending=bool(ok and forget),
                   error='' if ok else scrub(message),
                   message=scrub(message) if forget or not ok else 'نود از استخر حذف شد')
        except Exception as error:
            update(pool, ip, status='failed', message='حذف کامل نشد: ' + scrub(error), error=scrub(error))

def recover():
    # A server restart cannot prove completion of an interrupted remote deletion.
    def write(data):
        for pool in data.get('pools', {}).values():
            for job in pool.get('node_removals', {}).values():
                if job.get('status') in ACTIVE:
                    job.update(status='failed', message='عملیات با راه‌اندازی مجدد وب قطع شد؛ وضعیت نود را بررسی و دوباره تلاش کنید')
    atomic_update(write)
