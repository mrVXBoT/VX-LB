"""Durable asynchronous admission for pool deletion and forwarded-port edits."""
import threading
import time
import uuid
from contextlib import contextmanager
from core.storage import load_data, atomic_update
from core.transport_change import mutation_lock, busy, _mutation_local
from core.load_balancer import LoadBalancerManager
from core.validation import validate_ports, validate_port

ACTIVE = {'queued','running'}


def update(name, **fields):
    def save(data):
        data['pool_tasks'][name].update(fields, updated_at=time.time())
    atomic_update(save)


@contextmanager
def worker_job(job_id):
    previous = getattr(_mutation_local,'job_id',None)
    _mutation_local.job_id = job_id
    try:
        yield
    finally:
        _mutation_local.job_id = previous


def start(name, kind, values=None):
    if kind not in ('delete','ports_add','ports_remove','slipstream_settings','http_transport'):
        return False,'عملیات نامعتبر است'
    if busy(load_data()):
        return False, 'عملیات دیگری در حال اجراست'
    with mutation_lock():
        data=load_data()
        if busy(data):
            return False,'عملیات دیگری در حال اجراست'
        pool=data.get('pools',{}).get(name)
        if pool is None:
            return False,'استخر یافت نشد'
        try:
            if kind == 'http_transport':
                if pool.get('transport') not in ('http', 'https') or values not in ('http', 'https'):
                    return False, 'استخر و نوع معتبر HTTP/HTTPS لازم است'
                if values == pool.get('transport'):
                    return False, 'نوع HTTP فعلی تغییری نکرده است'
            elif kind == 'slipstream_settings':
                if pool.get('engine') != 'slipstream' or not isinstance(values, dict):
                    return False, 'تنظیمات معتبر Slipstream لازم است'
                from core.slipstream_update import candidate
                normalized = candidate(pool, values)
                values = {key: normalized[key] for key in values}
            elif kind=='ports_add':
                values=validate_ports(values)
                if set(values).issubset(set(map(str,pool.get('client_ports',[])))):
                    return False,'این پورت‌ها قبلاً ثبت شده‌اند'
            elif kind=='ports_remove':
                values=validate_port(values)
                current=list(map(str,pool.get('client_ports',[])))
                if values not in current:
                    return False,'پورت در استخر وجود ندارد'
                if len(set(current))<2:
                    return False,'آخرین پورت استخر را نمی‌توان حذف کرد'
        except (ValueError, KeyError, TypeError) as error:
            return False,str(error)
        job={'created_at':time.time(),'phase':'queued','id':uuid.uuid4().hex,'kind':kind,'name':name,'status':'queued','message':'در صف حذف استخر' if kind=='delete' else 'در صف تغییر تنظیمات Slipstream' if kind == 'slipstream_settings' else 'در صف تغییر HTTP/HTTPS' if kind == 'http_transport' else 'در صف تغییر پورت‌ها','updated_at':time.time(),'error':'','values':values}
        def save(data):
            data.setdefault('pool_tasks',{})[name]=job
        atomic_update(save)
        try:
            threading.Thread(target=run,args=(name,job['id']),daemon=True).start()
        except Exception:
            update(name,status='failed',message='عملیات شروع نشد؛ دوباره تلاش کنید')
            return False,'عملیات شروع نشد'
        return True,job


def run(name,job_id):
    with mutation_lock(),worker_job(job_id):
        data=load_data()
        job=data.get('pool_tasks',{}).get(name,{})
        if job.get('id')!=job_id or job.get('status')!='queued':
            return
        try:
            update(name,status='running',started_at=time.time(),phase='cleaning' if job['kind']=='delete' else 'configuring',message='در حال پاک‌سازی منابع استخر' if job['kind']=='delete' else 'در حال تغییر تنظیمات Slipstream' if job['kind'] == 'slipstream_settings' else 'در حال تغییر HTTP/HTTPS و بررسی داده' if job['kind'] == 'http_transport' else 'در حال تغییر پورت‌های نودها')
            if job['kind']=='delete':
                nodes = data.get('pools', {}).get(name, {}).get('nodes', [])
                last_progress = [None, 0]
                def progress(message):
                    current = next((n['ip'] for n in nodes if n['ip'] in str(message) or
                                    (n.get('node_name') and n['node_name'] in str(message))), '')
                    if current == last_progress[0] and time.monotonic() - last_progress[1] < 1:
                        return
                    last_progress[:] = [current, time.monotonic()]
                    update(name, phase='cleaning', current_node=current, message='در حال حذف سرویس‌ها و منابع نودها')
                ok,message=LoadBalancerManager.delete_entire_pool(name,callback=progress)
            elif job['kind'] == 'slipstream_settings':
                from core.slipstream_update import change
                ok, message = change(name, job['values'])
            elif job['kind']=='http_transport':
                from core.http_transport import change_mode
                ok,message=change_mode(name,job['values'])
            elif job['kind']=='ports_add':
                ok,message=LoadBalancerManager.add_client_ports(name,job['values'])
            else:
                ok,message=LoadBalancerManager.remove_client_port(name,job['values'])
            # Remote errors are untrusted and may contain credentials; mask inventory secrets.
            for server in [*data.get('iran_servers',[]),*data.get('kharej_servers',[])]:
                password=server.get('password')
                if password:
                    message=str(message).replace(password,'[REDACTED]')
            update(name,status='succeeded' if ok else 'failed',message='حذف استخر پایان یافت' if ok and job['kind']=='delete' else 'تغییر تنظیمات Slipstream پایان یافت' if ok and job['kind'] == 'slipstream_settings' else 'تغییر HTTP/HTTPS و آزمون داده پایان یافت' if ok and job['kind'] == 'http_transport' else 'تغییر پورت پایان یافت' if ok else 'عملیات کامل نشد؛ جزئیات را بررسی کنید',error='' if ok else str(message))
        except Exception:
            update(name,status='failed',message='عملیات قطع شد؛ وضعیت منابع را بررسی کنید',error='خطای اجرای عملیات؛ برای ادامه وضعیت نودها و سوابق سرویس را بررسی کنید')


def recover():
    def save(data):
        for job in data.get('pool_tasks',{}).values():
            if job.get('status') in ACTIVE:
                job.update(status='failed',message='ری‌استارت پنل عملیات را قطع کرد؛ پیش از تلاش مجدد وضعیت منابع را بررسی کنید',error='اجرای عملیات پس از restart خودکار تکرار نشد',updated_at=time.time())
    atomic_update(save)
