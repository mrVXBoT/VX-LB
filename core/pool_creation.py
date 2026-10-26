"""Persisted pool creation progress with asynchronous web admission.

A separate record survives engine-specific save_pool calls. Restart marks work
interrupted rather than replaying remote mutations without reconciliation.
"""
import copy
import threading
import time
import uuid
from core.storage import load_data, atomic_update
from core.transport_change import mutation_lock, busy, _mutation_local
from core.load_balancer import LoadBalancerManager
from core.pool_workflow import normalize_creation, pool_ready, validate_engine_target

ACTIVE = {'queued', 'running'}


def update(name, **fields):
    def save(data):
        data['pool_creations'][name].update(fields, updated_at=time.time())
    atomic_update(save)


def start(arguments):
    try:
        arguments = normalize_creation(arguments)
    except (ValueError, TypeError) as error:
        return False, str(error)
    name = arguments['pool_name']
    transport = arguments.get('transport', 'pck')
    from core.capabilities import validate_production_readiness
    from core.transport_change import _coerce_engine
    engine = _coerce_engine(arguments.get('engine'), transport)
    import os
    is_prod = bool(arguments.get('is_production', False) or os.environ.get("VX_LB_PRODUCTION", "").lower() in ("1", "true", "yes"))
    allow_exp = bool(arguments.get('allow_experimental', False))
    ok_gate, gate_msg = validate_production_readiness(engine, is_production=is_prod, allow_experimental=allow_exp)
    if not ok_gate:
        return False, gate_msg
    try:
        validate_engine_target(transport, engine)
    except ValueError as error:
        return False, str(error)

    with mutation_lock():
        data = load_data()
        if busy(data):
            return False, 'عملیات دیگری در حال اجراست'
        if name in data.get('pools', {}):
            return False, 'استخری با این نام وجود دارد؛ ابتدا وضعیت آن را بررسی کنید'
        job = {
            'id': uuid.uuid4().hex, 'status': 'queued', 'message': 'در صف ساخت استخر',
            'updated_at': time.time(), 'name': name, 'transport': arguments['transport'],
            'client_ports': arguments['client_ports'], 'kharej_ip': arguments['kharej_server']['ip'],
            'iran_ips': [s['ip'] for s in arguments['iran_servers']], 'error': '',
        }
        def save(data):
            data.setdefault('pool_creations', {})[name] = job
        atomic_update(save)
        try:
            threading.Thread(target=run, args=(copy.deepcopy(arguments), job['id']), daemon=True).start()
        except Exception:
            update(name, status='failed', message='عملیات شروع نشد؛ دوباره تلاش کنید')
            return False, 'عملیات شروع نشد'
        return True, job


def run(arguments, job_id=None):
    name = arguments['pool_name']
    # Values needed for deployment stay in memory, never in the job record.
    secrets = []
    def collect(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if (key.lower() in {'key', 'knock_key'} or any(word in key.lower() for word in ('password', 'token', 'secret', 'private_key'))) and isinstance(item,str) and item:
                    secrets.append(item)
                else:
                    collect(item)
        elif isinstance(value,list):
            for item in value:
                collect(item)
    collect(arguments)
    def scrub(message):
        message = str(message)
        for value in secrets:
            message = message.replace(value, '[REDACTED]')
        return message
    with mutation_lock():
        job = load_data().get('pool_creations', {}).get(name, {})
        if job.get('status') != 'queued' or (job_id is not None and job.get('id') != job_id):
            return
        previous_job = getattr(_mutation_local, 'job_id', None)
        _mutation_local.job_id = job.get('id')
        try:
            update(name, status='running', message='در حال آماده‌سازی استخر و سرورها')
            def progress(message):
                text = str(message).lower()
                label = 'در حال پیکربندی تونل و رله'
                if 'connect' in text: label = 'اتصال به سرورهای دو سمت'
                elif 'install' in text: label = 'آماده‌سازی وابستگی‌های سرورها'
                elif 'verif' in text or 'probe' in text: label = 'بررسی نتیجهٔ راه‌اندازی'
                update(name, message=label)
            ok, message, _ = LoadBalancerManager.create_pool(**arguments, callback=progress)
            pool = load_data().get('pools', {}).get(name, {})
            provisioned = [n['ip'] for n in pool.get('nodes', []) if not n.get('provisioning')]
            expected = [s['ip'] for s in arguments['iran_servers']]
            complete = ok and pool_ready(pool, arguments['iran_servers'])
            update(name, status='succeeded' if complete else 'failed',
                   message='راه‌اندازی استخر پایان یافت؛ سلامت مسیر در کارت نودها نمایش داده می‌شود' if complete else 'ساخت استخر کامل نشد؛ نتیجهٔ نودها را بررسی کنید',
                   completed=len(set(expected)&set(provisioned)), total=len(expected),
                   error='' if complete else scrub(message))
        except Exception as error:
            update(name, status='failed', message='ساخت استخر کامل نشد؛ ممکن است منابعی روی سرورها باقی مانده باشد', error=scrub(error))
        finally:
            _mutation_local.job_id = previous_job


def project(data):
    """Read-only API view: show a card even before the engine saves its pool."""
    pools = copy.deepcopy(data.get('pools', {}))
    for name, backup in data.get('pool_backups', {}).items():
        pools.setdefault(name, copy.deepcopy(backup))
        if backup.get('transport_change') and not pools[name].get('transport_change'):
            pools[name]['transport_change'] = copy.deepcopy(backup['transport_change'])
    for name, job in data.get('pool_creations', {}).items():
        pool = pools.setdefault(name, {'name':name, 'transport':job['transport'], 'engine':job['transport'], 'nodes':[], 'client_ports':job['client_ports'], 'kharej_server':{'ip':job['kharej_ip']}})
        pool['creation_job'] = job
        pool['creation_placeholder'] = name not in data.get('pools', {})
        if job.get('status') in ACTIVE:
            existing = {n['ip'] for n in pool.get('nodes', [])}
            for ip in job['iran_ips']:
                if ip not in existing:
                    pool.setdefault('nodes', []).append({'ip':ip, 'server_name':ip, 'engine':pool.get('engine',job['transport']), 'provisioning':True, 'creation_pending':True})
    for name, job in data.get('pool_tasks', {}).items():
        if name in pools:
            pools[name]['operation_task'] = job
    return pools


def recover():
    def save(data):
        for job in data.get('pool_creations', {}).values():
            if job.get('status') in ACTIVE:
                job.update(status='failed', message='ری‌استارت پنل عملیات ساخت را قطع کرد؛ وضعیت منابع را بررسی کنید', error='راه‌اندازی خودکار تکرار نشد؛ ابتدا وضعیت نودها و منابع دو سمت را بررسی کنید', updated_at=time.time())
    atomic_update(save)
