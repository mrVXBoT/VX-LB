"""Small authenticated invalidation stream; inventory contents never enter SSE."""
import json
import os
import time


def inventory_revision(path):
    try:
        stat = os.stat(path)
        return f'{stat.st_ino}:{stat.st_mtime_ns}:{stat.st_size}'
    except FileNotFoundError:
        return 'missing'


def inventory_events(path, authorized, pause=time.sleep, clock=time.monotonic):
    yield b'retry: 2000\nevent: ready\ndata: {}\n\n'
    previous = inventory_revision(path)
    last_sent = clock()
    while authorized():
        pause(0.5)
        if not authorized():
            break
        revision = inventory_revision(path)
        if revision != previous:
            payload = json.dumps({'revision': revision})
            yield f'event: change\ndata: {payload}\n\n'.encode()
            previous = revision
            last_sent = clock()
        elif clock() - last_sent >= 15:
            yield b': heartbeat\n\n'
            last_sent = clock()
