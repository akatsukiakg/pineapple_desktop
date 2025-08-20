"""Module exposing concrete Pineapple actions via Module/Request API"""
from __future__ import annotations
import logging
from typing import Optional
from .modules import Module, Request
from .pineapple import PineappleSSH

logger = logging.getLogger('pineapple.module.pineapple')
module = Module('pineapple', logging.DEBUG)

@module.on_start()
def announce():
    # Placeholder: in this desktop app, just logs via send_notification
    module.send_notification('Pineapple module loaded', level=0)

@module.handles_action('run_scan')
def handle_run_scan(request: Request):
    """run_scan duration frequencies (ints)"""
    pine: Optional[PineappleSSH] = getattr(request, 'pine', None)
    created = False
    if pine is None:
        host = getattr(request, 'host', '172.16.42.1')
        user = getattr(request, 'username', 'root')
        pwd = getattr(request, 'password', None)
        pine = PineappleSSH(host, user, pwd)
        if not pine.connect():
            return ({'error': 'SSH connect failed'}, False)
        created = True
    try:
        duration = int(getattr(request, 'duration', 0))
        freqs = int(getattr(request, 'frequencies', 2))
        out = pine.run_scan(duration, freqs)
        return (out, True)
    except Exception as e:
        logger.exception('run_scan error')
        return ({'error': str(e)}, False)
    finally:
        if created and pine:
            pine.close()

@module.handles_action('list_probes')
def handle_list_probes(request: Request):
    pine: Optional[PineappleSSH] = getattr(request, 'pine', None)
    created = False
    if pine is None:
        host = getattr(request, 'host', '172.16.42.1')
        user = getattr(request, 'username', 'root')
        pwd = getattr(request, 'password', None)
        pine = PineappleSSH(host, user, pwd)
        if not pine.connect():
            return ({'error': 'SSH connect failed'}, False)
        created = True
    try:
        out = pine.list_probes()
        return (out, True)
    except Exception as e:
        logger.exception('list_probes error')
        return ({'error': str(e)}, False)
    finally:
        if created and pine:
            pine.close()

@module.handles_action('handshake_capture_start')
def handle_handshake_start(request: Request):
    pine: Optional[PineappleSSH] = getattr(request, 'pine', None)
    created = False
    if pine is None:
        host = getattr(request, 'host', '172.16.42.1')
        user = getattr(request, 'username', 'root')
        pwd = getattr(request, 'password', None)
        pine = PineappleSSH(host, user, pwd)
        if not pine.connect():
            return ({'error': 'SSH connect failed'}, False)
        created = True
    try:
        bssid = getattr(request, 'bssid')
        channel = int(getattr(request, 'channel'))
        out = pine.handshake_capture_start(bssid, channel)
        return (out, True)
    except Exception as e:
        logger.exception('handshake_start error')
        return ({'error': str(e)}, False)
    finally:
        if created and pine:
            pine.close()

@module.handles_action('handshake_capture_stop')
def handle_handshake_stop(request: Request):
    pine: Optional[PineappleSSH] = getattr(request, 'pine', None)
    created = False
    if pine is None:
        host = getattr(request, 'host', '172.16.42.1')
        user = getattr(request, 'username', 'root')
        pwd = getattr(request, 'password', None)
        pine = PineappleSSH(host, user, pwd)
        if not pine.connect():
            return ({'error': 'SSH connect failed'}, False)
        created = True
    try:
        out = pine.handshake_capture_stop()
        return (out, True)
    except Exception as e:
        logger.exception('handshake_stop error')
        return ({'error': str(e)}, False)
    finally:
        if created and pine:
            pine.close()

@module.handles_action('deauth')
def handle_deauth(request: Request):
    pine: Optional[PineappleSSH] = getattr(request, 'pine', None)
    created = False
    if pine is None:
        host = getattr(request, 'host', '172.16.42.1')
        user = getattr(request, 'username', 'root')
        pwd = getattr(request, 'password', None)
        pine = PineappleSSH(host, user, pwd)
        if not pine.connect():
            return ({'error': 'SSH connect failed'}, False)
        created = True
    try:
        mac = getattr(request, 'mac')
        bssid = getattr(request, 'bssid', 'ff:ff:ff:ff:ff:ff')
        channel = int(getattr(request, 'channel', 6))
        multiplier = int(getattr(request, 'multiplier', 1))
        out = pine.deauth(mac, bssid, channel, multiplier)
        return (out, True)
    except Exception as e:
        logger.exception('deauth error')
        return ({'error': str(e)}, False)
    finally:
        if created and pine:
            pine.close()

@module.handles_action('download_file')
def handle_download_file(request: Request):
    """Download a file from device to local path. Provide remote_path and local_path."""
    pine: Optional[PineappleSSH] = getattr(request, 'pine', None)
    created = False
    if pine is None:
        host = getattr(request, 'host', '172.16.42.1')
        user = getattr(request, 'username', 'root')
        pwd = getattr(request, 'password', None)
        pine = PineappleSSH(host, user, pwd)
        if not pine.connect():
            return ({'error': 'SSH connect failed'}, False)
        created = True
    try:
        r = getattr(request, 'remote_path')
        l = getattr(request, 'local_path')
        ok = pine.sftp_get(r, l)
        if ok:
            return ({'local_path': l}, True)
        return ({'error': 'sftp_get failed'}, False)
    except Exception as e:
        logger.exception('download_file error')
        return ({'error': str(e)}, False)
    finally:
        if created and pine:
            pine.close()

@module.handles_action('init_pineap')
def handle_init_pineap(request: Request):
    """Initialize PineAP: start daemon, set logging, optionally notifications, optionally start scan."""
    pine: Optional[PineappleSSH] = getattr(request, 'pine', None)
    created = False
    if pine is None:
        host = getattr(request, 'host', '172.16.42.1')
        user = getattr(request, 'username', 'root')
        pwd = getattr(request, 'password', None)
        pine = PineappleSSH(host, user, pwd)
        if not pine.connect():
            return ({'error': 'SSH connect failed'}, False)
        created = True
    try:
        log_on = bool(getattr(request, 'logging', True))
        notifications_on = bool(getattr(request, 'notifications', False))
        duration = int(getattr(request, 'duration', 0))
        freqs = int(getattr(request, 'frequencies', 2))
        out = []
        out.append(pine.start_pineapd())
        out.append(pine.logging(log_on))
        if notifications_on:
            out.append(pine.connect_notifications(True))
        # Optionally start scan
        if duration >= 0 and freqs in (0, 1, 2):
            out.append(pine.run_scan(duration, freqs))
        return ("\n".join(out), True)
    except Exception as e:
        logger.exception('init_pineap error')
        return ({'error': str(e)}, False)
    finally:
        if created and pine:
            pine.close()

@module.handles_action('logging')
def handle_logging(request: Request):
    pine: Optional[PineappleSSH] = getattr(request, 'pine', None)
    created = False
    if pine is None:
        host = getattr(request, 'host', '172.16.42.1')
        user = getattr(request, 'username', 'root')
        pwd = getattr(request, 'password', None)
        pine = PineappleSSH(host, user, pwd)
        if not pine.connect():
            return ({'error': 'SSH connect failed'}, False)
        created = True
    try:
        on = bool(getattr(request, 'on', True))
        return (pine.logging(on), True)
    except Exception as e:
        logger.exception('logging toggle error')
        return ({'error': str(e)}, False)
    finally:
        if created and pine:
            pine.close()

@module.handles_action('connect_notifications')
def handle_notifications(request: Request):
    pine: Optional[PineappleSSH] = getattr(request, 'pine', None)
    created = False
    if pine is None:
        host = getattr(request, 'host', '172.16.42.1')
        user = getattr(request, 'username', 'root')
        pwd = getattr(request, 'password', None)
        pine = PineappleSSH(host, user, pwd)
        if not pine.connect():
            return ({'error': 'SSH connect failed'}, False)
        created = True
    try:
        on = bool(getattr(request, 'on', True))
        return (pine.connect_notifications(on), True)
    except Exception as e:
        logger.exception('notifications toggle error')
        return ({'error': str(e)}, False)
    finally:
        if created and pine:
            pine.close()

@module.handles_action('pineap_help')
def handle_help(request: Request):
    pine: Optional[PineappleSSH] = getattr(request, 'pine', None)
    created = False
    if pine is None:
        host = getattr(request, 'host', '172.16.42.1')
        user = getattr(request, 'username', 'root')
        pwd = getattr(request, 'password', None)
        pine = PineappleSSH(host, user, pwd)
        if not pine.connect():
            return ({'error': 'SSH connect failed'}, False)
        created = True
    try:
        return (pine.pineap_help(), True)
    except Exception as e:
        logger.exception('help error')
        return ({'error': str(e)}, False)
    finally:
        if created and pine:
            pine.close()
