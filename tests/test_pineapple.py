from src.core.pineapple import PineappleSSH
from src.core.modules import Module, Request

def test_connect_fails_for_wrong_host():
    p = PineappleSSH(host='127.0.0.1', username='root', password='wrong', timeout=1)
    assert p.connect() is False

def test_module_handler():
    m = Module('testmod')
    @m.handles_action('echo')
    def echo(req: Request):
        return getattr(req, 'msg', '')

    req = Request('testmod', 'echo', msg='hello')
    payload, ok = m.handle_request(req)
    assert ok is True
    assert payload == 'hello'
