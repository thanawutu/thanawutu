"""Run the simulated Rapid7 console from test_r7 on 127.0.0.1:3780 (user / pass)."""
from http.server import ThreadingHTTPServer
import test_r7
test_r7.FakeConsole.scan_status = {}
ThreadingHTTPServer(("127.0.0.1", 3780), test_r7.FakeConsole).serve_forever()
