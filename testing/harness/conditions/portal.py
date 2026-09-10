from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pathlib

FLAG = pathlib.Path("/opt/state/portal-authenticated")
PAGE = (b"<html><body><h1>Network Login</h1>"
        b"<form method=POST action=/login>"
        b"<input name=u placeholder=user><button>Log in</button>"
        b"</form></body></html>")


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"authenticated\n" if FLAG.exists() else PAGE
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        FLAG.touch()
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("0.0.0.0", 8081), H).serve_forever()
