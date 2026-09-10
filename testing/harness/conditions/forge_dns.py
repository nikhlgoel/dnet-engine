import socketserver, struct, os
FORGED = os.environ.get("FORGED_IP", "10.99.99.99")

class H(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        if len(data) < 12:
            return
        tid = data[:2]
        q = data[12:]
        end = 0
        while end < len(q) and q[end] != 0:
            end += 1 + q[end]
        question = q[:end + 5]
        resp = tid + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00" + question
        resp += b"\xc0\x0c" + b"\x00\x01\x00\x01" + struct.pack(">I", 300)
        resp += b"\x00\x04" + bytes(int(o) for o in FORGED.split("."))
        sock.sendto(resp, self.client_address)

class S(socketserver.ThreadingUDPServer):
    allow_reuse_address = True

S(("0.0.0.0", 5353), H).serve_forever()
