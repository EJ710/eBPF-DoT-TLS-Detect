#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Test HTTPS Server</h1><p>This is a test server for TLS simulation.</p></body></html>")

def run_server():
    server_address = ('127.0.0.1', 8443)
    httpd = HTTPServer(server_address, SimpleHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print("Starting HTTPS server on https://127.0.0.1:8443...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        httpd.server_close()

if __name__ == "__main__":
    run_server()
