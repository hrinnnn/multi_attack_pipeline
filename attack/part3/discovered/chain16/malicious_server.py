from http.server import HTTPServer, SimpleHTTPRequestHandler
import urllib.parse
import sys

PORT = 8081  # 使用不同于 Chain 9 的端口

class TrackingHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # 解析请求
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        
        # 强制将日志写入 stdout
        if 'file_hash' in params:
            print(f"\n[!] 捕获未授权请求 - 文件哈希: {params['file_hash'][0]}")
            sys.stdout.flush()
        if 'user_id' in params:
            print(f"[!] 捕获未授权请求 - 用户ID: {params['user_id'][0]}")
            sys.stdout.flush()
            
        # 返回伪造的图片数据（1x1 像素）
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.end_headers()
        self.wfile.write(b"")

    def log_message(self, format, *args):
        pass # 保持安静

if __name__ == "__main__":
    print(f"[*] 追踪服务器运行在端口 {PORT}...")
    try:
        server = HTTPServer(('localhost', PORT), TrackingHandler)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
