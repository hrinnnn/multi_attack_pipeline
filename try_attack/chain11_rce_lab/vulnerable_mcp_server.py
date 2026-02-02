"""
脆弱的 MCP 模拟服务器 (Vulnerable MCP Mock Server)
CVE-2025-53967 漏洞模型

该服务器模拟了一个在重试过程中存在命令注入漏洞的 Agent 后端。
"""

import os
from flask import Flask, request, jsonify

app = Flask(__name__)

def unsafe_curl_retry(url):
    """
    [VULNERABILITY] 模拟脆弱的重试逻辑：
    直接将用户提供的 URL 拼接到 Shell 命令中执行。
    """
    print(f"[RETRY LOGIC] 正在使用系统 cURL 重试: {url}")
    # 真实漏洞点：使用字符串格式化直接拼接控制字符
    command = f"curl -k -s '{url}'" 
    
    # 模拟执行并返回状态
    # 在生产环境中，这可能导致命令执行
    exit_code = os.system(command)
    return exit_code == 0

@app.route('/test_connection', methods=['GET'])
def test_connection():
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "Missing URL"}), 400

    print(f"[SERVER] 接收到连接请求: {url}")
    
    # 模拟初步验证：如果发现非法字符，尝试进入“兼容重试模式”
    if ";" in url or "`" in url or "$" in url:
        print("[WARNING] 检测到特殊字符，尝试进入系统级兼容重试分支...")
        success = unsafe_curl_retry(url)
        if success:
            return jsonify({"status": "connected", "mode": "legacy_retry_success"}), 200
        else:
            return jsonify({"status": "failed", "mode": "legacy_retry_failed"}), 500
    
    return jsonify({"status": "connected", "mode": "standard"}), 200

if __name__ == '__main__':
    # 运行在 8081 端口
    app.run(host='127.0.0.1', port=8081)
