import pandas as pd
import sqlite3
import requests
from bs4 import BeautifulSoup
import re
import time
import json
import os
from openai import OpenAI

# ================= 配置区域 =================
# 使用环境变量中的 API Key
API_KEY = os.getenv("DASHSCOPE_API_KEY")
BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
MODEL_NAME = "qwen-plus"

# 数据库文件路径
DB_PATH = "agent_intelligence.db"
SOURCE_FILE = "1.md"

# ================= 1. 数据清洗函数 =================
def clean_excel_format(cell):
    """
    清洗 Excel 复制过来的格式，例如 ="2025-09-29" -> 2025-09-29
    """
    if pd.isna(cell):
        return ""
    cell = str(cell).strip()
    # 去除开头的 =
    if cell.startswith('='):
        cell = cell[1:]
    # 去除首尾的双引号
    if cell.startswith('"') and cell.endswith('"'):
        cell = cell[1:-1]
    return cell

def parse_markdown_file(file_path):
    """
    解析非标准 Markdown/Excel 混合格式文件
    """
    data = []
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # 根据文件内容，列是：日期, 渠道, 标题, 分类, URL, AI研判, 精选情报, 是否提交dima, 情报内容
    columns = ["date", "channel", "title", "category", "url", "ai_summary", "is_selected", "submit_status", "content"]
    
    for line in lines:
        if not line.strip():
            continue
        # 文件使用制表符分隔
        parts = line.split('\t')
        
        # 清洗格式
        cleaned_parts = [clean_excel_format(p) for p in parts]
        
        # 补齐长度
        if len(cleaned_parts) < len(columns):
            cleaned_parts += [""] * (len(columns) - len(cleaned_parts))
        
        # 过滤掉表头行
        if "日期" in cleaned_parts[0]:
            continue
            
        row_dict = dict(zip(columns, cleaned_parts))
        data.append(row_dict)
        
    return pd.DataFrame(data)

# ================= 2. 网页抓取函数 =================
def fetch_url_content(url):
    """
    简单抓取网页正文，如果失败返回空字符串
    """
    if not url or not url.startswith('http'):
        return ""
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 移除 script 和 style
            for script in soup(["script", "style", "nav", "footer"]):
                script.decompose()
            
            # 获取文本
            text = soup.get_text(separator='\n')
            # 清洗多余空行
            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            text = '\n'.join(chunk for chunk in chunks if chunk)
            
            # 返回完整正文（后续在调用 LLM 时进行分片/摘要处理以应对 token 限制）
            return text
    except Exception as e:
        print(f"Error fetching {url}: {e}")
    
    return ""

# ================= 3. LLM 筛选函数 =================
def filter_intelligence_with_llm(client, title, summary, scraped_content):
    """
    使用 LLM 判断情报是否与 Agent 攻击/防御相关
    """
    # 优先使用抓取的内容，如果没有则使用原本的摘要
    context = scraped_content if len(scraped_content) > 100 else summary
    
    prompt = f"""
    你是一个大模型安全专家。请分析以下情报，判断其是否与“AI Agent（智能体）的安全、攻击、防御、漏洞、越狱”高度相关。
    
    我们只关注：
    1. 针对 Agent/LLM 的具体攻击手法（如 Prompt Injection, Jailbreak, RCE）。
    2. Agent 框架（如 LangChain, AutoGen）的漏洞。
    3. 具体的安全事件或高价值的技术报告。
    
    请忽略：
    1. 纯粹的行业新闻（如某公司发布了新模型，但未提及安全特性）。
    2. 政策法规的泛泛而谈。
    3. 与安全技术无关的营销内容。

    情报标题: {title}
    情报内容: {context[:2000]} 

    请以 JSON 格式返回结果，不要包含 Markdown 格式标记（如 ```json ... ```），直接返回 JSON 字符串：
    {{
        "is_relevant": true/false,
        "reason": "简短的判断理由",
        "tags": ["Prompt Injection", "RCE", "Supply Chain", "etc..."]
    }}
    """
    # What's to add, I don't konw
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ]
        )
        content = response.choices[0].message.content
        # 清理可能存在的 markdown 代码块标记
        if content.startswith("```json"):
            content = content[7:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()
        
        result = json.loads(content)
        return result
    except Exception as e:
        print(f"LLM Error: {e}")
        return {"is_relevant": False, "reason": f"LLM Error: {str(e)}", "tags": []}

# ================= 主流程 =================
def main():
    if not API_KEY:
        print("错误：未找到环境变量 DASHSCOPE_API_KEY。请先设置该环境变量。")
        return

    # 1. 初始化数据库
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS filtered_intelligence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT,
            title TEXT,
            url TEXT,
            category TEXT,
            original_summary TEXT,
            scraped_content TEXT,
            is_relevant BOOLEAN,
            relevance_reason TEXT,
            tags TEXT,
            raw_data TEXT,
            extraction_status TEXT DEFAULT 'pending'
        )
    ''')
    
    # 检查 extraction_status 列是否存在，如果不存在则添加 (用于旧数据库迁移)
    cursor.execute("PRAGMA table_info(filtered_intelligence)")
    columns = [info[1] for info in cursor.fetchall()]
    if 'extraction_status' not in columns:
        print("正在迁移数据库: 添加 extraction_status 列...")
        cursor.execute("ALTER TABLE filtered_intelligence ADD COLUMN extraction_status TEXT DEFAULT 'pending'")
    
    conn.commit()

    # 2. 解析文件
    print("正在解析 Markdown 文件...")
    try:
        df = parse_markdown_file(SOURCE_FILE)
        print(f"共解析出 {len(df)} 条原始数据。")
    except FileNotFoundError:
        print(f"错误：找不到文件 {SOURCE_FILE}")
        return

    # 3. 初始化 LLM 客户端
    client = OpenAI(
        api_key=API_KEY,
        base_url=BASE_URL,
    )

    # 4. 循环处理
    for index, row in df.iterrows():
        title = row['title']
        url = row['url']
        summary = row['ai_summary']
        
        # 检查是否已处理过
        cursor.execute("SELECT id FROM filtered_intelligence WHERE title = ?", (title,))
        if cursor.fetchone():
            print(f"[{index+1}/{len(df)}] 跳过已存在: {title}")
            continue

        print(f"正在处理 [{index+1}/{len(df)}]: {title}")
        
        # A. 抓取网页
        scraped_text = ""
        if url:
            print(f"  - 正在抓取 URL: {url} ...")
            scraped_text = fetch_url_content(url)
            if not scraped_text:
                print("  - 抓取失败或无内容，使用原始摘要。")
        
        # B. LLM 筛选
        print("  - 正在进行 AI 研判...")
        analysis = filter_intelligence_with_llm(client, title, summary, scraped_text)
        
        is_relevant = analysis.get('is_relevant', False)
        reason = analysis.get('reason', 'Unknown')
        tags = ",".join(analysis.get('tags', []))
        
        print(f"  - 研判结果: {'✅ 相关' if is_relevant else '❌ 忽略'} ({reason})")

        # C. 入库
        cursor.execute('''
            INSERT INTO filtered_intelligence 
            (date, title, url, category, original_summary, scraped_content, is_relevant, relevance_reason, tags, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            row['date'], 
            title, 
            url, 
            row['category'], 
            summary, 
            scraped_text, 
            is_relevant, 
            reason, 
            tags,
            json.dumps(row.to_dict())
        ))
        conn.commit()
        
        # 避免请求过快
        time.sleep(1)

    conn.close()
    print(f"处理完成！数据已保存至 {DB_PATH}")

if __name__ == "__main__":
    main()


"""
so these things are done
"""