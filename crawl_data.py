import pandas as pd
import sqlite3
import requests
from bs4 import BeautifulSoup
import time
import json
import os
from openai import OpenAI
from datetime import datetime

# ================= 配置区域 =================
API_KEY = os.getenv("DASHSCOPE_API_KEY")
BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
MODEL_NAME = "qwen-plus"

NEW_DB_PATH = "intelligence_v2.db" # 全新数据库
SOURCE_FILE = "1.md"

# ================= 1. 数据库初始化 =================
def init_new_db():
    conn = sqlite3.connect(NEW_DB_PATH)
    cursor = conn.cursor()
    # 创建核心情报表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS intel_core (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            publish_date TEXT,
            title TEXT,
            url TEXT UNIQUE,
            category TEXT,
            md_summary TEXT,           -- Markdown里的原始摘要
            full_text TEXT,            -- 抓取到的网页正文
            crawl_status TEXT DEFAULT 'pending', -- pending, success, failed, skipped
            crawl_time TIMESTAMP,
            
            is_relevant INTEGER,       -- 0为不相关, 1为相关
            ai_reason TEXT,            -- AI给出的判断理由
            ai_tags TEXT,              -- 逗号分隔的标签
            process_status TEXT DEFAULT 'pending', -- pending, processed
            process_time TIMESTAMP
        )
    ''')
    conn.commit()
    return conn

# ================= 2. 爬虫与解析工具 =================
def parse_md_to_list(file_path):
    """解析 Markdown 文件"""
    if not os.path.exists(file_path):
        print(f"找不到文件: {file_path}")
        return []
    
    df = pd.read_csv(file_path, sep='\t', names=["date", "channel", "title", "category", "url", "ai_summary", "selected", "status", "content"], header=None, skiprows=1)
    
    # 格式清洗
    def clean(x):
        if pd.isna(x): return ""
        s = str(x).strip()
        # 循环剥离，直到没有变化
        while s and (s[0] in ' "=\'' or s[-1] in ' "=\''):
            s = s.strip(' "=\'')
        return s

    data_list = []
    for _, row in df.iterrows():
        data_list.append({
            "date": clean(row['date']),
            "title": clean(row['title']),
            "url": clean(row['url']),
            "category": clean(row['category']),
            "summary": clean(row['ai_summary'])
        })
    return data_list

def scrape_url(url):
    """抓取网页正文"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Referer": "https://www.google.com/",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=20)
        if resp.status_code == 200:
            # 自动处理编码
            resp.encoding = resp.apparent_encoding
            if "访问限制" in resp.text or "Checking your browser" in resp.text:
                print(f"      [!] 触发反爬验证.")
                return None
            soup = BeautifulSoup(resp.text, 'html.parser')
            for s in soup(["script", "style", "nav", "footer", "header"]): s.decompose()
            text = soup.get_text(separator='\n')
            return '\n'.join(line.strip() for line in text.splitlines() if line.strip())
    except Exception as e:
        print(f"      [!] 抓取异常: {e}")
    return None

# ================= 3. 核心阶段逻辑 =================

def stage_1_sync_md(conn):
    """阶段1：将 MD 数据同步到新数据库"""
    print("\n[阶段1] 正在同步 Markdown 数据...")
    data = parse_md_to_list(SOURCE_FILE)
    cursor = conn.cursor()
    new_count = 0
    for item in data:
        cursor.execute('''
            INSERT OR IGNORE INTO intel_core (publish_date, title, url, category, md_summary)
            VALUES (?, ?, ?, ?, ?)
        ''', (item['date'], item['title'], item['url'], item['category'], item['summary']))
        if cursor.rowcount > 0:
            new_count += 1
    conn.commit()
    print(f"--- 同步完成，新增 {new_count} 条记录 ---")

def process_pending_intelligence(conn, client):
    """阶段2 & 3 Combined: 抓取并立刻研判"""
    print("\n[阶段2&3] 启动自动处理流水线 (抓取 -> 研判)...")
    cursor = conn.cursor()
    
    # 查找所有未完成的任务 (crawl_status != 'success' or process_status == 'pending')
    # 优先处理还未判定相关性的
    cursor.execute("SELECT id, url, title, md_summary FROM intel_core WHERE process_status = 'pending' AND url != ''")
    tasks = cursor.fetchall()
    
    print(f"待处理任务数: {len(tasks)}")

    for i, (db_id, url, title, summary) in enumerate(tasks):
        print(f"\n[{i+1}/{len(tasks)}] 处理: {title[:30]}...")
        
        # 1. 抓取 (如果还没有内容)
        cursor.execute("SELECT full_text, crawl_status FROM intel_core WHERE id = ?", (db_id,))
        row = cursor.fetchone()
        full_text, crawl_status = row[0], row[1]
        
        if not full_text: # 需要抓取
            print(f"  -> 正在抓取: {url[:60]}...")
            content = scrape_url(url)
            if content:
                full_text = content
                cursor.execute("UPDATE intel_core SET full_text = ?, crawl_status = ?, crawl_time = ? WHERE id = ?", 
                             (content, 'success', datetime.now(), db_id))
            else:
                print("  -> 抓取失败。")
                cursor.execute("UPDATE intel_core SET crawl_status = ?, crawl_time = ? WHERE id = ?", 
                             ('failed', datetime.now(), db_id))
                conn.commit()
                continue # 不要用摘要研判，跳过该条
        else:
            print("  -> 已有正文，跳过抓取。")

        # 2. AI 研判 (仅当抓取成功)
        print("  -> AI 研判中...")
        context = full_text[:8000]
        analysis = ask_llm(client, title, context)
        
        is_relevant = 1 if analysis.get('is_relevant') else 0
        ai_reason = analysis.get('reason', 'N/A')
        ai_tags = ",".join(analysis.get('tags', []))
        
        cursor.execute('''
            UPDATE intel_core SET 
                is_relevant = ?, ai_reason = ?, ai_tags = ?, 
                process_status = 'processed', process_time = ?
            WHERE id = ?
        ''', (is_relevant, ai_reason, ai_tags, datetime.now(), db_id))
        conn.commit()
        
        icon = "✅" if is_relevant else "❌"
        print(f"  -> 结果: {icon} {ai_reason}")
        
        # 避免过快
        time.sleep(1)

def ask_llm(client, title, content):
    """调用 LLM 的封装"""
    prompt = f"""
    你是一个安全专家。判断以下情报是否与“AI Agent/LLM 的攻击、防御、漏洞、越狱、注入”高度相关。
    我们只关注：
    
    1. 针对 Agent/LLM 的具体攻击手法（如 Prompt Injection, Jailbreak, RCE）。
    2. Agent 框架（如 LangChain, AutoGen）的漏洞。
    3. 具体的安全事件或高价值的技术报告。
    
    请忽略：
    1. 纯粹的行业新闻（如某公司发布了新模型，但未提及安全特性）。
    2. 政策法规的泛泛而谈。
    3. 与安全技术无关的营销内容。
    
    情报标题: {title}
    情报正文: {content}

    请直接返回 JSON，格式如下:
    {{"is_relevant": true/false, "reason": "理由", "tags": ["标签1", "标签2"]}}
    """
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "system", "content": "你只输出 JSON。"}, {"role": "user", "content": prompt}]
        )
        text = response.choices[0].message.content.replace("```json", "").replace("```", "").strip()
        return json.loads(text)
    except Exception as e:
        print(f"      [!] LLM 错误: {e}")
        return {"is_relevant": False, "reason": "LLM Error", "tags": []}

# ================= 主程序 =================
def main():
    if not API_KEY:
        print("请设置环境变量 DASHSCOPE_API_KEY")
        return

    conn = init_new_db()
    client = OpenAI(api_key=API_KEY, base_url=BASE_URL)

    # 1. 同步数据
    stage_1_sync_md(conn)
    
    # 2. 自动处理流水线
    process_pending_intelligence(conn, client)

    conn.close()
    print("\n[√] 全部流程处理完毕！数据保存在 intelligence_v2.db")

if __name__ == "__main__":
    main()