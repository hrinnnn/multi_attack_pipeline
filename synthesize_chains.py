import sqlite3
import json
import textwrap
import os
from collections import defaultdict
from openai import OpenAI

# 配置 OpenAI 客户端 (同 extract_graph.py)
client = OpenAI(
    api_key=os.getenv("DASHSCOPE_API_KEY"), 
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
)

def synthesize_chain(atk, func, risk):
    """
    通过 LLM 对三元组进行逻辑验证并合成复现剧本
    """
    prompt = f"""
你是一位顶尖的 AI 安全专家。请根据以下提取出的图谱三元组（Attack, Functionality, Risk），验证其逻辑完整性并合成一个详细的**端到端攻击复现剧本**。

### 输入节点信息:
1. **Attack (攻击手段)**:
   - 标签: {atk['label']}
   - 技术细节: {atk['description']}

2. **Functionality (利用组件)**:
   - 标签: {func['label']}
   - 功能描述: {func['description']}

3. **Risk (风险后果)**:
   - 标签: {risk['label']}
   - 后果详述: {risk['description']}

### 任务要求:
1. **逻辑验证**: 判断该攻击手段是否真的能通过利用该组件功能导致该风险。如果逻辑不通（例如：攻击是针对邮件的，但组件是文件渲染器），请在 reason 中说明。
2. **场景合成**: 编写一段连贯、合乎技术逻辑的复现步骤。包含：准备阶段、触发向量、组件交互逻辑、最终提权/泄露路径。
3. **分值评定**: 给出一个 1-5 分的可复现性评分。

### 输出格式 (必须为纯 JSON):
{{
  "is_logical": true/false,
  "reason": "逻辑验证的理由",
  "exploit_narrative": "详细的复现剧本 (Markdown 格式)",
  "reproducibility_score": 1-5
}}
"""
    try:
        completion = client.chat.completions.create(
            model="qwen-plus",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"}
        )
        return json.loads(completion.choices[0].message.content)
    except Exception as e:
        print(f"Synthesis failed: {e}")
        return None

def init_verified_db(conn):
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS verified_scenarios (
            atk_id TEXT,
            func_id TEXT,
            risk_id TEXT,
            is_logical BOOLEAN,
            reason TEXT,
            exploit_narrative TEXT,
            reproducibility_score INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (atk_id, func_id, risk_id)
        )
    ''')
    conn.commit()

def export_report(conn, nodes):
    """
    从数据库读取已验证的场景并更新文本报告
    """
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM verified_scenarios WHERE is_logical = 1 ORDER BY reproducibility_score DESC")
    verified_rows = cursor.fetchall()
    
    import datetime
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("chains_verified.txt", "w", encoding="utf-8") as f:
        f.write("=== 高质量经过验证的攻击场景 (Verified Scenarios) ===\n")
        f.write(f"上次更新时间: {now_str}\n")
        f.write(f"Total Count: {len(verified_rows)}\n\n")
        for sc in verified_rows:
            atk_label = nodes.get(sc['atk_id'], {}).get('label', sc['atk_id'])
            risk_label = nodes.get(sc['risk_id'], {}).get('label', sc['risk_id'])
            func_label = nodes.get(sc['func_id'], {}).get('label', sc['func_id'])

            f.write(f"### [NEW DISCOVERY] {atk_label} -> {risk_label}\n")
            f.write(f"- **可复现性评分**: {'⭐' * (sc['reproducibility_score'] or 0)}\n")
            f.write(f"- **利用组件**: {func_label}\n")
            f.write(f"- **复现剧本**:\n{sc['exploit_narrative']}\n")
            f.write("-" * 80 + "\n\n")

    # 同时更新失败报告
    cursor.execute("SELECT * FROM verified_scenarios WHERE is_logical = 0")
    failed_rows = cursor.fetchall()
    with open("chains_failed_logic.txt", "w", encoding="utf-8") as f:
        f.write("=== 逻辑不匹配的剔除链条 (Rejected via Verification) ===\n\n")
        for sc in failed_rows:
            atk_label = nodes.get(sc['atk_id'], {}).get('label', sc['atk_id'])
            risk_label = nodes.get(sc['risk_id'], {}).get('label', sc['risk_id'])
            func_label = nodes.get(sc['func_id'], {}).get('label', sc['func_id'])
            f.write(f"Chain: {atk_label} --({func_label})--> {risk_label}\n")
            f.write(f"Reason: {sc['reason']}\n")
            f.write("-" * 50 + "\n")

def main():
    conn = sqlite3.connect('intelligence_v2.db', timeout=30)
    init_verified_db(conn)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 1. 加载所有节点
    cursor.execute("SELECT id, label, type, description FROM graph_nodes")
    nodes = {row['id']: dict(row) for row in cursor.fetchall()}

    # 2. 查找已合成的链条避免重复
    cursor.execute("SELECT atk_id, func_id, risk_id FROM verified_scenarios")
    processed = {(r['atk_id'], r['func_id'], r['risk_id']) for r in cursor.fetchall()}

    # 3. 寻找候选链 (New Discovered)
    cursor.execute("SELECT source, target, relation FROM graph_edges")
    edges = cursor.fetchall()

    cursor.execute("SELECT source, target, relation, source_ref FROM edge_evidence")
    ev_rows = cursor.fetchall()
    ev_map = defaultdict(lambda: {"refs": set()})
    for ev in ev_rows:
        ev_map[(ev['source'], ev['target'], ev['relation'])]["refs"].add(ev['source_ref'])

    func_uses = defaultdict(list)
    func_exposes = defaultdict(list)

    for edge in edges:
        s, t, r = edge['source'], edge['target'], edge['relation']
        refs = ev_map[(s, t, r)]["refs"]
        if r == 'utilizes': func_uses[t].append((s, refs))
        elif r == 'exposes': func_exposes[s].append((t, refs))

    candidates = []
    for f_id, attacks in func_uses.items():
        risks = func_exposes.get(f_id, [])
        for atk_id, atk_refs in attacks:
            for risk_id, risk_refs in risks:
                chain_key = (atk_id, f_id, risk_id)
                if chain_key not in processed:
                    if not (atk_refs & risk_refs): # New Discovery
                        candidates.append({
                            "atk": nodes[atk_id],
                            "func": nodes[f_id],
                            "risk": nodes[risk_id]
                        })

    print(f"Found {len(candidates)} NEW candidate chains for synthesis.")

    # 4. 逐条合成并实时保存
    for i, item in enumerate(candidates):
        print(f"[{i+1}/{len(candidates)}] Synthesizing: {item['atk']['label']} -> {item['risk']['label']}...")
        result = synthesize_chain(item['atk'], item['func'], item['risk'])
        
        if result:
            cursor.execute('''
                INSERT OR REPLACE INTO verified_scenarios 
                (atk_id, func_id, risk_id, is_logical, reason, exploit_narrative, reproducibility_score)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (item['atk']['id'], item['func']['id'], item['risk']['id'], 
                  result.get('is_logical'), result.get('reason'), 
                  result.get('exploit_narrative'), result.get('reproducibility_score')))
            conn.commit()
            
            # 实时更新报告
            export_report(conn, nodes)

    print(f"Done! Final reports updated.")

if __name__ == "__main__":
    main()
