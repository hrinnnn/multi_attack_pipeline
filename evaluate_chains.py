
import sqlite3
import json
import os
import time
from openai import OpenAI

# Configuration
DB_PATH = 'intelligence_v2.db'
API_KEY = os.getenv("DASHSCOPE_API_KEY")
BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
MODEL_NAME = "qwen-max"  # Updated to qwen-max
BATCH_LIMIT = 50 

client = OpenAI(api_key=API_KEY, base_url=BASE_URL)

SYSTEM_PROMPT = """
你是一个拥有20年实战经验的高级红队专家。你的任务是对 "Atomic Attack Chain" 进行可行性初筛。

**核心准则**:
我们不需要攻击链必须包含代码。但你必须进行 **Reality Check (深层事实核查)**。
不仅仅看文字逻辑是否通顺，更要用你的专家知识判断：**这种攻击路径在现在的 LLM 技术栈中真的存在吗？还是完全臆想出来的伪科学？**

**评分标准 (1-10)**:
- [1-3 分] Infeasible: **纯废话**。例："利用 AI 弱点攻击"。Reason: 没说具体怎么攻击。
- [4-6 分] Infeasible: **技术幻觉/逻辑硬伤**。例："通过 SQL 注入直接修改 LLM 的神经网络权重"。Reason: 描述很具体，但技术原理上完全行不通（数据库漏洞打不到模型权重），属于一本正经的胡说八道。
- [7-8 分] Feasible: **理论可行 (Theoretically Sound)**。例："利用隐藏字符污染 RAG 索引"。Reason: 符合当前 LLM 安全研究的已知攻击面（如 Data Poisoning），虽然没给具体 POC，但作为专家你确认这在技术上是绝对可行的。
- [9-10分] Feasible: **业界实锤 (Battle Tested)**。例："在 PDF 附件中嵌入 <|system|> 标签"。Reason: 这是一个被广为验证的经典 Indirect Prompt Injection 手法，成功率极高，几乎肯定能复现。

**输出 JSON**:
{
  "score": integer (1-10),
  "reason": "简短的中肯评价。如果给低分，请无情地指出其技术谬误；如果给高分，请确认该攻击手法的技术真实性。"
}
"""

USER_PROMPT_TEMPLATE = """
请评估以下新发现的攻击链的可复现性：

[攻击链结构]
1. 攻击技术: {attack_label}
   - 描述: {attack_desc}
2. 目标组件: {func_label}
   - 描述: {func_desc}
3. 潜在风险: {risk_label}
   - 描述: {risk_desc}
   
请返回 JSON 格式结果。
"""

def get_connection():
    return sqlite3.connect(DB_PATH)

def fetch_chains_to_evaluate(limit=0):
    conn = get_connection()
    cursor = conn.cursor()
    # Fetch chains that have not been scored yet (checking if evaluation_reason lacks '[Score:')
    # Or just re-evaluate all discovered chains for this pass?
    # Let's re-eval all discovered chains since we changed the logic.
    query = """
        SELECT 
            c.id, 
            a.label as attack, a.description as atk_desc,
            f.label as func, f.description as func_desc,
            r.label as risk, r.description as risk_desc
        FROM chains c
        JOIN graph_nodes a ON c.attack_id = a.id
        JOIN graph_nodes f ON c.func_id = f.id
        JOIN graph_nodes r ON c.risk_id = r.id
        WHERE c.source_type = 'discovered'
    """
    if limit > 0:
        query += f" LIMIT {limit}"
        
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return rows

def evaluate_chain(chain_row):
    cid, atk, atk_d, func, func_d, risk, risk_d = chain_row
    
    prompt = USER_PROMPT_TEMPLATE.format(
        attack_label=atk, attack_desc=atk_d,
        func_label=func, func_desc=func_d,
        risk_label=risk, risk_desc=risk_d
    )
    
    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {'role': 'system', 'content': SYSTEM_PROMPT},
                {'role': 'user', 'content': prompt}
            ],
            response_format={"type": "json_object"}
        )
        content = completion.choices[0].message.content
        return json.loads(content)
    except Exception as e:
        print(f"Error evaluating chain {cid}: {e}")
        return None

def update_chain_eval(cid, result):
    conn = get_connection()
    cursor = conn.cursor()
    
    score = result.get('score', 0)
    reason = result.get('reason', '')
    
    # Map score to category for reproducibility_level
    if score >= 7:
        repro_level = "High" # Using High/Medium/Low legacy field to store Feasible (High) vs Infeasible (Low)
    elif score >= 4:
        repro_level = "Medium"
    else:
        repro_level = "Low"
        
    # Store Score in the reason field text for visibility
    formatted_reason = f"[Score: {score}/10] {reason}"
    
    cursor.execute("""
        UPDATE chains 
        SET reproducibility_level = ?,
            evaluation_reason = ?
        WHERE id = ?
    """, (repro_level, formatted_reason, cid))
    
    conn.commit()
    conn.close()

def generate_reports():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Stats
    cursor.execute("SELECT reproducibility_level, COUNT(*) FROM chains WHERE source_type='discovered' AND reproducibility_level IS NOT NULL GROUP BY reproducibility_level")
    stats = dict(cursor.fetchall())
    total = sum(stats.values())
    
    with open("chain_evaluation_stats.md", "w", encoding="utf-8") as f:
        f.write("# 攻击链质量统计分析报告 (v2)\n\n")
        f.write(f"**评估总数**: {total}\n\n")
        f.write("## 质量分布\n")
        for level in ['High', 'Medium', 'Low']:
            count = stats.get(level, 0)
            percent = (count / total * 100) if total > 0 else 0
            f.write(f"- **{level}**: {count} 条 ({percent:.1f}%)\n")

    # Feasible Chains Report
    cursor.execute("""
        SELECT c.id, 
               a.label as attack, 
               c.evaluation_reason
        FROM chains c
        JOIN graph_nodes a ON c.attack_id = a.id
        WHERE c.reproducibility_level IN ('High', 'Medium')
        ORDER BY c.reproducibility_level DESC
    """)
    chains = cursor.fetchall()
    
    with open("feasible_chains.md", "w", encoding="utf-8") as f:
        f.write("# Feasible Attack Chains (Score >= 4)\n\n")
        for row in chains:
            cid, label, reason = row
            f.write(f"### {label}\n")
            f.write(f"**ID**: `{cid}`\n")
            f.write(f"**Evaluation**: {reason}\n")
            f.write("---\n")
            
    conn.close()
    print(f"Reports generated: chain_evaluation_stats.md, feasible_chains.md")

def main():
    print("Fetching discovered chains...")
    chains = fetch_chains_to_evaluate(BATCH_LIMIT)
    print(f"Found {len(chains)} chains to evaluate.")
    
    for i, chain in enumerate(chains):
        print(f"[{i+1}/{len(chains)}] Evaluating {chain[0]}...")
        result = evaluate_chain(chain)
        if result:
            update_chain_eval(chain[0], result)
            print(f"  -> Score {result.get('score')}: {result.get('reason')}")
        time.sleep(0.5) 
        
    generate_reports()

if __name__ == "__main__":
    main()

