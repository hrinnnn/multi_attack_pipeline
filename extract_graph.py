import sqlite3
import json
import os
from openai import OpenAI
from typing import List, Dict, Any
# 目前有batch_limit，
# 配置
DB_PATH = 'intelligence_v2.db'
API_KEY = os.getenv("DASHSCOPE_API_KEY")
BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
BATCH_LIMIT = 0  # 每次运行处理的最大条数，设为 0 表示无限制

client = OpenAI(api_key=API_KEY, base_url=BASE_URL)

def init_db(conn):
    """初始化数据库表"""
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS graph_nodes (
            id TEXT PRIMARY KEY,
            label TEXT,
            type TEXT NOT NULL,
            description TEXT,
            source_ref INTEGER
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS graph_edges (
            source TEXT NOT NULL,
            target TEXT NOT NULL,
            relation TEXT NOT NULL,
            PRIMARY KEY (source, target, relation),
            FOREIGN KEY (source) REFERENCES graph_nodes(id),
            FOREIGN KEY (target) REFERENCES graph_nodes(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS edge_evidence (
            source TEXT NOT NULL,
            target TEXT NOT NULL,
            relation TEXT NOT NULL,
            source_ref INTEGER NOT NULL,
            description TEXT,
            PRIMARY KEY (source, target, relation, source_ref),
            FOREIGN KEY (source, target, relation) REFERENCES graph_edges(source, target, relation)
        )
    ''')
    conn.commit()

def get_existing_nodes(cursor) -> str:
    """获取数据库中已存在的节点摘要，用于实体对齐"""
    try:
        cursor.execute("SELECT id, label, type FROM graph_nodes")
        nodes = cursor.fetchall()
    except sqlite3.OperationalError:
        return "无现有节点 (读取错误)"

    if not nodes:
        return "无现有节点。"
    
    # 优化：增加上下文数量，但精简格式
    # 格式: id(label)
    # 限制：取前 300 个节点，通常足够覆盖核心概念 # 有待斟酌
    node_list = [f"{row[0]}({row[1]})" for row in nodes[:300]]
    return ", ".join(node_list)

# 当existing_nodes_context过长时，需要截断，否则复杂度过高
def extract_graph_from_text(text: str, source_url: str): 
    """
    使用LLM从文本中提取图结构，同时进行图构建性检查
    """
    
    system_prompt = """
你是一个网络安全专家，负责构建"Agent攻击风险图谱"。
你的任务是从给定的情报文本中提取结构化的"攻击场景(Attack Scenarios)"。

### 1. 核心任务: 提取技术性攻击场景
每个场景必须通过以下三元组 (Star Topology) 描述一个完整的技术路径：
1.  **Attack (核心)**: 具体的攻击技术或手段。
    - **【硬性要求】**: 必须包含具体的**实现方法论 (Methodology)**。
	- 在节点的description中，你应该将attack方法的实现细节全部记录下来，必要时你可以将原文关于攻击具体方法的段落复制到description中
	- Description 可以非常长，必须要具体。如果原文没有具体的实现方法，请不要总结成attack节点。
    - **【禁令】**: 禁止提取宽泛的分类词（如 "Prompt Injection", "Data Leakage"）作为节点，除非文中详细描述了其实现步骤。
    - 示例: 提取 "Indirect Prompt Injection via SVG obfuscation" 而不是 "Prompt Injection"。
2.  **Functionality (利用点/手段)**: 攻击者利用了 Agent 的哪个具体技术组件？
    - **【推理与具象化】**: 若文中未直言组件名，必须基于技术常识推理。
    - **【推荐分类 (Taxonomy)】**: 
        - `System Prompt Store` (系统提示词存储)
        - `Input Sanitizer/Validator` (输入清洗/验证器)
        - `RAG Retriever` (RAG检索器)
        - `External Tool Connector` (外部工具连接器/MCP服务器)
        - `Model Parameter/Weights` (模型权重)
        - `Context Window Manager` (上下文窗口管理器)
        - `Output Filter/Parser` (输出过滤器/解析器)
        - `Sandboxed Executor` (代码沙箱执行器)
    - **【禁令】**: 严禁使用 "General Agent", "AI System" 等模糊词。
3.  **Risk (后果)**: 攻击最终造成的技术或业务风险状态。

### 2. 图构建性检查 (Graphability) - 严苛模式
只有满足以下条件的材料才被视为 `graphable: true`:
- 描述了具体的**利用路径** (Exploit Path)。
- 至少包含一个明确的**技术实现细节**（例如特定的攻击载荷格式、利用的特定协议缺陷、绕过逻辑等）。
- 如果仅是新闻播报、合规建议、或无细节的漏洞声明，请设为 `graphable: false`。

### 3. 边关系定义:
- `utilizes`: Attack -> Functionality (攻击利用了功能)
- `causes`: Attack -> Risk (攻击导致了风险)
- `exposes`: Functionality -> Risk (功能设计/缺陷暴露了风险)
- `escalates_to`: Risk -> Risk (风险引发进一步风险)

### 4. JSON 输出要求:
- 所有 `id` 必须为下划线命名 (snake_case)。
- `description` 必须详细描述**“它是如何工作的”**。
- 如果 `graphable` 为 false，`reason` 必须指明缺失的具体技术要素。

JSON 输出结构:
```json
{
  "graphable": true,
  "scenarios": [
    {
      "attack": { "id": "snake_case_id", "label": "中文名", "type": "Attack", "description": "详细实现步骤" },
      "functionality": { "id": "snake_case_id", "label": "中文名", "type": "Functionality", "description": "组件功能描述" },
      "risk": { "id": "snake_case_id", "label": "中文名", "type": "Risk", "description": "后果详细描述" },
      "details": "该特定场景的简要总结"
    }
  ],
  "additional_edges": [{"source": "id1", "target": "id2", "relation": "..."}]
}
```
"""

    user_prompt = f"情报来源: {source_url}\n\n情报内容:\n{text[:25000]}" 

    try:
        completion = client.chat.completions.create(
            model="qwen-plus",
            messages=[
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': user_prompt}
            ],
            response_format={"type": "json_object"}
        )
        return json.loads(completion.choices[0].message.content)
    except Exception as e:
        print(f"LLM提取失败: {e}")
        return None

def merge_node_descriptions(old_desc: str, new_desc: str) -> str:
    """
    使用 LLM 合并两个描述，使其更全面
    """
    if not old_desc:
        return new_desc
    if not new_desc or new_desc == old_desc:
        return old_desc
        
    # 如果描述很短，直接拼接
    if len(old_desc) + len(new_desc) < 200:
        return f"{old_desc}\n\n[补充]: {new_desc}"

    prompt = f"""
    请将以下两个关于同一个技术概念的描述合并为一个全面、准确、技术性强的描述。
    保留所有关键技术细节，去除重复信息。

    描述 1 (旧): {old_desc}
    描述 2 (新): {new_desc}

    请直接输出合并后的描述文本，不要包含任何前缀或解释。
    """
    try:
        completion = client.chat.completions.create(
            model="qwen-plus",
            messages=[
                {'role': 'user', 'content': prompt}
            ]
        )
        return completion.choices[0].message.content.strip()
    except Exception as e:
        print(f"    描述合并失败: {e}")
        return f"{old_desc}\n\n[补充]: {new_desc}"

def check_semantic_similarity(new_node: Dict[str, Any], candidates: List[Dict[str, Any]]) -> str:
    """
    使用 LLM 检查新节点是否与现有节点语义相同。
    如果相同，返回现有节点的 ID；否则返回 None。
    """
    if not candidates:
        return None
        
    # 构造候选列表字符串
    candidates_str = "\n".join([f"- ID: {c['id']}, Label: {c['label']}, Desc: {c['description'][:100]}..." for c in candidates])
    
    prompt = f"""
    我正在构建一个网络安全知识图谱。
    我有一个新提取的节点，我想知道它是否实际上是数据库中已存在的某个节点的同义词或重复项。
    
    新节点:
    ID: {new_node['id']}
    Label: {new_node['label']}
    Type: {new_node['type']}
    Description: {new_node.get('description', '')}
    
    现有节点候选列表:
    {candidates_str}
    
    判断逻辑:
    1. 如果新节点与某个现有节点在**核心语义**上完全一致（只是命名不同），请返回该现有节点的 ID。
    2. 如果新节点是一个全新的概念，或者虽然相似但有明显区别（例如具体的变种），请返回 "None"。
    
    请只返回 JSON 格式结果: {{"match_id": "existing_id_or_null"}}
    """
    
    try:
        completion = client.chat.completions.create(
            model="qwen-plus",
            messages=[
                {'role': 'user', 'content': prompt}
            ],
            response_format={"type": "json_object"}
        )
        result = json.loads(completion.choices[0].message.content)
        match_id = result.get("match_id")
        if match_id and match_id.lower() != "none":
            return match_id
        return None
    except Exception as e:
        print(f"    语义对齐检查失败: {e}")
        return None

def process_node(cursor, node, existing_nodes_dict, existing_nodes_by_type, id_mapping, intelligence_id):
    """
    处理单个节点的插入/更新/对齐逻辑
    """
    try:
        original_id = node['id']
        final_id = original_id
        new_desc = node.get('description', '')
        node_type = node['type']
        
        # 1. 检查是否直接存在 (Exact Match)
        if original_id in existing_nodes_dict:
            final_id = original_id
            old_desc = existing_nodes_dict[final_id]['description']
            if new_desc and new_desc != old_desc:
                # 简单拼接 merge，避免太频繁调用LLM
                merged_desc = merge_node_descriptions(old_desc, new_desc)
                cursor.execute("UPDATE graph_nodes SET description = ? WHERE id = ?", (merged_desc, final_id))
                existing_nodes_dict[final_id]['description'] = merged_desc
        
        else:
            # 2. 语义对齐检查 (Semantic Match)
            candidates = existing_nodes_by_type.get(node_type, [])
            match_id = check_semantic_similarity(node, candidates)
            
            if match_id and match_id in existing_nodes_dict:
                print(f"    [Semantic Match] '{original_id}' -> '{match_id}'")
                final_id = match_id
                # 合并描述
                old_desc = existing_nodes_dict[final_id]['description']
                if new_desc:
                    merged_desc = merge_node_descriptions(old_desc, new_desc)
                    cursor.execute("UPDATE graph_nodes SET description = ? WHERE id = ?", (merged_desc, final_id))
                    existing_nodes_dict[final_id]['description'] = merged_desc
            else:
                # 3. 确认为新节点，插入
                print(f"    [New Node] 插入: {final_id}")
                cursor.execute('''
                    INSERT INTO graph_nodes (id, label, type, description, source_ref)
                    VALUES (?, ?, ?, ?, ?)
                ''', (final_id, node['label'], node['type'], new_desc, intelligence_id))
                
                # 更新内存缓存
                node_info = {"id": final_id, "label": node['label'], "type": node_type, "description": new_desc}
                if node_type not in existing_nodes_by_type:
                    existing_nodes_by_type[node_type] = []
                existing_nodes_by_type[node_type].append(node_info)
                existing_nodes_dict[final_id] = node_info

        # 记录映射关系
        id_mapping[original_id] = final_id
        return final_id
            
    except Exception as e:
        print(f"    处理节点错误 {node.get('id')}: {e}")
        return original_id

def insert_edge(cursor, source, target, relation, description, intelligence_id):
    """
    插入边及证据，处理多源支持
    """
    try:
        # 1. 插入或忽略逻辑边
        cursor.execute('''
            INSERT OR IGNORE INTO graph_edges (source, target, relation)
            VALUES (?, ?, ?)
        ''', (source, target, relation))
        
        # 2. 插入具体的证据记录 (支持多源)
        cursor.execute('''
            INSERT OR IGNORE INTO edge_evidence (source, target, relation, source_ref, description)
            VALUES (?, ?, ?, ?, ?)
        ''', (source, target, relation, intelligence_id, description))
        
    except Exception as e:
        print(f"    插入边/证据失败 {source}->{target}: {e}")

def save_graph_data(conn, data, source_url, intelligence_id):
    cursor = conn.cursor()
    
    if not data.get("graphable", False):
        reason = data.get('reason', '无原因')
        print(f"  -> 跳过 (不可图化): {reason}")
        cursor.execute("UPDATE intel_core SET extraction_status = 'skipped' WHERE id = ?", (intelligence_id,))
        conn.commit()
        return

    scenarios = data.get("scenarios", [])
    additional_edges = data.get("additional_edges", [])
    
    print(f"  -> 提取: {len(scenarios)} 场景, {len(additional_edges)} 额外边")

    # 预加载所有现有节点
    cursor.execute("SELECT id, label, type, description FROM graph_nodes")
    all_existing_nodes = cursor.fetchall()
    existing_nodes_by_type = {}
    existing_nodes_dict = {} 
    
    for row in all_existing_nodes:
        nid, nlabel, ntype, ndesc = row
        if ntype not in existing_nodes_by_type:
            existing_nodes_by_type[ntype] = []
        node_info = {"id": nid, "label": nlabel, "type": ntype, "description": ndesc}
        existing_nodes_by_type[ntype].append(node_info)
        existing_nodes_dict[nid] = node_info

    id_mapping = {}

    # 1. 处理 Scenarios (节点 + 核心边)
    for scenario in scenarios:
        # 提取并在必要时创建节点
        attack_node = scenario.get('attack')
        func_node = scenario.get('functionality')
        risk_node = scenario.get('risk')
        
        if not (attack_node and func_node and risk_node):
            print("    [Warn] 跳过不完整的 Scenario")
            continue

        # 处理节点 (并获取对齐后的ID)
        atk_id = process_node(cursor, attack_node, existing_nodes_dict, existing_nodes_by_type, id_mapping, intelligence_id)
        func_id = process_node(cursor, func_node, existing_nodes_dict, existing_nodes_by_type, id_mapping, intelligence_id)
        risk_id = process_node(cursor, risk_node, existing_nodes_dict, existing_nodes_by_type, id_mapping, intelligence_id)

        # 核心关系 1: Attack -> utilizes -> Functionality
        insert_edge(cursor, atk_id, func_id, 'utilizes', scenario.get('details', ''), intelligence_id)
        
        # 核心关系 2: Attack -> causes -> Risk
        insert_edge(cursor, atk_id, risk_id, 'causes', scenario.get('details', ''), intelligence_id)

    # 2. 处理 Additional Edges
    for edge in additional_edges:
        # 兼容性处理：LLM有时会用 type 代替 relation
        relation = edge.get('relation') or edge.get('type')
        if not relation:
            print(f"    [Warn] 跳过格式错误的边 (缺少 relation/type): {edge}")
            continue

        src = id_mapping.get(edge['source'], edge['source'])
        dst = id_mapping.get(edge['target'], edge['target'])
        
        # 简单的边验证
        if src in existing_nodes_dict and dst in existing_nodes_dict:
             insert_edge(cursor, src, dst, relation, edge.get('description', ''), intelligence_id)
        else:
             print(f"    [Warn] 跳过额外边 {src}->{dst}: 节点未找到")

    # 更新状态为已提取
    cursor.execute("UPDATE intel_core SET extraction_status = 'extracted' WHERE id = ?", (intelligence_id,))
    conn.commit()

def main():
    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
    cursor = conn.cursor()

    # 获取已完成 AI 研判且相关的待处理情报 (intel_core 表)
    # 只处理 is_relevant=1 且 extraction_status 为 'pending' 的数据
    cursor.execute("SELECT id, url, full_text FROM intel_core WHERE is_relevant=1 AND process_status='processed' AND extraction_status='pending'")
    rows = cursor.fetchall()

    print(f"找到 {len(rows)} 条待处理情报...")
    
    # 限制处理条数
    if BATCH_LIMIT > 0:
        rows = rows[:BATCH_LIMIT]
        print(f"  -> 根据设置，本次仅处理前 {BATCH_LIMIT} 条。")

    for i, row in enumerate(rows):
        db_id, url, content = row
        print(f"\n[{i+1}/{len(rows)}] 正在处理 [{db_id}] {url} ...")
        
        # 优化文本截取策略: Head-Tail Straddle
        # 目的是保留文章的开头（简介/核心逻辑）和结尾（结论/修复建议）
        # Qwen-Plus 支持 30k+ tokens，这里设置约 60k 字符的上限以确保完整性
        if len(content) > 60000:
            head = content[:35000]
            tail = content[-25000:]
            content_to_process = head + "\n\n[... content truncated for length ...]\n\n" + tail
            print(f"  -> 内容非常长 ({len(content)} 字符)，激活大容量 Head-Tail 截取策略 (35k+25k)")
        else:
            content_to_process = content
        
        # 1. 获取当前已有的节点上下文 
        # (已移除：不再需要在Prompt中包含现有节点，改用Post-process对齐)
        # existing_nodes_context = get_existing_nodes(cursor)
        
        # 2. 调用LLM提取
        result = extract_graph_from_text(content_to_process, url)
        
        # 3. 存入数据库并更新状态
        if result:
            save_graph_data(conn, result, url, db_id)
        else:
            # 如果LLM调用失败，暂时不更新状态，以便重试，或者标记为 error
            print("  -> LLM调用失败，跳过本次更新")

    conn.close()

if __name__ == "__main__":
    main()
