import sqlite3
import os

# 获取脚本所在目录，计算数据库绝对路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, '../intelligence_v2.db')

def list_nodes():
    if not os.path.exists(DB_PATH):
        print(f"Error: Database not found at {DB_PATH}")
        return

    # 添加 timeout 以防数据库锁冲突
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 根据数据库实际 schema 获取节点：id, label, type, description, origin
    try:
        cursor.execute("SELECT id, label, type, origin FROM graph_nodes ORDER BY type")
        nodes = cursor.fetchall()
    except sqlite3.OperationalError as e:
        print(f"Database error: {e}")
        conn.close()
        return
    
    if not nodes:
        print("No nodes found in the database.")
        conn.close()
        return

    # 按类型分组
    nodes_by_type = {}
    for node in nodes:
        node_type = node['type']
        if node_type not in nodes_by_type:
            nodes_by_type[node_type] = []
        nodes_by_type[node_type].append(node)
    
    print(f"--- Graph Nodes (Total: {len(nodes)}) ---")
    for node_type in sorted(nodes_by_type.keys()):
        print(f"\n[{node_type.upper()}] nodes:")
        for node in nodes_by_type[node_type]:
            # origin 标记
            origin_tag = f" [augmented]" if node['origin'] == 'augmented' else ""
            print(f"  - {node['label']} (ID: {node['id']}){origin_tag}")
            
    conn.close()

if __name__ == "__main__":
    list_nodes()
