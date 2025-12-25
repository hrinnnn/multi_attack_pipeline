
import sqlite3

def reset_graph():
    DB_PATH = 'intelligence_v2.db'
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    print(f"正在重置数据库: {DB_PATH}")

    try:
        # 1. 清空图谱数据表
        cursor.execute("DELETE FROM graph_nodes")
        cursor.execute("DELETE FROM graph_edges")
        cursor.execute("DELETE FROM edge_evidence")
        print("- 已清空 graph_nodes, graph_edges 和 edge_evidence 表。")

        # 2. 重置情报主表的提取状态
        # 将所有已提取(extracted)或跳过(skipped)的状态重置为待处理(pending)
        cursor.execute("UPDATE intel_core SET extraction_status = 'pending'")
        print("- 已将所有情报的 extraction_status 重置为 'pending'。")

        conn.commit()
        print("\n重置成功！您可以重新运行 extract_graph.py 来构建新图谱。")

    except sqlite3.OperationalError as e:
        print(f"\n[错误] 数据库操作失败: {e}")
        print("请确保数据库表结构正确，且没有其他程序正在占用数据库。")
    
    finally:
        conn.close()

if __name__ == "__main__":
    confirm = input("确定要清空所有图谱数据并重置提取状态吗？(y/n): ")
    if confirm.lower() == 'y':
        reset_graph()
    else:
        print("操作已取消。")
