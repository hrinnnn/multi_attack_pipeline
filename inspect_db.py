import sqlite3
import pandas as pd

# 设置 pandas 显示选项，防止内容被截断
pd.set_option('display.max_colwidth', 50)
pd.set_option('display.width', 1000)

def inspect_results():
    conn = sqlite3.connect("agent_intelligence.db")
    
    # 1. 统计概况
    print("=== 📊 数据概况 ===")
    try:
        total = conn.execute("SELECT count(*) FROM filtered_intelligence").fetchone()[0]
        relevant = conn.execute("SELECT count(*) FROM filtered_intelligence WHERE is_relevant = 1").fetchone()[0]
        print(f"总情报数: {total}")
        print(f"高价值(相关)情报数: {relevant}")
        if total > 0:
            print(f"筛选率: {relevant/total*100:.1f}%")
        else:
            print("筛选率: N/A (无数据)")
        print("-" * 50)

        # 2. 查看前 10 条高价值情报
        print("\n=== 🏆 高价值情报示例 (Top 10) ===")
        query = """
        SELECT id, date, title, tags, relevance_reason 
        FROM filtered_intelligence 
        WHERE is_relevant = 1 
        ORDER BY date DESC 
        LIMIT 10
        """
        df = pd.read_sql_query(query, conn)
        
        if not df.empty:
            print(df)
        else:
            print("⚠️ 没有找到相关情报，请检查 LLM 的筛选逻辑或原始数据。")
            
    except sqlite3.OperationalError as e:
        print(f"数据库查询错误: {e}")
        print("可能数据库表尚未创建或为空。")

    conn.close()

if __name__ == "__main__":
    inspect_results()
