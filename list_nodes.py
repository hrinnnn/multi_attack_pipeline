
import sqlite3
import textwrap

def list_nodes():
    DB_PATH = 'intelligence_v2.db'
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 按类型分组获取所有点
    # 类别通常为: attack_method, functionality, risk (或者 Prompt 中定义的分类)
    cursor.execute("SELECT id, label, type, description FROM graph_nodes ORDER BY type, id")
    nodes = cursor.fetchall()

    if not nodes:
        print("数据库中暂无节点数据。")
        return

    # 统计分类数据
    by_type = {}
    for node in nodes:
        ntype = node['type']
        if ntype not in by_type:
            by_type[ntype] = []
        by_type[ntype].append(node)

    print(f"=== 攻击图谱节点清单 (共 {len(nodes)} 个) ===\n")
    
    with open('node_summary.txt', 'w', encoding='utf-8') as f:
        f.write(f"=== 攻击图谱节点清单 (共 {len(nodes)} 个) ===\n\n")

        for ntype, nodeList in by_type.items():
            type_title = ntype.replace('_', ' ').title()
            category_header = f"【{type_title}】({len(nodeList)} 个)\n" + "=" * 40 + "\n"
            print(category_header, end="")
            f.write(category_header)
            
            for node in nodeList:
                label = node['label'] if node['label'] else node['id']
                node_line = f"- {label} ({node['id']})\n"
                print(node_line, end="")
                f.write(node_line)
                
                # 美化描述输出
                desc = node['description'] if node['description'] else "无描述"
                wrapped_desc = textwrap.fill(desc, width=80)
                indented_desc = textwrap.indent(wrapped_desc, "    ") + "\n\n"
                print(indented_desc, end="")
                f.write(indented_desc)
            
            print("\n")
            f.write("\n\n")

    print(f"结果已同步保存至: node_summary.txt")
    conn.close()

if __name__ == "__main__":
    list_nodes()
