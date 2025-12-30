import sqlite3
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

def visualize():
    print("正在生成图谱可视化...")
    conn = sqlite3.connect('intelligence_v2.db')
    cursor = conn.cursor()

    # Fetch nodes
    cursor.execute("SELECT id, type, label FROM graph_nodes")
    nodes = cursor.fetchall()

    # Fetch edges
    # 过滤掉 'exposes' 边，复刻 agent_attack_graph_no_exposes.png 的风格
    cursor.execute("SELECT source, target, relation FROM graph_edges WHERE relation != 'exposes'")
    edges = cursor.fetchall()

    conn.close()

    if not nodes:
        print("数据库中没有节点，无法绘图。")
        return

    G = nx.DiGraph()

    # Define colors (Matching the provided image style)
    type_color_map = {
        'Attack': '#90ee90',       # Light Green (Attack)
        'Functionality': '#add8e6', # Light Blue (Functionality)
        'Risk': '#fa8072'          # Salmon (Risk)
    }
    
    # Edge colors
    edge_color_map = {
        'utilizes': '#d62728',     # Red
        'causes': '#9467bd',       # Purple
        'exposes': '#1f77b4',      # Blue (Filtered out currently)
        'escalates_to': '#ff7f0e'  # Orange
    }
    
    # Add nodes
    labels = {}
    for node_id, node_type, node_label in nodes:
        # Use label if available, else ID, truncate if too long
        display_label = node_label if node_label else node_id
        if len(display_label) > 20:
            display_label = display_label[:18] + "..."
            
        G.add_node(node_id, type=node_type, label=display_label)
        labels[node_id] = display_label

    # Add edges
    for source, target, relation in edges:
        if source in G.nodes and target in G.nodes:
            G.add_edge(source, target, label=relation)

    # Prepare node colors list in order of G.nodes()
    node_colors = []
    for node in G.nodes():
        node_type = G.nodes[node].get('type', 'Unknown')
        node_colors.append(type_color_map.get(node_type, '#cccccc'))

    # Setup plot
    plt.figure(figsize=(24, 18))
    
    # 设置中文字体 (尝试适配 macOS 和 Windows)
    plt.rcParams['font.sans-serif'] = ['Arial Unicode MS', 'SimHei', 'PingFang SC', 'Heiti TC', 'sans-serif']
    plt.rcParams['axes.unicode_minus'] = False
    
    # Layout algorithm: Layered Layout
    # Top: Risk, Middle: Attack, Bottom: Functionality
    pos = {}
    
    # Group nodes by type
    risks = [n for n in G.nodes() if G.nodes[n].get('type') == 'Risk']
    attacks = [n for n in G.nodes() if G.nodes[n].get('type') == 'Attack']
    funcs = [n for n in G.nodes() if G.nodes[n].get('type') == 'Functionality']
    
    # Helper to distribute nodes evenly on X axis
    def set_layer_pos(nodes, y_level):
        if not nodes: return
        width = len(nodes)
        for i, node in enumerate(nodes):
            # Normalize x to be between -1 and 1 (or similar range)
            # If only 1 node, place at 0
            if width == 1:
                x = 0.5
            else:
                x = (i + 0.5) / width
            pos[node] = (x, y_level)

    set_layer_pos(risks, 2.0)   # Top
    set_layer_pos(attacks, 1.0) # Middle
    set_layer_pos(funcs, 0.0)   # Bottom
    
    # Draw nodes
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=3000, alpha=0.9, edgecolors='white', linewidths=2)
    
    # Draw edges with specific colors
    edge_colors = []
    for u, v in G.edges():
        rel = G.edges[u, v].get('label', '')
        edge_colors.append(edge_color_map.get(rel, 'gray'))

    nx.draw_networkx_edges(G, pos, width=2.0, alpha=0.7, arrowsize=25, arrowstyle='-|>', 
                           connectionstyle="arc3,rad=0.1", edge_color=edge_colors)
    
    # Draw node labels
    # Wrap labels for better display
    import textwrap
    wrapped_labels = {k: '\n'.join(textwrap.wrap(v, width=10)) for k, v in labels.items()}
    nx.draw_networkx_labels(G, pos, wrapped_labels, font_size=9, font_weight="bold", font_family='sans-serif')
    
    # Draw edge labels (Optional: might be too cluttered in layered view, let's keep it but make it smaller)
    edge_labels = nx.get_edge_attributes(G, 'label')
    # nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=7, font_color='black', label_pos=0.3)

    # Add Legend
    legend_patches = [
        mpatches.Patch(color='#fa8072', label='Risk (风险)'),
        mpatches.Patch(color='#90ee90', label='Attack (攻击)'),
        mpatches.Patch(color='#add8e6', label='Functionality (功能)'),
        mpatches.Patch(color='#d62728', label='Utilizes (利用)'),
        mpatches.Patch(color='#9467bd', label='Causes (导致)')
    ]
    plt.legend(handles=legend_patches, loc='upper left', fontsize=14, title="Legend", bbox_to_anchor=(0, 1))

    plt.title("Agent Attack Risk Graph (Layered View)", fontsize=24)
    plt.axis('off')
    
    output_file = "agent_attack_graph_layered.png"
    plt.savefig(output_file, format="PNG", dpi=300, bbox_inches='tight')
    print(f"图谱可视化已保存至: {output_file}")

if __name__ == "__main__":
    visualize()
