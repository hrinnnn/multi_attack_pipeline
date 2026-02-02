# Scenario 数据结构与智能提取实现方案（最新版）

## 数据结构设计

### 1. chains 表：Chain 作为一等公民

```sql
CREATE TABLE chains (
    id TEXT PRIMARY KEY,              -- 例如 "chain_pdf_rag_bypass"
    attack_id TEXT NOT NULL,          -- → graph_nodes.id (type=Attack)
    func_id TEXT NOT NULL,            -- → graph_nodes.id (type=Func)
    risk_id TEXT NOT NULL,            -- → graph_nodes.id (type=Risk)
    source_type TEXT,                 -- 'existing' 或 'discovered'
    source_refs TEXT,                 -- JSON数组，来源情报ID列表
    reproducibility_score INTEGER,    -- 可复现性评分 1-5
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(attack_id, func_id, risk_id),
    FOREIGN KEY (attack_id) REFERENCES graph_nodes(id),
    FOREIGN KEY (func_id) REFERENCES graph_nodes(id),
    FOREIGN KEY (risk_id) REFERENCES graph_nodes(id)
);
```

### 2. scenarios 表：用 JSON 存储步骤序列

```sql
CREATE TABLE scenarios (
    id TEXT PRIMARY KEY,              -- 例如 "scenario_zero_click_exfil"
    name TEXT NOT NULL,               -- 人类可读名称
    description TEXT,                 -- 场景描述
    steps_json TEXT NOT NULL,         -- JSON数组：步骤序列
    final_state TEXT,                 -- 最终状态描述
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## 智能提取升级 (Phase 5)

### 1. 核心概念重定义
Prompt 中明确指示模型根据情报粒度灵活输出：
- **Atomic Chain (原子链)**: 单步攻击，必须包含完整的 **Attack-Func-Risk 三角关系**。
  - `Attack` 利用 `Functionality` (`utilizes`)
  - `Attack` 导致 `Risk` (`causes`)
  - `Functionality` 暴露 `Risk` (`exposes`)
- **Complex Scenario (复合场景)**: 包含时序关系的多个步骤。
  - 每个步骤本质上是一个 Atomic Chain。
  - 步骤间通过状态（State）逻辑连接。

### 2. JSON 输出结构
```json
{
  "graphable": true,
  "atomic_chains": [
    { "attack": "...", "functionality": "...", "risk": "..." }
  ],
  "complex_scenarios": [
    {
      "name": "...",
      "steps": [
        {
          "order": 1,
          "chain": { "attack": "...", "functionality": "...", "risk": "..." },
          "resulting_state": "..."
        }
      ]
    }
  ]
}
```

### 3. 严格边验证逻辑 (Strict Validator)
代码中将实施**白名单机制**，严厉拒绝不符合定义的边：

| 关系 (Relation) | 源节点类型 (From) | 目标节点类型 (To) | 语义解释 |
|---|---|---|---|
| `utilizes` | **Attack** | **Functionality** | 攻击技术利用了组件的功能特性或漏洞 |
| `causes` | **Attack** | **Risk** | 攻击技术直接导致了某种后果 |
| `exposes` | **Functionality** | **Risk** | 组件的设计缺陷或特性暴露了某种风险面 |

> **注意**: 
> - 每一个 Atomic Chain **必须** 包含这三条边。
> - `scenarios` 中的步骤连接隐含在 `order` 中，**不**在 `graph_edges` 表中创建物理边。

---

## 文件修改计划
1. **`extract_graph.py`**: 更新 System Prompt，增加输出校验逻辑，更新 `save_graph_data` 以支持 `atomic_chains` 和 `complex_scenarios` 的自动落库。
2. **`manage_scenarios.py`**: 增强查询功能，确保同时支持 Scenario 和底层 Chain 的检索。
