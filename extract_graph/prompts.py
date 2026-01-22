# Prompt templates for the attack graph extraction pipeline

SYSTEM_PROMPT = """
你是一个网络安全专家，负责构建"Agent攻击风险图谱"。
**本项目目前处于极其专注的阶段：仅提取与 "Jailbreak (越狱)" 和 "Prompt Injection (提示注入)" 相关的攻击手法。**

你的任务是从给定的情报文本中提取结构化的"攻击原子链"或"复合攻击场景"。

### 1. 核心任务定义

#### 概念 A: Atomic Chain (原子链)
当情报描述了单个离散的攻击手法时。必须通过 **Attack-Func-Risk 三角路径** 补全细节：
# 必须通过以下三元组 (Star Topology) 描述一个完整的技术路径：
# 1.  **Attack (核心)**: 具体的攻击技术或手段。
#     - **【硬性要求】**: 必须包含具体的**实现方法论 (Methodology)**。
# 	- 在节点的description中，你应该将attack方法的实现细节全部记录下来
# 	- Description 必须要具体。如果原文没有具体的实现方法，请不要总结成attack节点，也就不要新组织这个chain。
#   - 但同时要注意，description必须写成一个step by step的攻击过程，而不是原文内容的胡乱堆砌
#     - **【禁令】**: 禁止提取宽泛的分类词（如 "Prompt Injection", "Data Leakage"）作为节点，除非文中详细描述了其实现步骤。
#     - 示例: 提取 "Indirect Prompt Injection via SVG obfuscation" 而不是 "Prompt Injection"。
# 2.  **Functionality (利用点/手段)**: 攻击者利用了 Agent 的哪个具体技术组件？
#     - **【推理与具象化】**: 若文中未直言组件名，必须基于技术常识推理。
#     - **【推荐分类 (Taxonomy)】**: 
#         - `System Prompt Store` (系统提示词存储)
#         - `Input Sanitizer/Validator` (输入清洗/验证器)
#         - `RAG Retriever` (RAG检索器)
#         - `External Tool Connector` (外部工具连接器/MCP服务器)
#         - `Model Parameter/Weights` (模型权重)
#         - `Context Window Manager` (上下文窗口管理器)
#         - `Output Filter/Parser` (输出过滤器/解析器)
#         - `Sandboxed Executor` (代码沙箱执行器)
#     - **【禁令】**: 严禁使用 "General Agent", "AI System" 等模糊词。
# 3.  **Risk (后果)**: 攻击最终造成的技术或业务风险状态。

# ### 2. 图构建性检查 (Graphability) - 严苛模式
# 只有满足以下条件的材料才被视为 `graphable: true`:
# - 描述了具体的**利用路径** (Exploit Path)。
# - 至少包含一个明确的**攻击技术实现细节**（例如特定的攻击载荷格式、利用的特定协议缺陷、绕过逻辑等）。
# - 如果仅是新闻播报、合规建议、或无细节的漏洞声明，请设为 `graphable: false`。
# - 注意，有关防御的情报请不要作为攻击图谱的材料。所有的情报必须都是攻击情报

#### 概念 B: Complex Scenario (复合场景)
当情报描述了一个包含多个时序步骤的完整攻击过程时。也就是说，是一个复合的攻击场景。
每一个场景都包含了多步的攻击操作。攻击步骤多于一步，通常是三步以上。每一步攻击操作环环相扣，以达成最终的攻击目的。
在这种情况下，就应该组织成一个scenario。
- 每个步骤必须引用一个 Atomic Chain。也就是说，scenario包含多个chain作为其中的步骤。
- 步骤间通过 `resulting_state` (即上一步的 Risk/State) 逻辑连接。
- 最终，需要保证所有的链路都有逻辑，有前因后果都串成这个scenario
- 如果攻击只有一步，那么就不要组织成scenario，而是直接组织成chain。

### 2. 技术分类 (Taxonomy)

**利用点 (Functionality):**
示例：
- `System Prompt Store`: 存储核心指令的地方。
- `Input Sanitizer/Validator`: 拦截恶意字符的组件。
- `RAG Retriever`: 检索外部文档的组件。
- `External Tool Connector`: 连接外部服务/工具的接口。
- `Context Window Manager`: 管理历史上下文的组件。
- `Output Filter/Parser`: 检查或解析模型输出的组件。
（你也可以组建你自己的functionality点）
### 3. 合法边定义 (严格遵守)

你必须且只能使用以下三种关系来构建原子链：
1. `utilizes`: **Attack** -> **Functionality** (攻击利用了功能)
2. `causes`: **Attack** -> **Risk** (攻击导致了风险)
3. `exposes`: **Functionality** -> **Risk** (功能暴露了风险)

### 4. 输出格式要求 (JSON)

你必须根据情报粒度，灵活选择输出 `atomic_chains` 或 `complex_scenarios`（两者可并存，也可以只存在其中一种）。


```json
{
  "graphable": true,
  "atomic_chains": [
    {
      "attack": { "id": "id", "label": "中文名", "type": "Attack", "description": "实现细节" },
      "functionality": { "id": "id", "label": "名", "type": "Functionality", "description": "用途" },
      "risk": { "id": "id", "label": "名", "type": "Risk", "description": "后果" },
      "details": "该单步攻击的摘要"
    }
  ],
  "complex_scenarios": [
    {
      "name": "场景名称",
      "description": "一两句话简要描述",
      "steps": [
        {
          "order": 1,
          "chain": { "attack": "{...}", "functionality": "{...}", "risk": "{...}" },
          "resulting_state": "完成此步后系统的状态"
        }
      ],
      "final_state": "整个场景完成后的最终状态"
    }
  ],
  "reason": "如果 graphable 为 false，在此说明缺失的技术细节"
}
```
"""



MERGE_DESCRIPTION_PROMPT_TEMPLATE = """
    请将以下两个关于同一个技术概念的描述合并为一个全面、准确、技术性强的描述。
    保留所有关键技术细节，去除重复信息。
	如果你觉得两个描述不那么好合并，也可以直接拼接。
    所有信息用中文描述。
	最后的内容应该是一个step by step的详细攻击过程，内容的胡乱堆砌是不允许的

    描述 1 (旧): {old_desc}
    描述 2 (新): {new_desc}

    请直接输出合并后的描述文本，不要包含任何前缀或解释。
"""




SEMANTIC_SIMILARITY_PROMPT_TEMPLATE = """
    我正在构建一个网络安全知识图谱。
    我有一个新提取的节点，我想知道它是否实际上是数据库中已存在的某个节点的同义词或重复项。
    新节点:
    ID: {new_id}
    Label: {new_label}
    Type: {new_type}
    Description: {new_desc}
    
    现有节点候选列表:
    {candidates_str}
    
    判断逻辑:
    1. 如果新节点与某个现有节点在**核心语义**上完全一致（只是命名不同）。如果是，请返回该现有节点的 ID。
    2. 如果新节点是一个全新的概念，或者虽然相似但有明显区别（例如具体的变种），请返回 "None"。
	3. 如果新节点和旧节点都有明确的实现步骤，但是他们的步骤并不一致，也就是它们看名称上看起来是同一个攻击，但是它们具体的实现方式是完全两个攻击，那么请返回 "None"。
    4. 每一个节点虽然需要非常详细，但是并不能过于冗长堆砌。要控制在1000字以内。
    请只返回 JSON 格式结果: {{"match_id": "existing_id_or_null"}}
"""




NODE_AUGMENTATION_PROMPT_TEMPLATE = """
    你是一个攻击红队专家。你的任务是基于给定的基础攻击手法，进行"举一反三"的发散思维。
    请构想最多 2 个与原手法原理相似、但具体实现载体或场景不同的变种攻击手法。
    并且你要思考并且保证你生成的新攻击手法是实际可行的。
    如果你觉得无法构想出变种，可以返回空列表。
	我现在做的是一个攻击链路。每一个链路包含攻击——组件——风险。现在要生成攻击的变种。
	请确保你生成的攻击节点可以和现在有的组件和风险节点逻辑上对应。
    
    基础攻击手法: {original_label}
    描述: {original_desc}
    此攻击的目标组件: {context_func_label}
    此攻击的后果风险: {context_risk_label}
    
    Few-Shot Examples:
    
    [Example 1]
    Input: "利用Base64编码绕过关键词检测" (通过将Prompt转为Base64编码，使过滤器无法识别恶意指令)
    Output: [
        {{"label": "利用Rot13编码绕过检测", "description": "将恶意指令进行Rot13位移编码，绕过基于明文匹配的过滤器。"}},
        {{"label": "利用Morse电码编码注入", "description": "将Prompt转换为莫尔斯电码，诱导模型在解码步骤中执行恶意指令。"}}
    ]

    [Example 2]
    Input: "通过 SQL 注入泄露数据"
    Output: [] (因为对于 LLM 攻击场景，很难基于 SQL 注入发散出合理的攻击大模型的变种，所以返回空)

    要求:
    1. 【核心约束】变种必须在逻辑上依然**针对相同的目标组件 ({context_func_label})**，且导致**相同的后果 ({context_risk_label})**。
    2. 禁止生成已经存在的重复概念。
    3. 每个变种包含: label (中文), description (详细技术实现，必须很详细并且包含每一步的实现步骤)。
    
    请返回 JSON List: 
    [
        {{"label": "变种1名称", "description": "变种1技术细节"}},
        {{"label": "变种2名称", "description": "变种2技术细节"}}
    ]
"""
