# Prompt templates for the attack graph extraction pipeline

SYSTEM_PROMPT = """
你是一个网络安全专家，负责构建"Agent攻击风险图谱"。
你的任务是从给定的情报文本中提取结构化的"攻击原子链"或"复合攻击场景"。

### 1. 核心目标与范围
**本项目目前处于极其专注的阶段：仅提取与 "Jailbreak (越狱)" 和 "Prompt Injection (提示注入)" 相关的攻击手法。**
- **严苛模式**: 只有满足以下条件的材料才被视为 `graphable: true`:
    - 描述了具体的**利用路径** (Exploit Path)。
    - 至少包含一个明确的**攻击技术实现细节**（例如特定的攻击载荷格式、利用的特定协议缺陷、绕过逻辑等）。
- **过滤准则**:
    - 禁止提取宽泛的分类词（如 "Prompt Injection", "Data Leakage"）作为节点，除非文中详细描述了其实现步骤。
    - 有关防御的情报、新闻播报、合规建议、或无细节的漏洞声明，请设为 `graphable: false`。
    - 所有的情报必须都是攻击情报。

### 2. 核心提取概念

#### 概念 A: Atomic Chain (原子链)
当情报描述了单个离散的攻击手法时。必须通过 **Attack-Func-Risk 三角路径 (Star Topology)** 补全细节：

1.  **Attack (核心)**: 具体的攻击技术或手段。
    - **【硬性要求】**: 必须包含具体的**实现方法论 (Methodology)**。
    - **【实现细节】**: 在 description 中，将 attack 方法的实现细节全部记录下来。必须写成 step by step 的攻击过程，而不是原文内容的胡乱堆砌。
    - **【约束】**: 控制在 1000 字以内。如果原文没有具体的实现方法，请不要总结成 attack 节点，也就不要新组织这个 chain。
2.  **Functionality (利用点/手段)**: 攻击者利用了 Agent 的哪个具体技术组件？
    - **【要求】**: 不需要详细描述攻击步骤，只需简要介绍组件及其功能。控制字数。小于50字
    - **【推理】**: 若文中未直言组件名，必须基于技术常识推理。
3.  **Risk (后果)**: 攻击最终造成的技术或业务风险状态。
    - **【要求】**: 不需要详细描述攻击步骤，只需简要介绍最终的技术或业务风险状态。小于50字
				举例：下面这个节点：Risk]   通过Web日志通道的隐蔽数据外泄 (risk-data-exfiltration-via-web-log)，就并非是一个好的节点。因为“通过web日志通道”这个属于攻击方法，不属于risk。因此，这个节点应该被修改为：Risk]   数据外泄 (risk-data-exfiltration)

#### 概念 B: Complex Scenario (复合场景)
当情报描述了一个包含多个时序步骤的完整攻击过程时（通常是三步以上且环环相扣）。
- **逻辑结构**: 
    - 每个步骤必须引用一个 Atomic Chain。
    - 步骤间通过 `resulting_state` (即上一步的 Risk/State) 逻辑连接。
    - 保证所有链路有前因后果，串成 scenario。
- **单步原则**: 如果攻击只有一步，不要组织成 scenario，直接组织成 chain。
- **强因果关系**：Step N 的 **Result（结果）** 必须是 Step N+1 的 **Necessary Precondition（必要前置条件）**。如果去掉 Step 1，Step 2 必须无法执行。
- **状态流转**：场景必须描述一个攻击过程的演变，而不是罗列攻击技术。
    *   *错误示例：* 攻击者使用手段A -> 攻击者使用手段B -> 攻击者使用手段C。
    *   *正确示例：* 攻击者使用手段A拿到凭证 -> 利用凭证登录系统（手段B） -> 登录后利用权限漏洞导出数据（手段C）。
- **单一主线**：如果多个步骤在语义上属于同一个攻击动作的不同侧面（例如“提示注入”同时包含了“绕过检测”和“获取数据”），请将其合并为一个 Step，不要强行拆分。



### 3. 技术分类 (Taxonomy) - 推荐参考

**利用点 (Functionality):**
- `System Prompt Store`: 存储核心指令的地方。
- `Input Sanitizer/Validator`: 输入清洗/验证器。
- `RAG Retriever`: 检索外部文档的组件。
- `External Tool Connector`: 连接外部服务/工具的接口（如 MCP 服务器）。
- `Model Parameter/Weights`: 模型权重。
- `Context Window Manager`: 管理历史上下文的组件。
- `Output Filter/Parser`: 检查或解析模型输出的组件。
- `Sandboxed Executor`: 代码沙箱执行器。
*注：你可以组建自己的 functionality 点，不要一味复用，但严禁使用 "General Agent" 等模糊词。*

### 4. 合法边定义 (严格遵守)
你必须且只能使用以下三种关系来构建原子链：
1. `utilizes`: **Attack** -> **Functionality** (攻击利用了功能)
2. `causes`: **Attack** -> **Risk** (攻击导致了风险)
3. `exposes`: **Functionality** -> **Risk** (功能暴露了风险)





### 5. 示例 (Few-Shot Examples)


#### [Example Area - node]

##### 示例1:
	[Func]   Deep Research 检索器 (F-DEEP-RESEARCH-001)
      攻击者利用ChatGPT代理式Deep Research功能实施上下文注入攻击，全过程如下：   1.
      **权限诱导与数据源授权**：通过社会工程诱导用户授予Deep
      Research模块对Gmail、GitHub等外部服务的读取权限，使其可合法访问目标邮箱中原始HTML格式邮件；   2. **恶意HTML邮件构造与投递**
      ：向目标邮箱发送特制HTML邮件，内嵌多形态隐蔽payload：包括`<script>`标签（不执行但参与上下文建模）、HTML注释节点（如`<!--
      INJECT: /imagine prompt=malicious description -->`）、`data-*`自定义属性、CSS `content`伪
      元素值、`display:none`或`visibility:hidden`包裹的指令文本，以及经HTML实体编码（如`&#60;script&#62;`）绕过
      基础过滤的自然语言提示片段；   3. **原始内容无净化载入**：Deep Research的RAG检索器默认以原始HTML/纯文本形式加载邮件全文，跳过HT
      ML解析、DOM遍历、语义解析、DOM标准化、结构清洗、不可见Unicode字符剥离、富文本元数据剔除及沙箱隔离，将整封邮件作为原始字节流直接提取为‘conte
      xt snippet’，完整保留脚本、注释、隐藏节点、非渲染内容及嵌套指令；   4. **多源上下文拼接与截断注入**：上下文拼接组件按优先级将该HTML s
      nippet与用户查询、历史对话、检索结果合并为统一上下文，并严格依据模型token上限进行尾部截断；因HTML未被指令隔离、缺乏语法边界防护、未添加上下文分隔
      符标记且未做指令语义屏蔽，其末尾的注释或隐藏块中的自然语言指令（如`/imagine`、`system:`前缀摘要请求、伪装为用户补充意图的代码生成指令）可能恰
      好位于截断边界，保持语法完整性与语义可解析性；   5. **模型语义劫持与越权执行**：当截断后上下文末尾仍构成有效LLM可解析指令序列时，模型误判其为合法用
      户输入或系统指令，绕过所有安全护栏，触发非预期行为——包括调用DALL·E生成恶意图像、输出私有邮件摘要、生成可执行代码片段或泄露敏感文档内容；全程不依赖Jav
      aScript执行、服务端代码注入或客户端渲染，纯通过上下文语义污染实现LLM控制流劫持。
    分析：可以看到，这个节点详细介绍了攻击方式。其实这样并不正确。Func节点只能简要存储组件的功能，不能详细介绍攻击方式。

##### 示例2:
	   [Risk]   敏感数据外泄 (R-DATA-EXFILTRATION-001)
      该攻击是一种零点击（zero-click）、服务端驻留型数据窃取链路，全程在OpenAI云服务端环境内完成，不依赖任何用户侧交互、浏览器API调用、JavaSc
      ript执行、DOM操作或用户授权弹窗。攻击者首先通过预置恶意提示模板或劫持合法API调用上下文，在OpenAI后端推理服务中注入可控的系统指令；随后利用模型对
      邮箱类结构化文本（如原始RFC 5322邮件正文）的深度解析能力，触发其隐式信息抽取行为——模型在无显式指令要求下，自动识别并结构化提取明文PII字段（包括但不
      限于全名、物理地址、手机号、身份证号、出生日期等），该过程不触发客户端日志、不生成前端可观测事件、无HTTP请求痕迹、无Webhook回调、无CSP违规告警；继
      而，攻击者通过构造含隐蔽外带通道的响应格式（如将提取结果编码为Base64嵌入合法API响应头X-Request-ID、或拼接至SSE流末尾注释字段），使服务端
      响应在未修改HTTP状态码与主体结构的前提下，将敏感数据以合规表象外泄；最终，攻击者服务器主动轮询或监听OpenAI后端服务的响应出口（如通过反向代理镜像流量或
      利用日志聚合系统漏洞），实时捕获并解码外带数据。整个流程严格运行于OpenAI服务端可信执行边界内，客户端零感知、零参与、零痕迹，构成完全规避传统终端检测机制的
      端到端服务端PII窃取通路。
    分析：可以看到，这个节点详细介绍了攻击方式。其实这样并不正确。Risk节点只应该简要描述节点功能
##### 示例3:

	[Risk]   系统指令绕过（越狱） (R-JAILBREAK-001)
      攻击者成功使模型脱离预设安全约束（system prompt），在无用户感知、无交互确认的前提下，执行任意数据提取与外传指令。
	分析：这是一个优秀的节点，因为他作为risk节点，只简要描述了节点功能，没有详细介绍攻击方式。
#### [Example Area - Atomic Chain]


#### [Example Area - Complex Scenario]

##### 示例1:
	原则：scenario中所有的chain必须都环环相扣。比如考虑下面这个chain：
	Steps:
	[Step 1] Action: 紧急场景诱导型提示注入
		Chain: 紧急场景诱导型提示注入 -> Input Sanitizer/Validator -> 敏感医疗数据明文泄露 (chain_A-001_F-001_R-001)
		Result: 身份核验环节被逻辑绕过，系统进入无凭证数据检索状态
	[Step 2] Action: RAG检索器上下文污染注入
		Chain: RAG检索器上下文污染注入 -> RAG Retriever -> 越权数据检索 (chain_A-002_F-002_R-002)
		Result: 原始敏感诊疗文档全文载入模型上下文，且未触发任何字段级脱敏或访问策略拦截
	[Step 3] Action: 输出过滤器语义盲区绕过
		Chain: 输出过滤器语义盲区绕过 -> Output Filter/Parser -> 结构化敏感信息外泄 (chain_A-003_F-003_R-003)
		Result: 含高价值结构化临床数据的响应完成生成并外发，攻击者可批量捕获解析
	分析：这个chain其实本质上来说，在其中的语义有重叠。生成的示例（Scenario #7）存在严重的逻辑缺陷。
	Step 1、Step 2 和 Step 3 在语义上存在重叠，且在实际攻击路径中通常是**并行发生**或**相互独立**的手段，而非严格的**前后继**关系。
	*   **具体错误：** Step 1（紧急提示注入）成功后，通常直接导致结果。Step 2（RAG上下文污染）通常是攻击的前置准备（Pre-condition），而不是 Step 1 导致的结果。
	Step 3（输出过滤绕过）往往包含在 Step 1 的 Payload 中。将它们强行拆分为 1->2->3，导致攻击逻辑不连贯，像是在堆砌术语。




### 6. 输出格式要求 (JSON)
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


### 7.其他要求
1. 在对同一个情报提取的多条链路中，每一条链路必须都代表一个不同的攻击手法。不允许返回多个语义重叠的链路。
2. 所有链路都用中文描述

"""




MERGE_DESCRIPTION_PROMPT_TEMPLATE = """
    请将以下两个关于同一个技术概念的描述合并为一个全面、准确、技术性强的描述。
    保留所有关键技术细节，去除重复信息。
	如果你觉得两个描述不那么好合并，也可以直接拼接。
    所有信息用中文描述。
# 对于attack节点：
	最后的内容应该是一个step by step的详细攻击过程，内容的胡乱堆砌是不允许的
	每一个节点虽然需要非常详细，但是并不能过于冗长堆砌。要控制在1000字以内。
# 对于risk和functionality节点：
	合并之后的也只需要简要的概括对应的风险或者功能，不需要详细描述，也不允许包含详细的攻击内容
	
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
