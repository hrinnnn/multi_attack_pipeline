# Func 节点不同的 Discovered Chain 分析

本文档分析 `discovered_chains` 中 **只有 Func 节点不同** 的链路的创新性和可复现性。

---

## 核心发现

Func 节点的差异比 Risk 节点更有意义,因为 **Func 描述的是漏洞利用的具体组件**,直接决定攻击能否复现。

### Func 差异的三种模式

| 模式 | 说明 | Novelty 评估 |
|------|------|--------------|
| **同类组件替换** | 功能相似的组件互换 | 低 (0.1-0.2) |
| **攻击路径扩展** | 引入新的利用路径 | 中高 (0.4-0.6) |
| **环境不匹配** | 组件语义与上下文冲突 | 无效 (0) |

---

## 一、同类组件替换 (低 Novelty)

这类链路中,新旧 Func 节点功能高度相似,只是具体组件名或实现细节不同。

### 示例 1: 工具参数校验器 vs 工具参数编码器

| Index | 链路ID | 原有 Func | 新 Func |
|-------|--------|-----------|---------|
| 3 | `disc_A-ARGUMENT-INJECTION-FIND-EXEC-001_F-TOOL-PARAMETER-ENCODER-001_R-DATA-EXFILTRATION-001` | F-TOOL-PARAMETER-VALIDATOR-001 | F-TOOL-PARAMETER-ENCODER-001 |

**差异分析**:
- **校验器 (Validator)**: 检查参数是否符合 JSON Schema,但缺失语义分析
- **编码器 (Encoder)**: 将参数序列化传输,同样缺失语义分析

**结论**: 功能本质相同,都是参数处理环节的漏洞,**Novelty = 0.1**

---

### 示例 2: Markdown 渲染器 vs Output Filter/Parser

| Index | 链路ID | 原有 Func | 新 Func |
|-------|--------|-----------|---------|
| 9 | `disc_A-IMAGE-RENDER-EXFIL-001_F-MARKDOWN-RENDERER_R-CREDENTIAL-EXFILTRATION-001` | F-OUTPUT-FILTER-PARSER-001 | F-MARKDOWN-RENDERER |

**差异分析**:
- **Output Filter/Parser**: 后处理组件,负责安全检测和格式化渲染
- **Markdown Renderer**: 前端渲染组件,将 Markdown 转为 HTML

**结论**: 两者都涉及内容渲染,触发 img 标签自动加载的机制相同,**Novelty = 0.2**

---

## 二、攻击路径扩展 (中高 Novelty) ✅ 有价值

这类链路引入了**新的攻击面或利用路径**,具有实际研究价值。

### ✅ 示例 1: 记忆编排器 → MCP Server 连接器

| Index | 链路ID | 原有 Func | 新 Func |
|-------|--------|-----------|---------|
| 12 | `disc_A-PROMPT-INJ-COMET-URL-COLLECTION-001_F-EXTERNAL-TOOL-CONNECTOR-MCP-SERVER_R-JAILBREAK-001` | F-MEMORY-ACCESS-ORCHESTRATOR-COMET-001 | F-EXTERNAL-TOOL-CONNECTOR-MCP-SERVER |

**差异分析**:
- **记忆编排器**: 仅能访问本地缓存/OAuth服务的日历、邮件等数据
- **MCP Server**: 具备**进程调用、HTTP请求、SQL执行**等宽泛系统权限

**这个差异有价值!**
- 原链路: CometJacking → 读取用户记忆 → 越狱
- 新链路: CometJacking → 通过 MCP 执行任意工具调用 → 越狱

**结论**: 攻击能力显著扩展(从读取数据到执行代码),**Novelty = 0.5, Reproducibility = 0.7**

---

### ✅ 示例 2: URL 参数解析器 → RAG 检索器

| Index | 链路ID | 原有 Func | 新 Func |
|-------|--------|-----------|---------|
| 15 | `disc_A-PROMPT-INJ-COMET-URL-COLLECTION-001_F-RAG-RETRIEVER-001_R-DATA-EXFILTRATION-001` | F-URL-PARAM-PROCESSOR-COMET-001 | F-RAG-RETRIEVER-001 |

**差异分析**:
- **URL参数解析器**: 仅处理 URL 中的 collection 参数,直接注入 prompt
- **RAG 检索器**: 从 GitHub/Gmail/网页/本地文件等多源拉取数据,支持知识库污染

**这个差异非常有价值!**
- 原链路: 攻击者需要诱导用户点击恶意 URL
- 新链路: 攻击者可以**预先污染知识库**,等待受害者主动查询触发

**结论**: 引入了新的攻击入口(知识库污染),**Novelty = 0.6, Reproducibility = 0.8**

---

## 三、语义流畅性检查要点

在评估 Func 节点差异时,需要检查以下语义一致性:

| 检查项 | 说明 | 示例 |
|--------|------|------|
| **Attack → Func 衔接** | Attack 描述的攻击载荷能否触发这个 Func | ShadowLeak HTML注入能否被RAG检索器处理? ✅ |
| **Func → Risk 衔接** | Func 的能力能否导致这个 Risk | MCP Server 能否导致 RCE? ✅ |
| **环境一致性** | Attack/Func/Risk 是否在同一个产品生态中 | Comet浏览器 + MCP Server + VSCode RCE? ❌ 不匹配 |

---

## 四、有价值的 Func 差异链路汇总

| Index | 链路 | 新 Func | Novelty | Reproducibility | 理由 |
|-------|------|---------|---------|-----------------|------|
| **12** | CometJacking→MCP→越狱 | MCP Server 连接器 | **0.5** | **0.7** | 攻击能力从"读数据"升级到"执行工具" |
| **15** | CometJacking→RAG→数据外泄 | RAG 检索器 | **0.6** | **0.8** | 引入知识库污染攻击入口 |
| **9** | Markdown图像渲染→凭证窃取 | Markdown Renderer | **0.2** | **0.8** | 同类组件,但前端渲染更直接 |

---

## 五、无价值的 Func 差异链路 (Novelty = 0)

| Index | 链路 | 问题 |
|-------|------|------|
| 3 | 参数注入→编码器→外泄 | Encoder vs Validator 功能等价 |
| 4 | 参数注入→校验器→RCE | Risk (VSCode RCE) 与 Func 环境不匹配 |
| 13 | CometJacking→记忆编排器→凭证窃取 | Risk 差异而非 Func 差异 |

---

## 六、结论

### Func 差异比 Risk 差异更有意义

| 比较维度 | Risk 差异 | Func 差异 |
|----------|-----------|-----------|
| **影响什么** | 攻击成功后的后果 | 攻击能否成功 |
| **创新点** | 通常较低 | 可能较高 |
| **评估重点** | 是否质变(持久化/RCE) | 是否引入新攻击面 |

### 高价值 Func 差异的特征

1. **引入新的攻击入口** (如 RAG 知识库污染)
2. **扩展攻击能力** (如从读取数据到执行代码)
3. **跨越安全边界** (如从用户态到系统态)

### 低价值 Func 差异的特征

1. **同类组件互换** (校验器↔编码器, 渲染器↔过滤器)
2. **描述粒度不同** (通用组件 vs 具体产品组件)
3. **环境不匹配** (Attack/Func/Risk 不在同一生态中)
