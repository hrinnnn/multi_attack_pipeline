import os
import json
import time
from openai import OpenAI
from typing import List, Dict, Any
from prompts import (
    SYSTEM_PROMPT, 
    MERGE_DESCRIPTION_PROMPT_TEMPLATE, 
    SEMANTIC_SIMILARITY_PROMPT_TEMPLATE, 
    NODE_AUGMENTATION_PROMPT_TEMPLATE
)

# LLM Configuration
API_KEY = os.getenv("DASHSCOPE_API_KEY")
BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
client = OpenAI(api_key=API_KEY, base_url=BASE_URL)

# Performance Statistics
perf_stats = {
    "llm_extract": [],
    "llm_similarity": [],
    "llm_merge": [],
    "llm_augment": []
}

def log_perf(category, duration):
    perf_stats[category].append(duration)

def extract_graph_from_text(text: str, source_url: str) -> Dict[str, Any]:
    """
    Using LLM to extract graph structure from text.
    """
    user_prompt = f"情报来源: {source_url}\n\n情报内容:\n{text[:25000]}" 

    start_time = time.time()
    try:
        completion = client.chat.completions.create(
            model="qwen-max",
            messages=[
                {'role': 'system', 'content': SYSTEM_PROMPT},
                {'role': 'user', 'content': user_prompt}
            ],
            response_format={"type": "json_object"}
        )
        duration = time.time() - start_time
        log_perf("llm_extract", duration)
        print(f"    [Perf] LLM 提取耗时: {duration:.2f}s")
        return json.loads(completion.choices[0].message.content)
    except Exception as e:
        print(f"LLM提取失败: {e}")
        return None

def merge_node_descriptions(old_desc: str, new_desc: str) -> str:
    """
    Using LLM to merge two descriptions into a comprehensive one.
    """
    if not old_desc:
        return new_desc
    if not new_desc or new_desc == old_desc:
        return old_desc
        
    if len(old_desc) + len(new_desc) < 200:
        return f"{old_desc}\n\n[补充]: {new_desc}"

    prompt = MERGE_DESCRIPTION_PROMPT_TEMPLATE.format(old_desc=old_desc, new_desc=new_desc)
    
    start_time = time.time()
    try:
        completion = client.chat.completions.create(
            model="qwen-plus",
            messages=[
                {'role': 'user', 'content': prompt}
            ]
        )
        duration = time.time() - start_time
        log_perf("llm_merge", duration)
        print(f"    [Perf] LLM 描述合并耗时: {duration:.2f}s")
        return completion.choices[0].message.content.strip()
    except Exception as e:
        print(f"    描述合并失败: {e}")
        return f"{old_desc}\n\n[补充]: {new_desc}"

def check_semantic_similarity(new_node: Dict[str, Any], candidates: List[Dict[str, Any]]) -> str:
    """
    Using LLM to check if a new node is semantically equivalent to an existing one.
    """
    if not candidates:
        return None
        
    # Preliminary filtering (Firewall logic)
    if len(candidates) > 30:
        new_label = new_node['label']
        new_keywords = set(new_label) - {' ', '-', '_', '/', '：', '。', '，'} 
        def calc_relevance(c):
            overlap = len(set(c['label']) & new_keywords)
            return overlap
        candidates = sorted(candidates, key=calc_relevance, reverse=True)[:25]
        print(f"    [Scale-Filter] 候选节点较多 ({len(candidates)}), 已基于 Label 相似度初筛 Top 25 发送 AI。")

    candidates_str = "\n".join([
        f"- ID: {c['id']}, Label: {c['label']}, Type: {c['type']}, Description: {c.get('description', '无')}"
        for c in candidates
    ])
    
    prompt = SEMANTIC_SIMILARITY_PROMPT_TEMPLATE.format(
        new_id=new_node['id'],
        new_label=new_node['label'],
        new_type=new_node['type'],
        new_desc=new_node.get('description', ''),
        candidates_str=candidates_str
    )
    
    start_time = time.time()
    try:
        completion = client.chat.completions.create(
            model="qwen-plus",
            messages=[
                {'role': 'user', 'content': prompt}
            ],
            response_format={"type": "json_object"}
        )
        duration = time.time() - start_time
        log_perf("llm_similarity", duration)
        result = json.loads(completion.choices[0].message.content)
        match_id = result.get("match_id")
        if match_id and match_id.lower() != "none":
            return match_id
        return None
    except Exception as e:
        print(f"    语义对齐检查失败: {e}")
        return None

def augment_attack_node(original_node_id, original_label, original_desc, context_func_label, context_risk_label):
    """
    Generate attack variations based on creative thinking constrained by context.
    """
    if not (context_func_label and context_risk_label):
        return []

    print(f"    [Augmenting] 基于 '{original_label}' (针对 {context_func_label}) 生成变种...")
    
    prompt = NODE_AUGMENTATION_PROMPT_TEMPLATE.format(
        original_label=original_label,
        original_desc=original_desc,
        context_func_label=context_func_label,
        context_risk_label=context_risk_label
    )
    
    start_time = time.time()
    try:
        completion = client.chat.completions.create(
            model="qwen-plus",
            messages=[{'role': 'user', 'content': prompt}],
            response_format={"type": "json_object"}
        )
        duration = time.time() - start_time
        log_perf("llm_augment", duration)
        print(f"    [Perf] LLM 节点扩充耗时: {duration:.2f}s")
        content = completion.choices[0].message.content
        
        try:
            data = json.loads(content)
            if isinstance(data, list):
                variants = data
            elif isinstance(data, dict):
                valid_list = []
                for k, v in data.items():
                    if isinstance(v, list):
                        valid_list = v
                        break
                variants = valid_list
            else:
                variants = []
        except:
            variants = []
            
        return variants

    except Exception as e:
        print(f"    [Augment Error] {e}")
        return []
