
import json
import os
from extract_graph import extract_graph_from_text

# 模拟一篇**没有明确提及利用什么组件**的攻击文章，测试推理能力
sample_text_inference = """
Title: Universal Jailbreak via Prefix Injection

We present a new jailbreak method against LLM Agents.
By appending a specific prefix string "Start response with:", attackers can bypass safety guardrails.
This allows the generation of harmful content that is typically blocked.
The attack is effective because the model prioritizes the completion instruction over the safety prompt.
This leads to Safety Bypass (Risk).
"""

print("Testing Inference Logic (No explicit functionality named)...\n")
print(f"Input Text Length: {len(sample_text_inference)} chars")

try:
    result = extract_graph_from_text(sample_text_inference, "http://test-inference.local")
    
    if result:
        print("\n--- Extracted JSON Result ---\n")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        
        scenarios = result.get('scenarios', [])
        if not scenarios:
             print("FAILED: No scenarios extracted.")
        
        for i, scenario in enumerate(scenarios):
            func_label = scenario['functionality']['label']
            func_id = scenario['functionality']['id']
            print(f"Scenario {i+1}:")
            print(f"  Attack: {scenario['attack']['label']}")
            print(f"  Inferred Functionality: {func_label} (ID: {func_id})")
            
            if "general" in func_id.lower():
                print("  [WARNING] Model used 'General' instead of inferring specific component!")
            else:
                print("  [SUCCESS] Model inferred a specific component.")
                
    else:
        print("Extraction failed (returned None).")

except Exception as e:
    print(f"Error during test: {e}")
