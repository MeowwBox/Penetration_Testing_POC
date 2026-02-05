import feedparser
import os
import re

# ================= 配置区域 =================
RSS_URL = "https://mrxn.net/rss.php"
README_PATH = "README.md"

# 关键词列表
WEB_KEYWORDS = [
    'rce', 'sql', 'xss', 'csrf', 'upload', 'injection', 'web', 'cms', 
    '文件上传', '文件读取', 'sql注入', '信息泄露', '命令执行', 
    '目录遍历', '目录穿越', 'xxe', 'bypass', 'auth'
]

# README定位标记 (请确保这些标记在你README的HTML源码中完全匹配)
START_MARKER_REGEX = r'id="head4">Web APP</span>' 
END_MARKER_REGEX = r'id="head5">'                 
# ===========================================

def fetch_rss_entries():
    """获取 RSS 并返回解析后的数据列表"""
    print(f"Fetching RSS from {RSS_URL}...")
    try:
        feed = feedparser.parse(RSS_URL)
        entries = []
        for entry in feed.entries:
            entries.append({
                "title": entry.title,
                "link": entry.link
            })
        return entries
    except Exception as e:
        print(f"Error fetching RSS: {e}")
        return []

def is_relevant(title):
    """关键词过滤"""
    title_lower = title.lower()
    if any(keyword in title_lower for keyword in WEB_KEYWORDS):
        return True
    return False

def get_existing_urls(content_lines):
    """提取现有链接用于去重"""
    urls = set()
    link_pattern = re.compile(r'\]\((http[s]?://.*?)\)')
    for line in content_lines:
        found = link_pattern.findall(line)
        for url in found:
            urls.add(url.strip())
    return urls

def update_readme():
    if not os.path.exists(README_PATH):
        print(f"Error: {README_PATH} not found.")
        return

    with open(README_PATH, 'r', encoding='utf-8') as f:
        content = f.read()
    
    lines = content.splitlines()
    
    # 1. 定位区块
    start_index = -1
    end_index = -1
    
    for i, line in enumerate(lines):
        if re.search(START_MARKER_REGEX, line):
            start_index = i
        elif start_index != -1 and re.search(END_MARKER_REGEX, line):
            end_index = i
            break
            
    if start_index == -1 or end_index == -1:
        print("Error: Markers not found in README.md")
        return

    # 2. 获取该区块内现有的 URL (去重)
    existing_urls = get_existing_urls(lines[start_index:end_index])
    print(f"Existing links count: {len(existing_urls)}")

    # 3. 处理 RSS 数据
    rss_data = fetch_rss_entries()
    entries_to_add = []

    for item in rss_data:
        title = item['title']
        link = item['link']

        if not is_relevant(title):
            continue

        if link.strip() in existing_urls:
            print(f"Skipping duplicate: {title}")
            continue
        
        # 格式化
        entries_to_add.append(f"- [{title}]({link})")

    if not entries_to_add:
        print("No new entries.")
        return

    print(f"Adding {len(entries_to_add)} new entries...")

    # 4. 插入位置：end_index 之前的最后一个非空行之后
    insert_pos = end_index 
    while insert_pos > start_index and lines[insert_pos-1].strip() == "":
        insert_pos -= 1

    # 倒序插入，保持RSS顺序
    for entry in reversed(entries_to_add):
        lines.insert(insert_pos, entry)
    
    with open(README_PATH, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))
    print("Update successful.")

if __name__ == "__main__":
    update_readme()
