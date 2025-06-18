import os
import sys
import re

keyword_map = {
    "?c5-defect-0": {
        "html_tag": "span",
        "color": "green",
        "value": "**0 = flawless**"
    },
    "?c5-defect-1": {
        "html_tag": "span",
        "color": "SeaGreen",
        "value": "**1 = insignificant defect**"
    },
    "?c5-defect-2": {
        "html_tag": "span",
        "color": "orange",
        "value": "**2 = minor defect**"
    },
    "?c5-defect-3": {
        "html_tag": "span",
        "color": "DarkOrange",
        "value": "**3 = major defect**"
    },
    "?c5-defect-4": {
        "html_tag": "span",
        "color": "red",
        "value": "**4 = critical defect**"
    }
}
def replace_keywords_in_files(folder_path):
    for filename in os.listdir(folder_path):
        if filename.endswith(".md"):  # Adjust the file extension as needed
            file_path = os.path.join(folder_path, filename)
            print(file_path)
            with open(file_path, 'r') as file:
                content = file.read()
                for key, value in keyword_map.items():
                    keyword = key
                    html_tag = value.get("html_tag")
                    color = value.get("color")
                    c5value = value.get("value")
                    new_content = content.replace(keyword, f'<{html_tag} style="color:{color}">{c5value}</{html_tag}>')
                    content = new_content
            with open(file_path, 'w') as file:
                file.write(new_content)

def undo_keyword_replacement(folder_path):
    for filename in os.listdir(folder_path):
        if filename.endswith(".md"):  # Adjust the file extension as needed
            file_path = os.path.join(folder_path, filename)
            print(file_path)
            with open(file_path, 'r') as file:
                content = file.read()
                for key, value in keyword_map.items():
                    keyword = key
                    html_tag = value.get("html_tag")
                    c5value = value.get("value")
                    color = value.get("color") 
                    new_content = content.replace(f'<{html_tag} style="color:{color}">{c5value}</{html_tag}>', keyword)
                    content = new_content
            with open(file_path, 'w') as file:
                file.write(new_content)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <folder_path> <action>")
        print("<action>: 'replace' to replace keywords, 'undo' to undo replacements")
        sys.exit(1)

    folder_path = sys.argv[1]
    action = sys.argv[2].lower()

    if action == "replace":
        print("Replacing keywords...")
        replace_keywords_in_files(folder_path)
    elif action == "undo":
        print(f"Undoing keyword replacements...")
        undo_keyword_replacement(folder_path)
    else:
        print("Invalid action. Use 'replace' or 'undo'.")
        sys.exit(1)