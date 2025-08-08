# hooks.py
import os

def set_title_from_filename(markdown, page, config, files):
    stem = os.path.splitext(os.path.basename(page.file.src_path))[0]
    page.meta['title'] = stem
    lines = markdown.splitlines()
    for i, l in enumerate(lines):
        if l.startswith("# "):
            lines[i] = "# " + stem
            break
    else:
        lines.insert(0, "# " + stem)
    return "\n".join(lines)
