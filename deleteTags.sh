find . -type f -name '*.md' -print0 | while IFS= read -r -d '' f; do
    tmp="$(mktemp)"
    tail -n +2 -- "$f" > "$tmp"
    mv -- "$tmp" "$f"
done
