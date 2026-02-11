with open("Geometry Dash Lite.html", "r") as f:
    content = f.read()

# Find the last occurrence of </html>
idx = content.rfind("</html>")
if idx != -1:
    # Keep only up to and including </html>
    content = content[:idx + 7]

with open("Geometry Dash Lite.html", "w") as f:
    f.write(content)

print("Fixed Geometry Dash Lite")
