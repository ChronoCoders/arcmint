import re

path = '/opt/arcmint/Cargo.toml'
with open(path, 'r') as f:
    content = f.read()

# Update tonic to 0.12
# The regex looks for: tonic = { version = "0.11"
# We replace with: tonic = { version = "0.12"
content = re.sub(r'tonic = \{ version = "0\.11"', 'tonic = { version = "0.12"', content)
content = re.sub(r'tonic-build = "0\.11"', 'tonic-build = "0.12"', content)

with open(path, 'w') as f:
    f.write(content)
