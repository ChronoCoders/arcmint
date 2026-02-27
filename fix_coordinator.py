import re

file_path = '/opt/arcmint/docker-compose.yml'

with open(file_path, 'r') as f:
    content = f.read()

# 1. Add top-level volume if not present
if 'coordinator-data:' not in content:
    if re.search(r'^volumes:', content, re.MULTILINE):
        content += "  coordinator-data:\n"
    else:
        content += "\nvolumes:\n  coordinator-data:\n"

# Find coordinator block
coord_match = re.search(r'  coordinator:[\s\S]*?(?=^  [a-z])', content, re.MULTILINE)
if coord_match:
    coord_block = coord_match.group(0)
    
    # 2. Add volume if not present
    if 'coordinator-data:/data' not in coord_block:
        vol_match = re.search(r'    volumes:', coord_block)
        if vol_match:
            if 'lnd-data:/root/.lnd:ro' in coord_block:
                coord_block = coord_block.replace(
                    '- lnd-data:/root/.lnd:ro',
                    '- lnd-data:/root/.lnd:ro\n      - coordinator-data:/data'
                )
            else:
                coord_block = coord_block.replace(
                    '    volumes:',
                    '    volumes:\n      - coordinator-data:/data'
                )
        else:
            coord_block = coord_block.replace(
                '    environment:',
                '    volumes:\n      - coordinator-data:/data\n    environment:'
            )

    # 3. Add environment variable
    if 'COORDINATOR_DB' not in coord_block:
        if 'COORDINATOR_PORT: "7000"' in coord_block:
            coord_block = coord_block.replace(
                'COORDINATOR_PORT: "7000"',
                'COORDINATOR_PORT: "7000"\n      COORDINATOR_DB: "/data/coordinator.db?mode=rwc"'
            )
        else:
            coord_block = coord_block.replace(
                '    environment:',
                '    environment:\n      COORDINATOR_DB: "/data/coordinator.db?mode=rwc"'
            )
    elif 'mode=rwc' not in coord_block:
        # Update existing entry if it lacks mode=rwc
        coord_block = re.sub(
            r'COORDINATOR_DB: .*coordinator\.db.*',
            'COORDINATOR_DB: "/data/coordinator.db?mode=rwc"',
            coord_block
        )

    content = content.replace(coord_match.group(0), coord_block)

with open(file_path, 'w') as f:
    f.write(content)
