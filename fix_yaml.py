import re

with open('/opt/arcmint/docker-compose.yml', 'r') as f:
    content = f.read()

new_lnd_init = """  lnd-init:
    image: lightninglabs/lnd:v0.17.4-beta
    restart: "no"
    depends_on:
      lnd:
        condition: service_healthy
    volumes:
      - lnd-data:/root/.lnd
      - lnd-init:/lnd-init
      - ./lnd-init.sh:/lnd-init.sh:ro
    entrypoint: /bin/sh /lnd-init.sh
"""

new_miner = """  miner:
    image: lncm/bitcoind:v26.0
    restart: unless-stopped
    depends_on:
      lnd-init:
        condition: service_completed_successfully
    volumes:
      - bitcoind-data:/data/.bitcoin
      - ./miner.sh:/miner.sh:ro
    entrypoint: /bin/sh /miner.sh
"""

# Replace lnd-init block
# Match from "  lnd-init:" at start of line (2 spaces) up to "  miner:" at start of line
# Use re.MULTILINE so ^ matches start of line
content = re.sub(r'^  lnd-init:[\s\S]*?(?=^  miner:)', new_lnd_init, content, flags=re.MULTILINE)

# Replace miner block
# Match from "  miner:" at start of line up to "  prometheus:" at start of line
content = re.sub(r'^  miner:[\s\S]*?(?=^  prometheus:)', new_miner, content, flags=re.MULTILINE)

with open('/opt/arcmint/docker-compose.yml', 'w') as f:
    f.write(content)
