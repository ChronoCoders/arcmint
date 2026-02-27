import sys

for line in sys.stdin:
    if 'reqwest =' in line:
        print('reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls", "http2", "charset"] }')
    else:
        sys.stdout.write(line)
