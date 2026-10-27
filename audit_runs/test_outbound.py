import socket

# Test TCP to an external IP (e.g. Cloudflare 1.1.1.1:80 or Google 142.250.190.46:80)
for ip, port in [("1.1.1.1", 80), ("8.8.8.8", 53), ("142.250.190.46", 80)]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect((ip, port))
        print(f"OUTBOUND LEAK DETECTED: Successfully connected to {ip}:{port}")
        s.close()
    except Exception as e:
        print(f"Connection to {ip}:{port} failed: {type(e).__name__}: {e}")
