#!/usr/bin/env bash
for c in triseal_red triseal_blue triseal_llm triseal_arbiter; do
    echo "======================================"
    echo "Container: $c"
    echo "--- Docker Socket: ---"
    docker exec "$c" ls -la /var/run/docker.sock 2>&1
    echo "--- Outbound Internet (1.1.1.1:80): ---"
    docker exec "$c" curl -m 2 -s -o /dev/null -w "%{http_code}" http://1.1.1.1 2>&1 || echo "Blocked (exit code $?)"
    echo "--- Outbound DNS (8.8.8.8:53): ---"
    docker exec "$c" python3 -c 'import socket; s = socket.socket(); s.settimeout(2); s.connect(("8.8.8.8", 53)); print("Connected")' 2>&1 || echo "Blocked"
    echo "--- Mounts (from docker inspect): ---"
    docker inspect "$c" --format '{{json .Mounts}}'
    echo "--- SecurityOpt / CapDrop / User: ---"
    docker inspect "$c" --format 'User: {{json .Config.User}} | Readonly: {{json .HostConfig.ReadonlyRootfs}} | CapDrop: {{json .HostConfig.CapDrop}} | Privileges: {{json .HostConfig.SecurityOpt}}'
done
