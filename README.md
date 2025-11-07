P2P Rust TUI Chat with Discovery and Wireshark

Run locally (one machine)

1. Build images and start discovery:
   - docker compose up --build -d discovery
2. Start two peers in separate terminals:
   - docker compose run --rm -it peer-1
   - docker compose run --rm -it peer-2
3. Type messages; they sync across peers.

Wireshark sniffing (macOS)

- Capture on interface lo0 with display filter:
  - tcp.port==7001 || tcp.port==7002 || tcp.port==8080
- You should see plaintext NDJSON chat lines.

Optional: capture container traffic directly (advanced)

- wireshark -k -i <(docker exec -i <peer_container> tcpdump -U -n -i any -w -)

Run across two machines (LAN)

- Machine A (discovery + peer-1):
  - DISCOVERY_URL=http://0.0.0.0:8080 and publish 8080:8080
  - peer-1 with ANNOUNCE_ADDR=<A_LAN_IP>:7001 and DISCOVERY_URL=http://<A_LAN_IP>:8080; publish 7001:7001
- Machine B (peer-2):
  - ANNOUNCE_ADDR=<B_LAN_IP>:7002, DISCOVERY_URL=http://<A_LAN_IP>:8080; publish 7002:7002
- Wireshark on each host: capture on primary NIC with display filter:
  - tcp.port in {7001,7002,8080}

Environment variables (peer)

- NODE_NAME: peer name (e.g., peer-1)
- ROOM: chat room (default: default)
- LISTEN_PORT: TCP port to listen on (e.g., 7001)
- DISCOVERY_URL: e.g., http://discovery:8080 (or http://<host>:8080)
- ANNOUNCE_ADDR: reachable host:port for others (e.g., host.docker.internal:7001)
- MAX_PEERS: max outbound connections (default: 8)

Automated Docker tests (multi-user simulation)

Run a three-peer headless test that auto-sends messages and self-verifies:

1. Execute the integration test script:
   - scripts/integration-test.sh
2. What it does:
   - Starts `discovery`, and peers `alice` (7101), `bob` (7102), `charlie` (7103)
   - `alice` auto-sends "hello from alice", `bob` auto-sends "hi from bob"
   - Each peer runs in HEADLESS mode and verifies expected messages via stdout
   - The script checks all three containers exit with code 0
3. Manual run:
   - docker compose -f docker-compose.test.yml up --build --abort-on-container-exit
   - Check logs for `TEST_PASS` or `TEST_FAIL`
