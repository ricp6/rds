# Trabalho Prático RDS 24/25

## How to Run

1. **Start Compile P4 program with API description in P4Info file:**
```bash
p4c-bm2-ss --std p4-16  p4/l2switch.p4 -o json/l2switch.json --p4runtime-files json/l2switch.p4info.txt
p4c-bm2-ss --std p4-16  p4/l3switch_tunnel.p4 -o json/l3switch_tunnel.json  --p4runtime-files json/l3switch_tunnel.p4info.txt
p4c-bm2-ss --std p4-16  p4/l3switch_mslp.p4 -o json/l3switch_mslp.json  --p4runtime-files json/l3switch_mslp.p4info.txt
p4c-bm2-ss --std p4-16  p4/l3switch_mslp_firewall.p4 -o json/l3switch_mslp_firewall.json  --p4runtime-files json/l3switch_mslp_firewall.p4info.txt
```

2. **Run the mininet script (terminal 1):**
```bash
sudo python3 mininet/tp-topo.py
```

3. **Run the controller (terminal 2):**
```bash
python3 controller/tp-controller.py --config configs/switches_config.json --programs configs/switches_programs.json --tunnels "configs/tunnels_config.json" --clone "configs/clone_config.json"
```


## Debugging Tips

Here are some useful commands to help troubleshoot and verify your topology:

### 1. **Wireshark (Packet Capture)**

### 2. **ARP Table Inspection**
   - **Command:** `arp -n`
   - **Usage:** Check the ARP table on any Mininet host to ensure proper IP-to-MAC Default gateway resolution.
   - Example:
     ```bash
     mininet> h1 arp -n
     ```

### 3. **Interface Information**
   - **Command:** `ip link`
   - **Usage:** Display the state and configuration of network interfaces for each host or router.
   - Example:
     ```bash
     mininet> r1 ip link
     ```

### 4. **P4 Runtime Client for Monitoring**
   - **Command:** `sudo ./tools/nanomsg_client.py --thrift-port <r1_port or r2_port>`
   - **Usage:** Interact with the P4 runtime to inspect flow tables and rules loaded on each router.
   - Example:
     ```bash
     sudo ./tools/nanomsg_client.py --thrift-port 9090
     ```

### 5. **Check the controller terminal in order to see some logs**
   You can also check `logs/s1-p4runtime-request.txt`

### 6. **Check configuration with `simple_switch_CLI`**
   ```bash
   $ simple_switch_CLI --thrift-port 9090
   ```
   ```bash
   RuntimeCmd: table_dump MyIngress.dMacLookup
   ```
   ```bash
   RuntimeCmd: table_dump MyIngress.sMacLookup
   ```
   for help
   ```bash
   RuntimeCmd: help
   ```


These commands will help you inspect network traffic, verify ARP entries, check interface states, and interact directly with the P4 routers.
