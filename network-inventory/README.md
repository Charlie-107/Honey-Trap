# NetScope Inventory

NetScope is a local network inventory dashboard. It discovers online devices with
`nmap`, records names, IPv4 addresses, MAC addresses and manufacturers, and
separates likely IoT devices from other assets. A bounded service scan identifies
open services and available product or version details.

The assessment planner builds an authorized, device-specific checklist for IT,
network, and IoT assets. Plans can be exported as JSON for evidence tracking.

## Run

```bash
cd /home/anik/network-inventory
./run.sh
```

Open <http://127.0.0.1:8080> and select a directly connected network.

The interface is split into independent pages that share the same server state:

- Inventory: <http://127.0.0.1:8080/inventory>
- Assessments: <http://127.0.0.1:8080/assessments>
- Activity: <http://127.0.0.1:8080/activity>

To use a different port:

```bash
./run.sh --port 9090
```

For an authenticated deployment, create the private environment file first:

```bash
cp .netscope-env.example .netscope-env
chmod 600 .netscope-env
./run-public.sh
```

Never commit `.netscope-env`, tunnel credentials, or Cloudflare certificates.

The service binds to `127.0.0.1` by default. Do not expose it to another network
without adding authentication and HTTPS.

## Requirements

- Linux with the `ip` command
- Python 3.10 or newer
- `nmap`

No Python or JavaScript packages are required.

## Current Scope

- Host discovery checks the 50 most common TCP ports with light service detection.
- It does not test vulnerabilities, credentials, or internal device processes.
- Targets must be inside a directly connected IPv4 network.
- A single scan is limited to 4,096 addresses.
- Service detection is limited to the first 128 online devices per scan.
- MAC addresses are generally visible only on the same layer-2 network.
- Device type is a best-effort classification from hostname and manufacturer.
- Inventory is kept in memory and resets when the service restarts.
- Assessment plans are non-destructive and do not launch exploits, password
  attacks, denial-of-service tests, or persistence actions.

Only scan networks you own or are authorized to administer.

## Global Agent Mode

The public controller lets separate users inventory their own local networks
without exposing the controller host's LAN. Each user creates an isolated
capability workspace and pairs an outbound-only desktop agent.

Start the controller:

```bash
./run-controller.sh
```

Pair an agent using the short-lived code shown by the controller:

```bash
python3 agent.py --server https://your-controller.example --pair ABCD1234
python3 agent.py
```

The agent accepts only directly connected RFC1918 IPv4 networks with no more
than 4,096 addresses. It rejects arbitrary CIDRs and public internet targets.
