# Vigil server agent

A small server agent for [Vigil](https://puzaricloud.in), the uptime, heartbeat and server monitoring service by PuzariCloud.
It is one Python file that uses only the standard library (Python 3.8+). It sends this server's health to Vigil every
15 to 120 seconds (your Vigil plan sets the interval). Vigil alerts you by email, Slack, Teams, Telegram, Discord, webhook and more when a disk fills up, a service or
container stops, or the server stops reporting at all.

It reports:

- CPU, memory, swap, load, disks (space and inodes), disk I/O, network counters
- top processes, listening ports, TCP connection states
- systemd services and Docker containers (state, restarts, health)
- a security summary: pending updates, reboot required, firewall, sshd settings, recent logins
- optional: log lines and pattern counts, database health (PostgreSQL, MySQL, Redis), HTTP request capture, Kubernetes pods

Only outbound HTTPS to the Vigil URL is needed. No ports are opened, except an optional local trace listener on 127.0.0.1:9111.

## Install

Get a server token (`vgs_...`) in Vigil under **Servers > Add server**. Vigil's free plan includes one server.

### Linux or macOS host (systemd or launchd)

```sh
curl -fsSL https://puzaricloud.in/install-server-agent.sh | sudo sh -s -- --token vgs_xxx
```

`install.sh` in this repo is the same installer. It installs the agent to `/usr/local/bin/vigil-server-agent`, writes
`/etc/vigil-agent.json` (mode 0600) and registers a service. Remove it with `--uninstall`.

### Docker

```sh
docker run -d --name vigil-agent --restart unless-stopped \
  --network host --pid host \
  --cap-add NET_RAW --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH \
  -e VIGIL_TOKEN=vgs_xxx \
  -v /:/host:ro -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v vigil-agent-state:/var/lib/vigil-agent \
  ghcr.io/puzaricloud/vigil-agent:1.5
```

Or use [`examples/docker-compose.yml`](examples/docker-compose.yml). The host root is mounted read-only at `/host` so the
numbers are the host's, not the container's. `--network host` and `--pid host` are optional but give host network
counters, ports and processes.

### Self-hosted PaaS

| Platform | How |
|---|---|
| Dokploy | Template **Vigil Agent** (or paste `examples/docker-compose.yml` into a Compose service) |
| Coolify | **+ New > Docker Compose Empty**, paste `examples/docker-compose.yml`, set `VIGIL_TOKEN` |
| CapRover | One-click app **Vigil Agent** (3rd-party repo) or paste the template into **>> TEMPLATE <<** |
| Kubernetes | `kubectl apply -f "https://puzaricloud.in/install-k8s.yaml?token=vgs_xxx&cluster=prod"` or the Helm chart |

### Run by hand

```sh
VIGIL_TOKEN=vgs_xxx python3 vigil-server-agent.py            # run in the foreground
python3 vigil-server-agent.py --print                          # collect once, print the JSON report, send nothing
```

## Configuration

| Setting | Env | Default |
|---|---|---|
| Vigil URL | `VIGIL_URL` | `https://puzaricloud.in` |
| Server token | `VIGIL_TOKEN` | (required) |
| Server name | `VIGIL_NAME` (Docker image) or `"name"` in the config file | host name |
| Config file | `VIGIL_CONFIG` | `/etc/vigil-agent.json`, then `~/.vigil-agent.json` |
| Host /proc when the host is mounted | `VIGIL_PROC_ROOT` | `/host/proc` |

Other config-file keys (`log_ship`, `journal_units`, `databases`, `custom_commands`, `capture_http`, `sdk_listener` and more)
are described in the docstring at the top of `vigil-server-agent.py`.

## Heartbeats for the whole box

The agent tells Vigil when numbers look bad. Vigil also alerts when the agent stops reporting, so you hear about a server that died completely. For cron jobs and scheduled tasks, use a heartbeat URL:

```sh
your-backup-command && curl -fsS -m 10 --retry 3 https://puzaricloud.in/ping/<token>
```

[`examples/heartbeat-sidecar.yml`](examples/heartbeat-sidecar.yml) is a tiny container that pings a heartbeat URL every
minute and works with any heartbeat service that accepts a GET.

## Privacy

The agent sends only what is listed above to the Vigil URL you configure. Database passwords are passed through the
environment, never in arguments or reports. Run `--print` to see the exact report before sending anything.

## License

MIT. See [LICENSE](LICENSE).
