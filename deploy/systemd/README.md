# systemd deployment

Two unit files for classic Linux hosts — one long-running service for the
FastAPI dashboard, one templated one-shot for keyword-specific swarm runs.

## Layout assumed

| Path | Owner | Contents |
|---|---|---|
| `/opt/threat-intel-aggregator/`   | `tia:tia` | Project checkout |
| `/opt/threat-intel-aggregator/.venv/` | `tia:tia` | Python venv with deps installed |
| `/opt/threat-intel-aggregator/output/` | `tia:tia` | Report artifacts + SQLite DB (writable) |
| `/opt/threat-intel-aggregator/logs/`   | `tia:tia` | Log files (writable) |
| `/etc/threat-intel-aggregator/env` | `root:root` 0600 | API keys + TIA_API_KEY |

## One-shot setup

```bash
# Create the service user + project root
sudo useradd --system --home /opt/threat-intel-aggregator --shell /sbin/nologin tia
sudo install -d -o tia -g tia /opt/threat-intel-aggregator
sudo -u tia git clone https://github.com/YOU/threat-intel-aggregator /opt/threat-intel-aggregator

# Build the venv as the service user
sudo -u tia python3.11 -m venv /opt/threat-intel-aggregator/.venv
sudo -u tia /opt/threat-intel-aggregator/.venv/bin/pip install /opt/threat-intel-aggregator

# Secret-carrying env file — 0600 so only root + the unit can read it
sudo install -d -m 0700 /etc/threat-intel-aggregator
sudo cp /opt/threat-intel-aggregator/.env.example /etc/threat-intel-aggregator/env
sudo chmod 0600 /etc/threat-intel-aggregator/env
# …then edit /etc/threat-intel-aggregator/env to fill in real keys

# Install the units
sudo cp /opt/threat-intel-aggregator/deploy/systemd/*.service /etc/systemd/system/
sudo cp /opt/threat-intel-aggregator/deploy/systemd/*.timer   /etc/systemd/system/
sudo systemctl daemon-reload
```

## Running

```bash
# Long-running API dashboard
sudo systemctl enable --now threat-intel-api.service
sudo systemctl status threat-intel-api.service
curl -H "X-API-Key: $TIA_API_KEY" http://localhost:8000/api/v1/health

# One-off run for a specific keyword
sudo systemctl start threat-intel@ransomware.service
journalctl -u threat-intel@ransomware.service --since "10 min ago"

# Scheduled 6-hour cadence for a specific keyword
sudo systemctl enable --now threat-intel@ransomware.timer
systemctl list-timers 'threat-intel@*.timer'
```

## Hardening notes

Both units ship with a strict sandboxing envelope:

- `NoNewPrivileges`, `PrivateTmp`, `PrivateDevices`, `ProtectHome`,
  `ProtectSystem=strict`
- `MemoryDenyWriteExecute`, `LockPersonality`, `RestrictNamespaces`
- `ReadWritePaths` limited to `output/` + `logs/` — the unit cannot modify
  anything else on the filesystem even if an agent is compromised
- `CapabilityBoundingSet=` (empty) — no Linux capabilities granted
- `SystemCallFilter=@system-service` with `@privileged @resources` removed
- `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` — no raw sockets, no
  netlink, no AF_PACKET

Verify the hardening with `systemd-analyze security threat-intel-api.service`.
Target score is ≤ 2.0 ("OK") — the default envelope lands around 1.6.
