# CloudEdge-AI-SOAR — Log Agent

Multi-threaded Linux log collector. Tails `syslog`, `auth.log`, and web
server access logs, extracts IOCs (IPs, hashes, domains), and ships
encrypted, signed event batches to the Cloud Edge Gateway (Cloudflare
Worker) for AI-driven threat classification.

## Architecture

```
 ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
 │ SourceWorker│   │ SourceWorker│   │ SourceWorker│   (1 thread per source)
 │  (syslog)   │   │   (auth)    │   │    (web)    │
 └──────┬──────┘   └──────┬──────┘   └──────┬──────┘
        │  parse + IOC-enrich each line      │
        └──────────────┬─────────────────────┘
                        ▼
              bounded thread-safe Queue
                        │
                        ▼
                 ┌─────────────┐
                 │   Shipper   │  batches, AES-256-GCM encrypts,
                 │  (1 thread) │  HMAC-SHA256 signs, POSTs w/ retry
                 └──────┬──────┘
                        ▼
          Cloud Edge Gateway (Cloudflare Worker)
```

## Running locally

```bash
cd log-agent
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# generate a real AES-256 key instead of the placeholder in config.yaml:
python -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"

export CLOUDEDGE_ENDPOINT="https://your-worker.workers.dev/ingest"
export CLOUDEDGE_HMAC_SECRET="$(openssl rand -hex 32)"
export CLOUDEDGE_AES_KEY_B64="<paste key from above>"

PYTHONPATH=src python src/main.py --config config/config.yaml
```

## Running tests

```bash
PYTHONPATH=src pytest tests/ -v
```

## Running in Docker

```bash
docker build -t cloudedge-log-agent .
docker run -d \
  -e CLOUDEDGE_ENDPOINT="https://your-worker.workers.dev/ingest" \
  -e CLOUDEDGE_HMAC_SECRET="..." \
  -e CLOUDEDGE_AES_KEY_B64="..." \
  -v /var/log:/var/log:ro \
  -v cloudedge-state:/var/lib/cloudedge-agent \
  cloudedge-log-agent
```

## Production deployment (systemd)

See `systemd/cloudedge-agent.service`. Copy secrets into
`/etc/cloudedge-agent/agent.env` (mode `0600`, owned by the `cloudedge`
user), then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cloudedge-agent
```

## Design notes

- **Rotation-safe tailing** — each worker stats the source file every poll;
  an inode change or file shrink triggers a reopen from offset 0, matching
  the behavior of filebeat/promtail.
- **Crash-safe resume** — offsets are persisted to `state.json` (atomic
  write via temp-file + `os.replace`) so a restart resumes exactly where
  it left off instead of re-ingesting or skipping lines.
- **Encryption + signing are independent** — AES-GCM gives confidentiality
  and its own built-in authentication tag; the additional HMAC signature
  lets the gateway reject bad requests (wrong secret, replay, tampering)
  before spending a decrypt cycle on them.
- **Backpressure** — the shared queue is bounded (`queue_max_size`). If the
  gateway is slow/down, the queue fills and new events are dropped at the
  collector with a logged warning, rather than the process growing memory
  unbounded. Ship the `dead_letter.ndjson` file out-of-band during a
  prolonged outage if you need zero event loss.
