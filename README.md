# goscan

Fast, simple TCP connect scanner + reporting.

## Features

- Ports: `-p 80,443,5900-5905`
- Targets (comma-separated): hostname, IP, CIDR, range
  - Examples: `example.com,192.168.1.1,192.168.2.1-100,10.10.10.0/24`
- Targets file: `-tf targets.txt` (one per line; supports comments + comma-separated entries)
- Concurrency + timeout controls
- Output formats: text, CSV, JSON
- Optional summary (text output)
- JSON summary output (`--summary-json`)
- CSV aggregation (`--group-by target|port`)
- Web-mode shortcuts: `--web` + `--emit urls|hostport`
- Import mode: ingest **Nmap XML** (`-oX`) and generate consistent summaries/reports

> Only scan systems you are authorized to test.

## Build

```bash
go build -o goscan .
```

## Scan (TCP connect)

```bash
./goscan -p 80,443,5900-5905 -t "example.com,192.168.1.1,192.168.2.1-100,10.10.10.0/24" -c 1000 -timeout 200

# Read targets from a file
./goscan -p 22,80,443 -tf targets.txt

# CSV output, open-only
./goscan -p 22,80,443 -tf targets.txt --format csv --out results.csv --only-open

# CSV aggregated by target (open ports per host)
./goscan -p 1-1024 -tf targets.txt --format csv --group-by target --out by-target.csv

# CSV aggregated by port (prevalence)
./goscan -p 1-1024 -tf targets.txt --format csv --group-by port --out by-port.csv

# JSON output
./goscan -p 22,80,443 -t "192.168.1.0/24" --format json --out results.json

# JSON output with summary
./goscan -p 1-1024 -t "192.168.1.0/24" --format json --summary-json --out results+summary.json

# Web-mode: common web/admin ports + emit clean URL list (no HTTP requests performed)
./goscan --web -tf targets.txt --emit urls --only-open --out web-urls.txt

# Web-mode: emit host:port list
./goscan --web -tf targets.txt --emit hostport --only-open --out web-hostports.txt
```

## Import Nmap XML

Run Nmap however you like (including any pivot/proxy method you prefer) and save XML:

```bash
nmap -sV -oX scan.xml 10.0.0.0/24
```

Then import and generate reports:

```bash
./goscan --import nmap-xml --in scan.xml --format text
./goscan --import nmap-xml --in scan.xml --format csv --out report.csv
./goscan --import nmap-xml --in scan.xml --format json --out report.json

# Import + web-filter + emit URLs
./goscan --import nmap-xml --in scan.xml --web --emit urls --out web-urls.txt
```

## Text output format

Lines are formatted as:

```
target/proto:port state [reason]
```

For imported Nmap XML, service fields may be included.
