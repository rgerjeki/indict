# indict

`indict` is an OSINT indicator enrichment and triage tool. You give it one
indicator (an IPv4/IPv6 address, a domain, a file hash, or a URL) and it does the
tedious part of triage for you: it detects the type, queries several OSINT
sources at once, normalizes their very different responses into one consistent
shape, correlates the results into a picture of related infrastructure, and
prints a readable report with an aggregated verdict.

The point is speed and correlation. Instead of pasting the same indicator into
six browser tabs and holding the results in your head, you run one command and
get the whole picture, including the pivots that turn a single indicator into a
map of the infrastructure around it.

```
indict example.com
indict 8.8.8.8 --json report.json
indict 44d88612fea8a8f36de82e1278abb02f --markdown -
indict evil-phish.example --redact --markdown ticket.md
```

## What makes it useful

- One command, many sources. Each source is a small module that returns the same
  normalized result, so adding a source does not change anything downstream.
- Graceful degradation. It runs with zero API keys (crt.sh, DNS, WHOIS/RDAP,
  GreyNoise, MalwareBazaar, urlscan). Add a key and the matching source lights up.
  A source that is missing a key, is not applicable, or errors out is reported as
  such, never silently dropped.
- Correlation, not just a dump. It pivots from the indicator to related
  infrastructure (subdomains from certificate transparency, resolved IPs, reverse
  DNS) and clusters them so you can see, for example, that a set of subdomains all
  sit on the same hosting IP.
- An aggregated verdict with the evidence behind it (clean, suspicious,
  malicious, or unknown), not a raw score you have to interpret.
- Output for people and for machines: a rich terminal report, `--json` for
  piping, and `--markdown` for pasting straight into a ticket.
- A `--redact` flag that strips PII (WHOIS registrant names and emails) so a
  report is safe to share.

## Install

`indict` targets Python 3.11 or newer.

```
git clone https://github.com/rgerjeki/indict
cd indict
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

Then copy the example environment file and add any keys you have (it works
without them):

```
cp .env.example .env
```

## Sources

| Source | Types | Key | What it gives you |
| --- | --- | --- | --- |
| DNS | ip, domain | none | A/AAAA/MX/NS/TXT records, reverse DNS (PTR) |
| WHOIS (RDAP) | ip, domain | none | Registrar, registration date, nameservers, network/org, domain age |
| crt.sh | domain | none | Subdomains from certificate transparency logs |
| GreyNoise (community) | ip | none | Benign/malicious classification, scanner/noise labels |
| MalwareBazaar | hash | none* | Whether a hash is a known malware sample, and its family |
| urlscan.io | domain, url | none | Public scan history and the IPs a host served from |
| AbuseIPDB | ip | free tier | Abuse confidence score and report volume |
| VirusTotal | ip, domain, hash, url | free tier | Multi-engine detection counts |

\* MalwareBazaar (abuse.ch) has begun requiring an auth key on some endpoints.
`indict` sends one if `MALWAREBAZAAR_API_KEY` is set, and degrades gracefully if
an anonymous request is rejected.

## How it works

The pipeline is deliberately linear and easy to follow:

1. **Detect** (`indicators.py`): classify and normalize the input. This also
   refangs defanged indicators, so `hxxps://evil[.]com` is understood as a URL.
2. **Enrich** (`sources/`): every source that supports the type and is available
   runs in parallel. Each returns a `SourceResult`: the same shape every time,
   with a verdict, a summary, normalized data, cite-out links, and any pivots it
   found.
3. **Correlate** (`correlate.py`): the pivots from all sources are deduplicated
   and clustered. For a domain, subdomains are resolved and grouped by hosting IP.
   For an IP, the domains that name it are grouped together.
4. **Aggregate** (`verdict.py`): the overall verdict is the most severe verdict
   any source actively made, with the per-source evidence attached. Silence never
   becomes a verdict: if nothing flagged the indicator and nothing cleared it, the
   result stays unknown.
5. **Render** (`report.py`): the same report becomes a terminal view, JSON, or
   Markdown.

Keeping one normalized shape is the whole trick. It is what lets six services
with wildly different APIs look like one tool, and it is what makes correlation
and a single verdict possible.

### The correlation story

Enrichment tells you facts about the indicator in isolation. Correlation is the
analyst move on top of that. Take a domain: crt.sh gives you subdomains that were
never in a DNS answer you asked for, DNS gives you the IPs the domain resolves to,
and urlscan gives you IPs it has historically served from. On their own those are
three lists. `indict` resolves the subdomains and clusters everything by IP, so
what you actually see is "these hosts all live on this one address," which is the
shape of a hosting footprint. That clustering is the thing a raw dump of six API
responses will not hand you.

## Example runs

The clearest way to see the point is a clean verdict and a malicious one, same
tool, same one-line command. The terminal output is colorized (green for clean,
red for malicious); it is shown here in plain text.

### A clean IP

`8.8.8.8` is Google's public DNS resolver. Two sources actively clear it, which
is what makes the overall verdict `CLEAN` rather than `unknown`. Note that
AbuseIPDB shows reports exist but with zero confidence: the tool surfaces both
numbers so you can judge them, instead of hiding the nuance.

```
$ indict 8.8.8.8

╭────────────────────────╮
│ 8.8.8.8  (ip)   CLEAN  │
╰────────────────────────╯
Sources
┏━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ source     ┃ verdict ┃ summary                                              ┃
┡━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ dns        │ unknown │ reverse DNS: dns.google                              │
│ whois      │ unknown │ network GOGL, org Google LLC                         │
│ greynoise  │ unknown │ not observed by GreyNoise (no scanning activity)     │
│ abuseipdb  │ clean   │ abuse confidence 0/100 from 120 report(s)            │
│ virustotal │ clean   │ 0/91 engines flagged malicious                       │
└────────────┴─────────┴──────────────────────────────────────────────────────┘
╭─ Verdict evidence ───────────────────────────────────────────────╮
│   • [clean] abuseipdb: abuse confidence 0/100 from 120 report(s)  │
│   • [clean] virustotal: 0/91 engines flagged malicious            │
╰──────────────────────────────────────────────────────────────────╯
Correlated infrastructure
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ domains on this IP   ┃ related indicators         ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 8.8.8.8  (2)         │ dns.google, google.com     │
└──────────────────────┴────────────────────────────┘
```

That correlation row stitches two sources together: `dns.google` came from the
reverse DNS lookup, `google.com` from AbuseIPDB's domain field.

### A malicious hash

This is the [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/)
hash, a harmless industry-standard string that every engine is built to flag. It
is the safe way to demonstrate a `MALICIOUS` verdict. VirusTotal carries the call;
MalwareBazaar degrades cleanly into "Not run" because abuse.ch now gates its API
behind a free key.

```
$ indict 44d88612fea8a8f36de82e1278abb02f

╭───────────────────────────────────────────────────────╮
│ 44d88612fea8a8f36de82e1278abb02f  (hash)   MALICIOUS  │
╰───────────────────────────────────────────────────────╯
Sources
┏━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ source     ┃ verdict   ┃ summary                            ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ virustotal │ malicious │ 64/73 engines flagged malicious    │
└────────────┴───────────┴────────────────────────────────────┘
╭─ Verdict evidence ──────────────────────────────────────────╮
│   • [malicious] virustotal: 64/73 engines flagged malicious │
╰─────────────────────────────────────────────────────────────╯
╭─ Not run ───────────────────────────────────────────────────╮
│   • malwarebazaar: needs a free abuse.ch auth key            │
│     (set MALWAREBAZAAR_API_KEY)                              │
╰─────────────────────────────────────────────────────────────╯
```

(Both runs used a VirusTotal and AbuseIPDB key. With no keys at all, those rows
move to the "Not run" panel and the keyless sources still run.)

A redacted Markdown sample report for a benign domain also lives in
[`examples/example.com.report.md`](examples/example.com.report.md), generated
with:

```
indict example.com --redact --markdown examples/example.com.report.md
```

## Configuration

Configuration comes from the environment, and from a `.env` file if present (real
environment variables win). Every value is optional.

| Variable | Purpose |
| --- | --- |
| `VIRUSTOTAL_API_KEY` | Enables the VirusTotal source |
| `ABUSEIPDB_API_KEY` | Enables the AbuseIPDB source |
| `MALWAREBAZAAR_API_KEY` | Optional abuse.ch auth key |
| `INDICT_CACHE_DIR` | Where the local response cache lives (default `.cache`) |
| `INDICT_CACHE_TTL` | Cache lifetime in seconds (default 86400) |
| `INDICT_HTTP_TIMEOUT` | Per-request timeout in seconds (default 20) |

### CLI flags

```
indict INDICATOR [options]

  --json PATH        write JSON to PATH ('-' for stdout)
  --markdown PATH    write a Markdown report to PATH ('-' for stdout)
  --redact           strip PII (WHOIS names/emails) for shareable output
  --no-cache         ignore and do not write the local response cache
  --no-correlate     skip live subdomain resolution during correlation
  --only SOURCES     comma-separated source names to run (e.g. dns,crt.sh)
  --env-file PATH    path to the .env file (default: .env)
  -q, --quiet        suppress the terminal report (useful with --json)
  --version
```

## Data handling and safety

This tool touches other people's data and, potentially, real investigations. The
design keeps sensitive material out of the repository:

- `.env`, the response cache, and any real output are gitignored. Put real runs
  in a gitignored `runs/` or `reports/` directory.
- The cache stays local. Many third-party terms of service forbid rehosting their
  data, so cached responses never leave your machine.
- Sources are cited, not mirrored. The report shows "VirusTotal: 12/70" and links
  out, rather than copying anyone's dataset.
- `--redact` strips WHOIS PII from shareable output.
- The only sample indicators used anywhere in this repo are publicly documented
  benign well-knowns (like `example.com`). Never a real victim, a personal
  domain, or work data.

## Development

```
pip install -e ".[dev]"
pytest        # all tests use mocked or canned responses, no live network calls
ruff check .
```

The tests mock HTTP with `respx` and exercise the DNS source through its pure
result builders, so the suite is fully hermetic.

## Layout

```
src/indict/
  cli.py            argument parsing and orchestration (parallel source runs)
  indicators.py     type detection, normalization, refanging
  models.py         the normalized result shapes (SourceResult, Pivot, Report)
  config.py         .env / environment loading
  cache.py          local JSON response cache
  http.py           shared HTTP client with 429 backoff
  redact.py         PII stripping for --redact
  sources/          one module per source, all returning SourceResult
  correlate.py      pivot deduplication and clustering
  verdict.py        aggregation into clean/suspicious/malicious/unknown
  report.py         terminal, JSON, and Markdown rendering
```

## License

MIT. See [LICENSE](LICENSE).
