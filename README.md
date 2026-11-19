# LogLens

Zero-dependency Java CLI that parses web server access logs, summarizes traffic,
and flags brute-force and flood attacks.

## Run it

Requires JDK 17+. From the project root:

```bash
javac -d out src/*.java
java -cp out Main
```

Choose `1` (press Enter for the bundled `sample_access.log`), then `2` for the report
or `3` to export `audit_report.txt`.

To regenerate the sample data: `java tools/GenerateLog.java`

## Sample output

```
====================================================
LOGLENS AUDIT REPORT
====================================================
Source file    : sample_access.log
Total requests : 500
Malformed lines: 0

TOP 5 ENDPOINTS
Endpoint                         Hits
/api/items                        132
/login                             60
/static/app.js                     49
/index.html                        45
/                                  40

STATUS DISTRIBUTION
Code   Meaning                Count   Share
200    OK                       382   76.4%
301    Moved Permanently         23    4.6%
401    Unauthorized              60   12.0%
404    Not Found                 20    4.0%
500    Server Error              15    3.0%

ANOMALIES
[BRUTE_FORCE] 203.0.113.66     60 failed auth attempts (401/403)
[RATE_LIMIT ] 198.51.100.7     90 requests within 10s

```

## Architecture

- `LogEntry`: immutable record for one parsed log line
- `LogParser`: compiled regex and streaming reader; skips malformed lines
- `Analyzer`: `Map.merge()` counters, top-K min-heap, two anomaly detectors
- `Main`: CLI menu only, no analysis logic

## How detection works

- **Brute force:** flags any IP with more than 10 `401`/`403` responses
- **Flooding:** flags any IP with more than 50 requests inside a 10-second sliding window

Two detectors are needed because the attacks look different. The brute-forcer sends
about one request per second (never trips the rate limit) but fails 60 logins. The
flooder gets `200`s (no auth failures) but sends 90 requests in 10 seconds.

## Complexity

- Parse and count: O(N) over log lines
- Top-K endpoints: O(D log K), where D is the number of distinct endpoints (min-heap of size K)
- Rate detection: O(M log M) per IP for the sort, then an O(M) sliding-window scan

## Limitations

Fixed thresholds, one log format (Common Log Format), and the whole file is held in memory.
