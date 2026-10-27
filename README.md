# isa-dnsproxy

Filtering DNS proxy: receives DNS queries over UDP and TCP, answers some of them locally
(blocklist, zone files) and forwards the rest to a DNS-over-HTTPS resolver.

Author: Kristián Lupták (xluptak00), VUT FIT, ISA 2026/27


## Build and run

```
make                       # builds ./isa-dnsproxy (needs libcurl)
make test                  # test.sh, run with sudo
./isa-dnsproxy -u https://cloudflare-dns.com/dns-query [-a ADDR] [-p PORT] [-z ZONEFILE]... [-b BLOCKLIST]... [-w SECONDS] [--insecure]
```

| Option | Meaning |
|---|---|
| `-u URL` | DoH resolver URL (required) |
| `-a ADDR` | listen address, IPv4 or IPv6 literal, default: all |
| `-p PORT` | listen port, default 53 |
| `-z FILE` | zone file, repeatable |
| `-b FILE` | blocklist file, repeatable |
| `-w SEC` | upstream timeout in seconds, default 3 |
| `--insecure` | do not verify the resolver's certificate and host name |
| `--help` | usage |



Standard output: one log line per message, `<timestamp> <client> <qname> <qtype> <verdict> <rcode>`.
Standard error: `listening on …`, `outstanding upstream request cap: N`, warnings and errors.

## Design

### Architecture and concurrency
One process, one thread, one `poll()` loop (timeout 25 ms) that watches the UDP and TCP listening
sockets and the accepted TCP connections. Nothing blocks:
local answers are produced immediately, forwarded queries are handed to libcurl (multi interface)
and answered when the transfer completes. libcurl's sockets are not polled,

### Libraries
| Library | URL | Version | License | Responsibility |
|---|---|---|---|---|
| libcurl | https://curl.se/libcurl/ | 8.5.0 | curl license (MIT/X-style) | HTTPS client: TLS, HTTP/2, the multi interface for concurrent DoH requests |

### Message processing
Every message goes through the same numbered steps (parse the header, check OPCODE/QDCOUNT/CLASS,
EDNS, zone lookup, blocklist, forward).

Response header: QR=1, OPCODE/RD/CD copied from the query, RA=1, AD=Z=0, AA=1 only for local answers.
The question is copied byte for byte when it parsed.

### UDP size and truncation
Limit is 512 bytes without OPT, otherwise the client's advertised size clamped to 512..1232.
An answer that does not fit becomes a truncated response (TC=1): header, question and our own OPT,
no records. TCP answers are never truncated.

### Blocklist
Lines are domain names or `<address> <name>` (hosts format); comments with `#`. Names are stored
lowercase without a trailing dot; a query is blocked if it or any of its parent domains is listed.
Blocked queries get NXDOMAIN (AA=0, no authority section).

Storage: open-addressing hash table with double hashing. The capacity is a prime number and grows to
the next prime when the load factor exceeds 0.675. A lookup hashes each suffix of the query name
(`a.b.example.com`, `b.example.com`, `example.com`, `com`), so it costs O(number of labels) probes.

### Zone files
Supported record types: A, AAAA, NS, CNAME, SOA, MX (all other types are skipped but
their owner name still exists). Answers from a zone are authoritative (AA=1):
- positive answer: records in the answer section, empty authority section;
- NODATA / NXDOMAIN: the zone's SOA in the authority section, TTL = min(SOA TTL, SOA MINIMUM);
- CNAME chains are followed inside the zone (at most 8 hops); a loop or a target outside the zone
  ends the chain with NOERROR;
- ANY returns every supported record set of the name;
- the zone with the longest matching apex wins; names in a loaded zone are never blocked or forwarded.

Storage: the same kind of label tree (rightmost label first). Each node has its own label and a
linked list of the entries (records) of that name; apex nodes are flagged.

### Forwarding (RFC 8484)
HTTP/2 `POST` with `Content-Type` and `Accept: application/dns-message`. The upstream query is the
client's query with ID 0; the client's ID is restored in the answer. The certificate and host name
are verified against `SSL_CERT_FILE` unless `--insecure` is given. Redirects are not followed. Any
failure (resolve, connect, TLS, timeout, non-2xx status, malformed body, request cap reached,
shutdown) is answered with SERVFAIL. At most 128 requests are outstanding; the cap is printed at start.
On SIGINT/SIGTERM in-flight queries get SERVFAIL and the process exits with status 0.

## Testing
`test.sh` starts the proxy on `PORT` (default 15353)
and a fake DoH upstream written in Python, and checks messages byte by byte: CLI errors, blocklist and
zone-file parsing, malformed messages, local answers, blocking, forwarding, truncation, timeouts, the
request cap, shutdown and TLS verification. Run it with `sudo make test`.

Tested against `https://cloudflare-dns.com/dns-query`. RFC 8484 usage is verified by the test suite (the fake upstream checks POST, both headers, the body and ID 0) and by the real run below: the proxy only accepts a 2xx answer with a matching question, and it returned the real addresses of example.com.

### Packet capture excerpt
Captured with tcpdump, decoded with tshark, query: dig @127.0.0.1 -p 15353 example.com A. <client> is the machine's own IPv6 address.

``` bash
   31   7.824217    127.0.0.1 → 127.0.0.1    DNS 100 Standard query 0x02a0 A example.com OPT
   35   8.138161 <client> → 2606:4700::6810:f8f9 TLSv1 609 Client Hello (SNI=cloudflare-dns.com)
   37   8.171168 2606:4700::6810:f8f9 → <client> TLSv1.3 2722 Server Hello, Change Cipher Spec, Application Data
   39   8.382443 <client> → 2606:4700::6810:f8f9 TLSv1.3 172 Change Cipher Spec, Application Data
   40   8.382824 <client> → 2606:4700::6810:f8f9 TLSv1.3 178 Application Data
   41   8.382965 <client> → 2606:4700::6810:f8f9 TLSv1.3 252 Application Data
   43   8.413789 2606:4700::6810:f8f9 → <client> TLSv1.3 661 Application Data, Application Data
   45   8.415510 2606:4700::6810:f8f9 → <client> TLSv1.3 253 Application Data
   46   8.415510 2606:4700::6810:f8f9 → <client> TLSv1.3 195 Application Data
   49   8.533784 <client> → 2606:4700::6810:f8f9 TLSv1.3 123 Application Data
   50   8.533943    127.0.0.1 → 127.0.0.1    DNS 120 Standard query response 0x02a0 A example.com A 104.20.23.154 A 172.66.147.243 OPT
```

## Known limitations
- **Duplicate zone apex:** if two zone files define the same apex, the program does not reject it. 
- **`--help` priority:** `--help` is only recognised when all other arguments are valid. With a malformed argument the program exits with status 64 instead of printing the usage and exiting with 0.
- **Unsupported records**: ANY at a name that has only unsupported record types answers NOERROR with no records.
- **Answer latency:** a forwarded answer can wait up to 25 ms for the next poll wake-up

## Use of AI
This project used Claude (Anthropic) as reviewer, explainer and generator of supporting material.
The core program code in `*.c` / `*.h` was written by the author; AI-generated parts are marked with comments in the files.

| File / part | Tool | What it did |
|---|---|---|
| `test.sh` | Claude | wrote the automated test suite and the fake DoH upstream |
| `zone_types` enum and and the static table in zonefile_h: | Claude | IANA QTYPE table |
| help text in common.h | Claude | usage message wording |
| `CHANGELOG.md` | Claude | draft of structure and wording, checked and modified by the author |
| this `README.md` | Claude | draft of structure and common parts; some sections were rewritten by author |
| code review | Claude | Point out probable mistakes based on tests in files, fixes were written by author |
| comments | Claude | AI was used to create doxygen comments for functions |
| explaining RFCs | Claude | Claude was used to explain parts of RFCs |
| looking up information | Claude | looked up documentation and its source |
| checking the resovler| Claude| explained how to capture and read the tcpdump/tshark output | 

## References

1. MOCKAPETRIS, P. *Domain names - implementation and specification*. RFC 1035. IETF, 1987.
2. HOFFMAN, P., McMANUS, P. *DNS Queries over HTTPS (DoH)*. RFC 8484. IETF, 2018.
3. DAMAS, J., GRAFF, M., VIXIE, P. *Extension Mechanisms for DNS (EDNS(0))*. RFC 6891. IETF, 2013.
4. THOMSON, S. et al. *DNS Extensions to Support IP Version 6*. RFC 3596. IETF, 2003.
5. ANDREWS, M. *Negative Caching of DNS Queries (DNS NCACHE)*. RFC 2308. IETF, 1998.
6. IANA. *Domain Name System (DNS) Parameters* (resource record types). https://www.iana.org/assignments/dns-parameters
7. STENBERG, D. et al. *libcurl - the multi interface*. https://curl.se/libcurl/c/libcurl-multi.html

## License
MIT, see `LICENSE`.