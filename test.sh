#!/usr/bin/env bash
# BEGIN AI-GENERATED CODE
# Tool: Claude (Anthropic). Purpose: automated tests for isa-dnsproxy, one file, one section per area
# (supporting test artifact, not part of the proxy). Listed in README "Use of AI".
#
# Usage: tests/run_tests.sh               run every section
#        tests/run_tests.sh cli           only the command-line section
#        tests/run_tests.sh blocklist     only the blocklist-parsing section
#        tests/run_tests.sh zone          only the zone-file-parsing section
#        tests/run_tests.sh messages      only the message-processing section (steps 1-9, headers, OPT, log, TCP)
#        tests/run_tests.sh local         only the zone-answer section (positive/negative answers, CNAME, ANY, truncation, zone vs. blocklist)
#        tests/run_tests.sh blocked       only the blocklist-verdict section (fake upstream must never see a blocked name)
#        tests/run_tests.sh forward       only the DoH forwarding section (fake upstream: POST format, errors, truncation, -w, cap, shutdown, TLS)
#        BIN=/path/to/isa-dnsproxy PORT=15353 tests/run_tests.sh   (the fake upstream uses PORT+1..PORT+3)
# Run it with sudo: the cli section also checks port 1 and the default port 53 (skipped without root).
# Needs bash, python3, awk, timeout, openssl (TLS part of forward). Exit status 0 = everything passed.
#
# Every output line is tagged with its section:   ok   [cli] ...     FAIL [blocklist] ...
# To add a section: write a section_<name>() function below and list <name> in SECTIONS.

BIN="${BIN:-./isa-dnsproxy}"
PORT="${PORT:-15353}"
SECTIONS="cli blocklist zone messages local blocked forward"
T="$(mktemp -d)"
PROXY=""
trap '[ -n "$PROXY" ] && kill -9 $PROXY 2>/dev/null; [ -n "$UPPIDS" ] && kill -9 $UPPIDS 2>/dev/null; rm -rf "$T"' EXIT

declare -A P F          # pass / fail counters per section
SEC=""
ok()  { P[$SEC]=$(( ${P[$SEC]:-0} + 1 )); echo "  ok   [$SEC] $1"; }
bad() { F[$SEC]=$(( ${F[$SEC]:-0} + 1 )); echo "  FAIL [$SEC] $1${2:+  -> $2}"; }
banner() { SEC="$1"; echo; echo "################ SECTION: $1 ################"; }

# fexpect "description" FILE REGEX  -> some line of FILE matches;  fexpect_not -> no line matches
fexpect()     { if grep -Eq -- "$3" "$2"; then ok "$1"; else bad "$1" "file has: $(head -c 300 "$2" | tr '\n' '|')"; fi; }
fexpect_not() { if grep -Eq -- "$3" "$2"; then bad "$1" "unexpected line: $(grep -Em1 -- "$3" "$2")"; else ok "$1"; fi; }

[ -x "$BIN" ] || { echo "binary $BIN not found - run make first"; exit 2; }

# ======================================================================================
# helpers of section "cli"
# ======================================================================================
# usage_error "args..."  -> must exit 64 and print something on stderr, nothing on stdout
usage_error() {
  timeout 3 "$BIN" "$@" >"$T/o" 2>"$T/e"; local rc=$?
  if [ $rc -eq 64 ] && [ -s "$T/e" ] && [ ! -s "$T/o" ]; then ok "exit 64 + stderr message: $*"
  else bad "expected EX_USAGE: $*" "rc=$rc stdout=$(wc -c <"$T/o")B stderr=$(wc -c <"$T/e")B"; fi
}

# starts_ok "args..." -> must still be running after 1 s and print 'listening on'
starts_ok() {
  "$BIN" "$@" >"$T/o" 2>"$T/e" & local pid=$!
  sleep 1
  if kill -0 $pid 2>/dev/null && grep -q '^listening on ' "$T/e"; then ok "accepted: $*"
  else bad "valid command line rejected: $*" "$(head -c 150 "$T/e" | tr '\n' '|')"; fi
  kill -TERM $pid 2>/dev/null; wait $pid 2>/dev/null
}

# starts_line "regex" args... -> like starts_ok, but a stderr line must also match the regex
starts_line() {
  local re="$1"; shift
  "$BIN" "$@" >"$T/o" 2>"$T/e" & local pid=$!
  sleep 1
  if kill -0 $pid 2>/dev/null && grep -Eq "$re" "$T/e"; then ok "accepted, printed /$re/: $*"
  else bad "start-up check /$re/: $*" "$(head -c 150 "$T/e" | tr '\n' '|')"; fi
  kill -TERM $pid 2>/dev/null; wait $pid 2>/dev/null
}

section_cli() {
  banner cli
  HAVE6=0
  python3 -c "import socket;socket.socket(socket.AF_INET6).bind(('::1',0))" 2>/dev/null && HAVE6=1
  IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1
  U="https://x.test/dns"

  echo "== help"
  "$BIN" -h >"$T/o" 2>"$T/e"; rc=$?
  [ $rc -eq 0 ] && ok "-h exits 0" || bad "-h exit status" "rc=$rc"
  [ -s "$T/o" ] && ok "-h prints usage on stdout" || bad "-h printed nothing on stdout"
  [ ! -s "$T/e" ] && ok "-h prints nothing on stderr" || bad "-h wrote to stderr"
  for opt in -u -p -a -z -b -w --insecure; do
    grep -q -- "$opt" "$T/o" && ok "usage text mentions $opt" || bad "usage text does not mention $opt"
  done
  "$BIN" --help >"$T/o2" 2>/dev/null; rc=$?
  [ $rc -eq 0 ] && cmp -s "$T/o" "$T/o2" && ok "--help == -h" || bad "--help differs from -h" "rc=$rc"
  "$BIN" -h -p 0 >/dev/null 2>&1; [ $? -eq 0 ] && ok "-h wins over invalid options (before them)" || bad "-h before invalid options"
  "$BIN" -p 0 -w 0 -u ftp://bad --help >/dev/null 2>&1; [ $? -eq 0 ] && ok "--help wins over invalid options (after them)" || bad "--help after invalid options"

  echo "== -u"
  usage_error                                  # no arguments at all
  usage_error -p 5300                          # -u missing
  usage_error -u                               # -u without value
  usage_error -u ""                            # empty URL
  usage_error -u ftp://x.test/dns
  usage_error -u x.test/dns
  usage_error -u "$U" -u "$U"                  # repeated single-valued option

  echo "== -p"
  usage_error -u "$U" -p 0
  usage_error -u "$U" -p 65536
  usage_error -u "$U" -p -1
  usage_error -u "$U" -p abc
  usage_error -u "$U" -p 53x
  usage_error -u "$U" -p ""
  usage_error -u "$U" -p
  usage_error -u "$U" -p 1 -p 2

  echo "== -w"
  usage_error -u "$U" -w 0
  usage_error -u "$U" -w 3601
  usage_error -u "$U" -w -5
  usage_error -u "$U" -w 1.5
  usage_error -u "$U" -w abc
  usage_error -u "$U" -w
  usage_error -u "$U" -w 2 -w 3

  echo "== -a"
  usage_error -u "$U" -a localhost
  usage_error -u "$U" -a "[::1]"
  usage_error -u "$U" -a 999.1.1.1
  usage_error -u "$U" -a "fe80::1%lo"
  usage_error -u "$U" -a ""
  usage_error -u "$U" -a
  usage_error -u "$U" -a 127.0.0.1 -a 127.0.0.2

  echo "== other invalid command lines"
  usage_error -u "$U" --bogus
  usage_error -u "$U" stray-argument
  usage_error -u "$U" -z
  usage_error -u "$U" -b
  usage_error -u "$U" --insecure=1

  echo "== valid command lines start"
  starts_ok -u http://127.0.0.1:1/dns -p $PORT -a 127.0.0.1
  starts_ok -u https://x.test/dns -p $PORT -a 127.0.0.1 -w 1
  starts_ok -u https://x.test/dns -p $PORT -a 127.0.0.1 -w 3600
  starts_ok -u https://x.test/dns -p $PORT -a 127.0.0.1 --insecure
  starts_ok -w 5 --insecure -a 127.0.0.1 -p $PORT -u https://x.test/dns        # any option order
  starts_line '^listening on 127\.0\.0\.1:65535$' -u "$U" -p 65535 -a 127.0.0.1   # upper port bound
  starts_line '^listening on 0\.0\.0\.0:'$PORT'$'  -u "$U" -p $PORT -a 0.0.0.0     # wildcard IPv4
  if [ $HAVE6 -eq 1 ]; then
    starts_line '^listening on \[::1\]:'$PORT'$' -u "$U" -p $PORT -a ::1
    starts_line '^listening on \[::\]:'$PORT'$'  -u "$U" -p $PORT -a ::           # wildcard IPv6
  else
    echo "  skip IPv6 start-up tests (no IPv6 on this machine)"
  fi
  if [ $IS_ROOT -eq 1 ]; then
    starts_line '^listening on 127\.0\.0\.1:1$' -u "$U" -p 1 -a 127.0.0.1         # lower port bound (root)
  else
    echo "  skip -p 1 (needs root: run with sudo)"
  fi

  echo "== defaults"
  if [ $IS_ROOT -eq 1 ]; then
    starts_line '^listening on [^ ]*:53$' -u "$U" -a 127.0.0.1                        # default -p is 53
    if python3 -c "
import socket,sys
for t in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, t); s.bind(('0.0.0.0', 53)); s.close()
" 2>/dev/null; then
      starts_line '^listening on (0\.0\.0\.0|\[::\]):53$' -u "$U"                 # default -a is all addresses
    else
      echo "  skip default -a on port 53 (something already listens on port 53, e.g. systemd-resolved)"
    fi
  else
    echo "  skip default port 53 (needs root: run with sudo)"
  fi
  # default -a (no -a): must print at least one listening line on a wildcard address
  if [ $HAVE6 -eq 1 ]; then
    starts_line '^listening on (0\.0\.0\.0|\[::\]):'$PORT'$' -u "$U" -p $PORT
  fi

  # default -w is 3 s, -w 1 is 1 s: measured against an upstream that accepts and never answers
  cat >"$T/blackhole.py" <<'PY'
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(16)
keep = []
while True:
    keep.append(s.accept()[0])
PY
  cat >"$T/q.py" <<'PY'
import socket, sys, time
q = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(10)
t = time.time(); s.sendto(q, ("127.0.0.1", int(sys.argv[1])))
try:
    r = s.recvfrom(4096)[0]; print("%.1f %d" % (time.time() - t, r[3] & 15))
except socket.timeout:
    print("NONE")
PY
  python3 "$T/blackhole.py" 18099 & BH=$!
  sleep 0.3
  check_timeout() { # check_timeout "desc" min max args...
    local desc="$1" lo="$2" hi="$3"; shift 3
    "$BIN" -u http://127.0.0.1:18099/dns -p $PORT -a 127.0.0.1 "$@" >"$T/o" 2>"$T/e" & local pid=$!
    sleep 1
    local out; out=$(python3 "$T/q.py" $PORT)
    kill -TERM $pid 2>/dev/null; wait $pid 2>/dev/null
    # expected: "<seconds> 2"  (SERVFAIL = RCODE 2)
    if awk -v o="$out" -v lo="$lo" -v hi="$hi" 'BEGIN{split(o,a," "); exit !(a[2]==2 && a[1]>=lo && a[1]<=hi)}'; then ok "$desc (SERVFAIL after ${out%% *} s)"
    else bad "$desc" "got: $out (wanted SERVFAIL after $lo..$hi s)"; fi
  }
  check_timeout "default -w is 3 s" 2.8 4.2
  check_timeout "-w 1 times out after 1 s" 0.8 2.2 -w 1
  kill $BH 2>/dev/null; wait $BH 2>/dev/null

  echo "== -z / -b"
  printf '$ORIGIN a.test.\n$TTL 60\n@ IN SOA ns.a.test. r.a.test. 1 2 3 4 5\nh IN A 1.2.3.4\n' >"$T/a.zone"
  printf '$ORIGIN b.test.\n$TTL 60\n@ IN SOA ns.b.test. r.b.test. 1 2 3 4 5\nh IN A 1.2.3.4\n' >"$T/b.zone"
  printf 'ads.example.com\n' >"$T/b1.txt"; printf 'tracker.example.net\n' >"$T/b2.txt"
  starts_ok -u "$U" -p $PORT -a 127.0.0.1 -z "$T/a.zone" -z "$T/b.zone"
  starts_ok -u "$U" -p $PORT -a 127.0.0.1 -b "$T/b1.txt" -b "$T/b2.txt"
  starts_ok -u "$U" -p $PORT -a 127.0.0.1 -z "$T/a.zone" -b "$T/b1.txt"
  for kind in z b; do
    timeout 3 "$BIN" -u "$U" -p $PORT -a 127.0.0.1 -$kind /nonexistent/file >"$T/o" 2>"$T/e"; rc=$?
    if [ $rc -eq 78 ] && grep -Eq '^/nonexistent/file:[0-9]+: .+' "$T/e" && [ ! -s "$T/o" ]; then ok "unreadable -$kind file: exit 78 + file:line: message"
    else bad "unreadable -$kind file" "rc=$rc stderr=$(head -c 120 "$T/e" | tr '\n' '|')"; fi
  done

}

# ======================================================================================
# helpers of section "blocklist"  (parsing only: valid files start, invalid files exit 78)
# ======================================================================================
stop() { [ -n "$PROXY" ] && { kill -TERM $PROXY 2>/dev/null; wait $PROXY 2>/dev/null; }; PROXY=""; }

# start_bl file...  -> proxy with -b for every file; waits up to 6 s for the 'listening on' line
start_bl() {
  stop; : >"$T/out"; : >"$T/err"
  local args=(); for f in "$@"; do args+=(-b "$f"); done
  "$BIN" -u http://127.0.0.1:1/dns -w 2 -a 127.0.0.1 -p $PORT "${args[@]}" >"$T/out" 2>"$T/err" &
  PROXY=$!
  for _ in $(seq 1 60); do
    grep -q '^listening on ' "$T/err" && return 0
    kill -0 $PROXY 2>/dev/null || { PROXY=""; return 1; }
    sleep 0.1
  done
  return 1
}

# case_ok "description" 'printf-%b content'  -> file loads without error; leaves proxy running for queries
case_ok() {
  echo "-- $1"
  printf '%b' "$2" >"$T/list.txt"
  start_bl "$T/list.txt" && ok "file accepted" || bad "file rejected" "$(head -c 200 "$T/err" | tr '\n' '|')"
}

# case_err "description" 'content' LINE -> exit 78, "<file>:LINE: message", nothing on stdout, no listening line
case_err() {
  echo "-- $1"
  stop
  printf '%b' "$2" >"$T/bad.txt"
  timeout 6 "$BIN" -u http://127.0.0.1:1/dns -a 127.0.0.1 -p $PORT -b "$T/bad.txt" >"$T/out" 2>"$T/err"; local rc=$?
  [ $rc -eq 78 ] && ok "exit status 78" || bad "exit status" "rc=$rc"
  grep -Eq "^$T/bad\.txt:$3: .+" "$T/err" && ok "stderr has <file>:$3: <message>" || bad "stderr message / line number" "wanted line $3, got: $(head -c 160 "$T/err" | tr '\n' '|')"
  [ ! -s "$T/out" ] && ok "nothing on stdout" || bad "stdout not empty"
  grep -q '^listening on' "$T/err" && bad "printed 'listening on' despite the error" || ok "did not start serving"
}

section_blocklist() {
  banner blocklist
  L126=$(printf 'a.%.0s' $(seq 1 126))      # "a." x 126
  L63=$(printf 'a%.0s' $(seq 1 63))
  L64=$(printf 'a%.0s' $(seq 1 64))

  echo "== comments, whitespace, line endings"
  case_ok "comments cut at the first #" '# whole line comment\nads1.test # trailing comment\nads2.test#glued comment\n   # indented comment\nads3.test\t# tab comment\n'
  case_ok "CRLF line endings" 'crlf1.test\r\ncrlf2.test\r\n\r\ncrlf3.test # c\r\n'
  case_ok "surrounding whitespace, tabs, blank and whitespace-only lines" '\n   \n\t\n   sp1.test   \n\ttab1.test\t\n \t sp2.test \t sp3.test \n'
  case_ok "last line without trailing newline" 'first.test\nlast.test'
  case_ok "only comments and blank lines" '# a\n\n# b\n   \n'

  echo "== several names per line, hosts(5) format"
  case_ok "IPv4 address then several names" '0.0.0.0 h1.test h2.test h3.test\n127.0.0.1\tt1.test\tt2.test\n'
  case_ok "leading IPv6 address (first token with ':') is skipped" ':: v6a.test\n::1 v6b.test v6c.test\nfe80::1 v6d.test\n0:0:0:0:0:0:0:1 v6e.test\n'
  case_ok "first token with ':' is skipped WITHOUT further checks" 'not:an:address!! skipped1.test\n:garbage skipped2.test\n'
  case_ok "names of digits and dots only are ignored (not errors), anywhere on the line" '0.0.0.0 d1.test 1.2.3.4\n999.999.999.999 d2.test\n1.2.3.4.\n12345\n1.2.3\n'
  case_ok "hosts(5) header names are ignored" '127.0.0.1 localhost\n127.0.0.1 localhost.localdomain\n127.0.0.1 local\n255.255.255.255 broadcasthost\n::1 localhost ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\nff02::3 ip6-allhosts\nreal.test\n'
  case_ok "header names are ignored but do not hide other names on the line" '127.0.0.1 localhost after-localhost.test\n'
  case_ok "names like 'localhost.example' or 'mylocal' are ordinary entries" 'localhost.example\nmylocal\nlocal.test\n'

  echo "== other valid forms"
  case_ok "mixed case entries" 'MiXeD.Test\nUPPER.EXAMPLE\n'
  case_ok "trailing dot on the entry" 'dot.test.\n0.0.0.0 dot2.test.\n'
  case_ok "duplicates and overlapping entries" 'dup.test\ndup.test\nDUP.test.\nsub.dup.test\n'
  case_ok "single-label entry" 'zzz\n'

  echo "== allowed characters, label and name limits (valid)"
  case_ok "letters, digits, '-' and '_' in labels" '_dmarc.test\na-b.test\n-lead.test\ntrail-.test\nxn--bcher-kva.test\n1abc.test\na1.2b.test\n9.9.9.9.example\n'
  case_ok "label of exactly 63 characters" "$L63.test\n"
  case_ok "name of exactly 253 characters (127 labels), with and without trailing dot" "${L126}b\n${L126}c.\n"

  echo "== two blocklist files"
  printf 'file1.test\n' >"$T/f1.txt"; printf 'file2.test\n' >"$T/f2.txt"
  start_bl "$T/f1.txt" "$T/f2.txt" && ok "two -b files accepted" || bad "two -b files rejected"

  echo "== format errors (exit 78, <file>:<line>: message, before serving)"
  case_err "label of 64 characters"                    "ok.test\n$L64.test\n"                         2
  case_err "empty label (a..test)"                     'ok.test\na..test\n'                          2
  case_err "leading dot"                               '# c\n\nok.test\n.test\n'                     4
  case_err "lone dot (root)"                           '.\n'                                         1
  case_err "character outside letters/digits/-/_"      'ok.test\nbad!name.test\n'                    2
  case_err "'@' in a name"                             'a@b.test\n'                                  1
  case_err "slash / URL as a name (not the first token)" 'ok.test\n0.0.0.0 http://x.test/path\n'               2
  case_err "wildcard"                                  '*.test\n'                                    1
  case_err "ABP-style entry"                           '||ads.test^\n'                               1
  case_err "allowlist-style entry"                     '@@allow.test\n'                              1
  case_err "non-ASCII byte"                            'ok.test\n\xc3\xbcnicode.test\n'              2
  case_err "':' in a token that is not the first"      '0.0.0.0 ok.test\nok2.test ::1\n'             2
  case_err "':' in the second token of an IPv4 line"   '0.0.0.0 a:b.test\n'                          1
  case_err "bad token after valid ones on the same line" 'a.test b.test c!.test\n'                   1
  case_err "bad token after a leading IPv6 address"    ':: ok.test bad..test\n'                      1
  case_err "bad name in a CRLF file"                   'ok.test\r\nok2.test\r\nbad!.test\r\n'        3
  case_err "bad name on the last line without newline" 'ok.test\nbad!'                               2
  case_err "error after a trailing comment line numbering" 'a.test # x\n# y\n\n   \nbad!.test # z\n' 5
  case_err "name of 254 characters (127 labels)"       "ok.test\n${L126}bb\n"                        2
  case_err "128 labels"                                "ok.test\n${L126}b.c\n"                       2
  case_err "254 characters before the trailing dot" "${L126}bb.\n"                   1
  case_err "tab-separated bad token"                   '0.0.0.0\tok.test\tbad!.test\n'               1
  printf 'ok.test\n' >"$T/good.txt"; printf 'ok2.test\nbad!.test\n' >"$T/bad2.txt"
  echo "-- error in the second of two files names that file"
  timeout 6 "$BIN" -u http://127.0.0.1:1/dns -a 127.0.0.1 -p $PORT -b "$T/good.txt" -b "$T/bad2.txt" >"$T/out" 2>"$T/err"; rc=$?
  [ $rc -eq 78 ] && grep -Eq "^$T/bad2\.txt:2: .+" "$T/err" && ok "78 + second file's name and line" || bad "second-file error" "rc=$rc $(head -c 160 "$T/err" | tr '\n' '|')"

  echo "== large blocklist (start-up within 5 s)"
  awk 'BEGIN{for(i=0;i<200000;i++) printf "0.0.0.0 host%d.sub%d.example.net\r\n", i, i%1000}' >"$T/big.txt"
  t0=$(date +%s%N)
  if start_bl "$T/big.txt"; then
    ms=$(( ($(date +%s%N) - t0) / 1000000 ))
    [ $ms -le 5000 ] && ok "200 000 entries parsed and listening in $ms ms" || bad "start-up too slow" "$ms ms (limit 5000)"
  else bad "200 000-entry file rejected" "$(head -c 200 "$T/err" | tr '\n' '|')"; fi

  stop
}

# ======================================================================================
# helpers of section "zone"  (parsing only: valid files start, invalid files exit 78)
# ======================================================================================
# start_z file...  -> proxy with -z for every file; waits up to 6 s for the 'listening on' line
start_z() {
  stop; : >"$T/out"; : >"$T/err"
  local args=(); for f in "$@"; do args+=(-z "$f"); done
  "$BIN" -u http://127.0.0.1:1/dns -w 2 -a 127.0.0.1 -p $PORT "${args[@]}" >"$T/out" 2>"$T/err" &
  PROXY=$!
  for _ in $(seq 1 60); do
    grep -q '^listening on ' "$T/err" && return 0
    kill -0 $PROXY 2>/dev/null || { PROXY=""; return 1; }
    sleep 0.1
  done
  return 1
}

# zone_ok "description" 'printf-%b content' -> zone is accepted
zone_ok() {
  echo "-- $1"
  printf '%b' "$2" >"$T/zone.z"
  start_z "$T/zone.z" && ok "zone accepted" || bad "zone rejected" "$(head -c 200 "$T/err" | tr '\n' '|')"
}

# zone_err "description" 'content' LINE-REGEX -> exit 78, "<file>:LINE: message", empty stdout, no listening line
zone_err() {
  echo "-- $1"
  stop
  printf '%b' "$2" >"$T/zone.z"
  timeout 6 "$BIN" -u http://127.0.0.1:1/dns -a 127.0.0.1 -p $PORT -z "$T/zone.z" >"$T/out" 2>"$T/err"; local rc=$?
  [ $rc -eq 78 ] && ok "exit status 78" || bad "exit status" "rc=$rc"
  grep -Eq "^$T/zone\.z:$3: .+" "$T/err" && ok "stderr has <file>:$3: <message>" || bad "stderr message / line number" "wanted line $3, got: $(head -c 160 "$T/err" | tr '\n' '|')"
  [ ! -s "$T/out" ] && ok "nothing on stdout" || bad "stdout not empty"
  grep -q '^listening on' "$T/err" && bad "printed 'listening on' despite the error" || ok "did not start serving"
}

section_zone() {
banner zone
H='$ORIGIN z.test.\n$TTL 60\n'                 # lines 1-2
SOA='@ IN SOA ns.z.test. a.z.test. 1 2 3 4 5\n' # line 3
S6='ns.z.test. a.z.test. 1 2 3 4 5'
L64=$(printf 'a%.0s' $(seq 1 64))

echo "== accepted: file structure"
zone_ok "the example from the specification" '$ORIGIN home.lan.\n$TTL 3600\n@       IN SOA   ns1.home.lan. admin.home.lan. 2026091401 7200 3600 1209600 3600\n@       IN NS    ns1\n@       IN MX    10 mail\nns1     IN A     192.168.1.1\nrouter  IN A     192.168.1.1\nrouter  IN AAAA  fd00:cafe::1\nnas     IN A     192.168.1.20\nmail    IN A     192.168.1.25\nmedia   IN CNAME nas\n'
zone_ok "no \$ORIGIN: SOA first with an absolute owner becomes the origin" '$TTL 60\nz.test. IN SOA ns.z.test. a.z.test. 1 2 3 4 5\nwww IN A 1.2.3.4\n@ IN NS ns\n'
zone_ok "no \$TTL at all, every record has its own TTL" '$ORIGIN z.test.\n@ 60 IN SOA ns.z.test. a.z.test. 1 2 3 4 5\nwww 30 IN A 1.2.3.4\n'
zone_ok "SOA is not the first record when \$ORIGIN is given" "${H}www IN A 1.2.3.4\n${SOA}"
zone_ok "comments, blank lines, whitespace-only lines" "; leading comment\n\n   \n\t; indented comment\n${H}${SOA}www IN A 1.2.3.4 ; trailing comment\nwww2 IN A 1.2.3.5;glued comment\n"
zone_ok "CRLF line endings" '$ORIGIN z.test.\r\n$TTL 60\r\n@ IN SOA ns.z.test. a.z.test. 1 2 3 4 5\r\nwww IN A 1.2.3.4\r\n\r\n'
zone_ok "last line without trailing newline" "${H}${SOA}www IN A 1.2.3.4"
zone_ok "tabs and several spaces as separators" '$ORIGIN z.test.\n$TTL\t60\n@\t\tIN\tSOA\tns.z.test.\ta.z.test.\t1 2   3 4\t5\nwww      IN      A       1.2.3.4\n'
zone_ok "mnemonics and IN in any case" "${H}${SOA}a in a 1.2.3.4\nb In AAAA ::1\nc IN Mx 10 a\nd IN ns a\ne IN cName a\n"
zone_ok "IN is optional, TTL is optional" "${H}${SOA}a A 1.2.3.4\nb 30 A 1.2.3.5\nc IN A 1.2.3.6\nd 30 IN A 1.2.3.7\n"
zone_ok "a line starting with whitespace repeats the previous owner" "${H}${SOA}www IN A 1.2.3.4\n    IN A 1.2.3.5\n\tIN AAAA ::1\n  60 IN A 1.2.3.6\n"
zone_ok "the SOA line itself can be followed by a continuation line" "${H}${SOA}  IN NS ns\n  IN MX 10 mail\n"
zone_ok "\$TTL changes for following records" "${H}${SOA}a IN A 1.2.3.4\n\$TTL 120\nb IN A 1.2.3.5\n\$TTL 0\nc IN A 1.2.3.6\n"
zone_ok "explicit TTL overrides \$TTL" "${H}${SOA}a 5 IN A 1.2.3.4\n"
zone_ok "same type, same owner, same TTL several times" "${H}${SOA}a IN A 1.2.3.4\na IN A 1.2.3.5\na 60 IN A 1.2.3.6\n"
zone_ok "different types at one owner may have different TTLs" "${H}${SOA}a 10 IN A 1.2.3.4\na 20 IN AAAA ::1\na 30 IN MX 5 a\n"

echo "== accepted: names"
zone_ok "@, relative and absolute names in owners and in rdata" "${H}${SOA}@ IN NS ns\n@ IN NS ns2.z.test.\n@ IN MX 10 mail\nwww IN CNAME @\nwww2.z.test. IN CNAME www\nx IN CNAME www.z.test.\n"
zone_ok "rdata name outside the zone is fine" "${H}${SOA}out IN CNAME www.example.org.\n@ IN NS ns.example.net.\n@ IN MX 5 mx.example.com.\n"
zone_ok "owner written in different case than the origin" "${H}${SOA}WWW.Z.TEST. IN A 1.2.3.4\nwww.Z.test. IN A 1.2.3.5\n"
zone_ok "deep owners without intermediate records" "${H}${SOA}a.b.c.d IN A 1.2.3.4\n"
zone_ok "owners with digits, hyphen, underscore" "${H}${SOA}_dmarc IN A 1.2.3.4\na-b IN A 1.2.3.5\n1abc IN A 1.2.3.6\nxn--bcher-kva IN A 1.2.3.7\n"
zone_ok "label of exactly 63 characters" "${H}${SOA}${L64%a} IN A 1.2.3.4\n"
zone_ok "CNAME loop and CNAME to a missing name load fine" "${H}${SOA}a IN CNAME b\nb IN CNAME a\nc IN CNAME nowhere\nself IN CNAME self\n"

echo "== accepted: rdata ranges"
zone_ok "SOA counters at their maximum" "${H}@ IN SOA ns.z.test. a.z.test. 4294967295 4294967295 4294967295 4294967295 2147483647\n"
zone_ok "SOA counters zero" "${H}@ IN SOA ns.z.test. a.z.test. 0 0 0 0 0\n"
zone_ok "TTL 0 and TTL 2147483647" "${H}${SOA}a 0 IN A 1.2.3.4\nb 2147483647 IN A 1.2.3.5\n"
zone_ok "\$TTL 2147483647" '$ORIGIN z.test.\n$TTL 2147483647\n@ IN SOA ns.z.test. a.z.test. 1 2 3 4 5\n'
zone_ok "MX preference 0 and 65535" "${H}${SOA}a IN MX 0 a\nb IN MX 65535 a\n"
zone_ok "A boundary addresses" "${H}${SOA}a IN A 0.0.0.0\nb IN A 255.255.255.255\nc IN A 127.0.0.1\n"
zone_ok "AAAA address forms" "${H}${SOA}a IN AAAA ::\nb IN AAAA ::1\nc IN AAAA fd00:cafe::1\nd IN AAAA 2001:db8:0:0:0:0:0:1\ne IN AAAA FD00::ABCD\nf IN AAAA ::ffff:1.2.3.4\n"

echo "== accepted: registered types we do not serve are skipped with a warning"
zone_ok "TXT, SRV, HTTPS, CAA, PTR, DS ... are accepted" "${H}${SOA}t IN TXT \"hello world\"\ns IN SRV 1 1 80 a\nh IN HTTPS 1 .\nc IN CAA 0 issue \"x\"\np IN PTR a\nd IN DS 1 2 3 abcd\n"
fexpect "a warning about the skipped type is printed on stderr" "$T/err" '(TXT|txt)'
zone_ok "unsupported mnemonic in lower case" "${H}${SOA}t in txt hello\n"
zone_ok "skipped records of different types at one owner may have different TTLs" "${H}${SOA}t 10 IN TXT a\nt 20 IN SPF a\nt 30 IN A 1.2.3.4\n"
zone_ok "skipped record next to supported ones at one owner" "${H}${SOA}t IN A 1.2.3.4\nt IN TXT x\nt IN AAAA ::1\n"

echo "== accepted: several zone files"
printf '%b' "${H}${SOA}www IN A 1.2.3.4\n" >"$T/z1.z"
printf '%b' '$ORIGIN y.test.\n$TTL 60\n@ IN SOA ns.y.test. a.y.test. 1 2 3 4 5\nwww IN A 1.2.3.5\n' >"$T/z2.z"
printf '%b' '$ORIGIN lab.z.test.\n$TTL 60\n@ IN SOA ns.lab.z.test. a.lab.z.test. 1 2 3 4 5\npc IN A 10.0.0.5\n' >"$T/z3.z"
echo "-- two zones with different apexes"
start_z "$T/z1.z" "$T/z2.z" && ok "accepted" || bad "rejected" "$(head -c 160 "$T/err" | tr '\n' '|')"
echo "-- nested zones (z.test and lab.z.test)"
start_z "$T/z1.z" "$T/z3.z" && ok "accepted" || bad "rejected" "$(head -c 160 "$T/err" | tr '\n' '|')"
echo "-- nested zones in the opposite order"
start_z "$T/z3.z" "$T/z1.z" && ok "accepted" || bad "rejected" "$(head -c 160 "$T/err" | tr '\n' '|')"

echo "== errors: SOA and origin"
zone_err "no SOA at all" "${H}a IN A 1.2.3.4\n" '[0-9]+'
zone_err "empty file (no SOA)" '' '[0-9]+'
zone_err "two SOA records" "${H}${SOA}${SOA}" 4
zone_err "SOA owner is not the origin" "${H}sub IN SOA ${S6}\n" 3
zone_err "SOA with an absolute owner that is not the origin" "${H}other.test. IN SOA ${S6}\n" 3
zone_err "no \$ORIGIN and a relative SOA owner" "\$TTL 60\nz.test IN SOA ${S6}\n" 2
zone_err "no \$ORIGIN and '@' as owner" "\$TTL 60\n@ IN SOA ${S6}\n" 2
zone_err "no \$ORIGIN and a record before the SOA" "\$TTL 60\nwww.z.test. IN A 1.2.3.4\nz.test. IN SOA ${S6}\n" 2
zone_err "\$ORIGIN after the first record" "\$TTL 60\nz.test. IN SOA ${S6}\n\$ORIGIN z.test.\n" 3
zone_err "\$ORIGIN twice" '$ORIGIN z.test.\n$ORIGIN y.test.\n$TTL 60\n'"${SOA}" 2
zone_err "relative \$ORIGIN" '$ORIGIN z.test\n$TTL 60\n'"${SOA}" 1
zone_err "\$ORIGIN without a value" '$ORIGIN\n'"${SOA}" 1
zone_err "\$ORIGIN with an extra token" '$ORIGIN z.test. extra\n'"${SOA}" 1
zone_err "\$ORIGIN with an invalid name" '$ORIGIN bad!.test.\n'"${SOA}" 1

echo "== errors: \$TTL"
for v in 1h -1 2147483648 abc 1.5 '60 70' ''; do
  zone_err "\$TTL '$v'" "\$ORIGIN z.test.\n\$TTL $v\n${SOA}" 2
done

echo "== errors: owners, types, classes, record form"
zone_err "owner outside the zone" "${H}${SOA}x.other. IN A 1.2.3.4\n" 4
zone_err "owner that only shares a string suffix with the origin" "${H}${SOA}xz.test. IN A 1.2.3.4\n" 4
zone_err "owner above the origin" "${H}${SOA}test. IN A 1.2.3.4\n" 4
zone_err "type not registered with IANA" "${H}${SOA}a IN BOGUSTYPE 1.2.3.4\n" 4
zone_err "class CH" "${H}${SOA}a CH A 1.2.3.4\n" 4
zone_err "class HS" "${H}${SOA}a HS A 1.2.3.4\n" 4
zone_err "owner only" "${H}${SOA}a\n" 4
zone_err "owner and class only" "${H}${SOA}a IN\n" 4
zone_err "no rdata" "${H}${SOA}a IN A\n" 4
zone_err "first record without an owner" "\$ORIGIN z.test.\n\$TTL 60\n  IN SOA ${S6}\n" 3
zone_err "record without TTL and without \$TTL" "\$ORIGIN z.test.\n@ IN SOA ${S6}\n" 2
zone_err "TTL above the maximum" "${H}${SOA}a 2147483648 IN A 1.2.3.4\n" 4
zone_err "TTL with a unit suffix" "${H}${SOA}a 1h IN A 1.2.3.4\n" 4
zone_err "negative TTL" "${H}${SOA}a -1 IN A 1.2.3.4\n" 4
zone_err "label of 64 characters in an owner" "${H}${SOA}${L64} IN A 1.2.3.4\n" 4
zone_err "empty label in an owner" "${H}${SOA}a..b IN A 1.2.3.4\n" 4
zone_err "invalid character in an owner" "${H}${SOA}bad!name IN A 1.2.3.4\n" 4
zone_err "directive \$INCLUDE" "${H}${SOA}\$INCLUDE other.zone\n" 4
zone_err "directive \$GENERATE" "${H}${SOA}\$GENERATE 1-3 h\$ A 1.2.3.\$\n" 4
zone_err "unknown directive" "${H}${SOA}\$FOO bar\n" 4
zone_err "line numbers count comments, blank and CRLF lines" "; c\r\n\r\n${H}${SOA}a IN A 999.1.1.1\r\n" 6

echo "== errors: malformed rdata of the mandatory types"
for v in 999.1.1.1 1.2.3 1.2.3.4.5 abc fd00::1 '1.2.3.4 5.6.7.8' '' ; do
  zone_err "A rdata '$v'" "${H}${SOA}a IN A $v\n" 4
done
for v in ::: 1.2.3.4 zz::1 'fd00::1 fd00::2' 12345::1 ''; do
  zone_err "AAAA rdata '$v'" "${H}${SOA}a IN AAAA $v\n" 4
done
for v in '' 10 65536 -1 abc '10 m extra' 'm 10' '1.5 m'; do
  zone_err "MX rdata '$v'" "${H}${SOA}a IN MX $v\n" 4
done
zone_err "NS without a name" "${H}${SOA}a IN NS\n" 4
zone_err "NS with two names" "${H}${SOA}a IN NS b c\n" 4
zone_err "NS with an invalid name" "${H}${SOA}a IN NS b..c\n" 4
zone_err "CNAME without a target" "${H}${SOA}a IN CNAME\n" 4
zone_err "CNAME with two targets" "${H}${SOA}a IN CNAME b c\n" 4
zone_err "CNAME with a label of 64 characters" "${H}${SOA}a IN CNAME ${L64}\n" 4
for v in "ns.z.test. a.z.test. 1 2 3 4" "ns.z.test. a.z.test. 1 2 3 4 5 6" "ns.z.test. a.z.test. ( 1 2 3 4 5 )" \
         "ns.z.test. a.z.test. 4294967296 2 3 4 5" "ns.z.test. a.z.test. abc 2 3 4 5" "ns.z.test. a.z.test. 1 -2 3 4 5" \
         "ns.z.test. a.z.test. 1 2 3 4294967296 5" "ns.z.test. a.z.test. 1 2 3 4 2147483648" "ns.z.test. a.z.test. 1 2 3 4 5h" \
         "bad!.z.test. a.z.test. 1 2 3 4 5" "ns.z.test. bad!.z.test. 1 2 3 4 5" "ns.z.test." ""; do
  zone_err "SOA rdata '$v'" "${H}@ IN SOA $v\n" 3
done

echo "== errors: consistency rules"
zone_err "one type at one owner with different TTLs (A)" "${H}${SOA}a 10 IN A 1.2.3.4\na 20 IN A 1.2.3.5\n" 5
zone_err "... also when written through a repeated owner" "${H}${SOA}a 10 IN A 1.2.3.4\n 20 IN A 1.2.3.5\n" 5
zone_err "... also when the owner differs only in case" "${H}${SOA}a 10 IN A 1.2.3.4\nA 20 IN A 1.2.3.5\n" 5
zone_err "... also when one TTL comes from \$TTL" "${H}${SOA}a IN A 1.2.3.4\n\$TTL 120\na IN A 1.2.3.5\n" 6
zone_err "... NS records" "${H}${SOA}@ 10 IN NS a\n@ 20 IN NS b\n" 5
zone_err "... MX records" "${H}${SOA}@ 10 IN MX 1 a\n@ 20 IN MX 2 b\n" 5
zone_err "... skipped TXT records" "${H}${SOA}t 10 IN TXT a\nt 20 IN TXT b\n" 5
zone_err "CNAME followed by another record" "${H}${SOA}a IN CNAME b\na IN A 1.2.3.4\n" 5
zone_err "another record followed by CNAME" "${H}${SOA}a IN A 1.2.3.4\na IN CNAME b\n" 5
zone_err "two CNAME records at one owner" "${H}${SOA}a IN CNAME b\na IN CNAME c\n" 5
zone_err "CNAME at the apex (owner of the SOA)" "${H}${SOA}@ IN CNAME b\n" 4
zone_err "CNAME next to a skipped TXT record" "${H}${SOA}a IN TXT x\na IN CNAME b\n" 5
zone_err "CNAME after a skipped TXT written with a repeated owner" "${H}${SOA}a IN TXT x\n   IN CNAME b\n" 5

echo "== errors: several zone files"
printf '%b' "${H}${SOA}www IN A 1.2.3.4\n" >"$T/dup1.z"; printf '%b' "${H}${SOA}other IN A 1.2.3.5\n" >"$T/dup2.z"
stop
timeout 6 "$BIN" -u http://127.0.0.1:1/dns -a 127.0.0.1 -p $PORT -z "$T/dup1.z" -z "$T/dup2.z" >"$T/out" 2>"$T/err"; rc=$?
[ $rc -eq 78 ] && ok "two zones with the same apex: exit 78" || bad "duplicate apex accepted" "rc=$rc"
grep -Eq "^$T/dup[12]\.z:[0-9]+: .+" "$T/err" && ok "... with a <file>:<line>: message" || bad "duplicate apex message" "$(head -c 160 "$T/err" | tr '\n' '|')"
printf '%b' "${H}${SOA}a IN A 999.1.1.1\n" >"$T/bad2.z"
timeout 6 "$BIN" -u http://127.0.0.1:1/dns -a 127.0.0.1 -p $PORT -z "$T/z2.z" -z "$T/bad2.z" >"$T/out" 2>"$T/err"; rc=$?
[ $rc -eq 78 ] && grep -Eq "^$T/bad2\.z:4: .+" "$T/err" && ok "error in the second file names that file and line" || bad "error in second file" "rc=$rc $(head -c 160 "$T/err" | tr '\n' '|')"
stop
}

# ======================================================================================
# section "messages": steps 1-9 of "Message processing", response header rules, OPT, log format, TCP framing
# The proxy runs WITHOUT zones/blocklist and with a dead upstream, so a valid query is forwarded and
# answered SERVFAIL by the proxy itself (that response must still obey the header rules).
# ======================================================================================
section_messages() {
banner messages

# ---------- raw DNS client: prints one line of key=value pairs per reply ----------
cat >"$T/dns.py" <<'PY'
import argparse, socket, struct, sys, time

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33,
         "NAPTR": 35, "DS": 43, "RRSIG": 46, "DNSKEY": 48, "SVCB": 64, "HTTPS": 65, "IXFR": 251,
         "AXFR": 252, "ANY": 255, "CAA": 257}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
num = lambda x: int(x, 0)

p = argparse.ArgumentParser()
p.add_argument("--port", type=int, required=True)
p.add_argument("--proto", default="udp")
p.add_argument("--id", type=num, default=0x1234)
p.add_argument("--opcode", type=num, default=0)
p.add_argument("--qr", type=num, default=0)
p.add_argument("--rd", type=num, default=1)
p.add_argument("--cd", type=num, default=0)
p.add_argument("--flags-or", type=num, default=0)
p.add_argument("--name", default="msg.test")
p.add_argument("--qname-hex")
p.add_argument("--type", default="A")
p.add_argument("--cls", type=num, default=1)
p.add_argument("--qtail", default="full")           # full | half (QTYPE only) | none
p.add_argument("--qd", type=num)
p.add_argument("--an", type=num)
p.add_argument("--ns", type=num)
p.add_argument("--ar", type=num)
p.add_argument("--opt", type=num)                   # advertised UDP size; absent = no OPT
p.add_argument("--opt-version", type=num, default=0)
p.add_argument("--opt-flags", type=num, default=0)
p.add_argument("--opt-rdata-hex", default="")
p.add_argument("--opt-rdlen", type=num)
p.add_argument("--opt-owner-hex", default="00")
p.add_argument("--opt-section", default="ar")       # an | ns | ar
p.add_argument("--opt2", action="store_true")       # append a second, bare OPT
p.add_argument("--extra-rr", default="")            # an | ns | ar: add a harmless A record (owner = pointer to the question)
p.add_argument("--tail-hex", default="")
p.add_argument("--raw")                             # whole message as hex (bypasses the builder)
p.add_argument("--split", action="store_true")      # TCP: send the frame one octet at a time
p.add_argument("--second-valid", action="store_true")
p.add_argument("--pipeline-two", action="store_true")
p.add_argument("--halfclose", default="")           # TCP: frame | prefix
p.add_argument("--timeout", type=float, default=2.0)
a = p.parse_args()

def enc(name):
    name = name.rstrip(".")
    return b"\0" if not name else b"".join(bytes([len(l)]) + l.encode("latin1") for l in name.split(".")) + b"\0"

def tval(t):
    return TYPES[t] if t in TYPES else num(t)

def build():
    qname = bytes.fromhex(a.qname_hex) if a.qname_hex is not None else enc(a.name)
    tail = {"full": struct.pack(">HH", tval(a.type), a.cls), "half": struct.pack(">H", tval(a.type)), "none": b""}[a.qtail]
    qsec = qname + tail
    sec = {"an": b"", "ns": b"", "ar": b""}
    cnt = {"an": 0, "ns": 0, "ar": 0}
    if a.opt is not None:
        rd = bytes.fromhex(a.opt_rdata_hex)
        rdlen = len(rd) if a.opt_rdlen is None else a.opt_rdlen
        sec[a.opt_section] += bytes.fromhex(a.opt_owner_hex) + struct.pack(">HHIH", 41, a.opt, (a.opt_version << 16) | a.opt_flags, rdlen) + rd
        cnt[a.opt_section] += 1
    if a.opt2:
        sec["ar"] += b"\0" + struct.pack(">HHIH", 41, 1232, 0, 0); cnt["ar"] += 1
    if a.extra_rr:
        sec[a.extra_rr] += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 0, 4) + bytes([1, 2, 3, 4]); cnt[a.extra_rr] += 1
    flags = (a.qr << 15) | (a.opcode << 11) | (a.rd << 8) | (a.cd << 4) | a.flags_or
    hdr = struct.pack(">HHHHHH", a.id, flags, 1 if a.qd is None else a.qd,
                      cnt["an"] if a.an is None else a.an, cnt["ns"] if a.ns is None else a.ns,
                      cnt["ar"] if a.ar is None else a.ar)
    return hdr + qsec + sec["an"] + sec["ns"] + sec["ar"] + bytes.fromhex(a.tail_hex), qsec

def skipname(m, i):
    while i < len(m):
        l = m[i]
        if l == 0: return i + 1
        if l & 0xC0 == 0xC0: return i + 2
        i += 1 + l
    raise ValueError

def summarize(r, qsec, lport, ms):
    if len(r) < 12:
        return "resp=SHORT len=%d lport=%d" % (len(r), lport)
    i, f, qd, an, ns, ar = struct.unpack(">HHHHHH", r[:12])
    pos, qok = 12, 0
    try:
        for _ in range(qd): pos = skipname(r, pos) + 4
        if qd >= 1 and qsec is not None: qok = int(r[12:12 + len(qsec)] == qsec)
    except ValueError:
        pass
    nopt, opt, ver, rdl, own, erc = 0, "-", "-", "-", "-", "-"
    try:
        for _ in range(an + ns + ar):
            start = pos; pos = skipname(r, pos)
            t, c, ttl, rdlen = struct.unpack(">HHIH", r[pos:pos + 10]); pos += 10 + rdlen
            if t == 41:
                nopt += 1
                if nopt == 1:
                    opt, erc, ver, rdl = str(c), str(ttl >> 24), str((ttl >> 16) & 255), str(rdlen)
                    own = "root" if r[start] == 0 else "other"
    except (ValueError, struct.error):
        pass
    return ("resp=OK rcode=%s id=%d qr=%d opcode=%d aa=%d tc=%d rd=%d ra=%d z=%d ad=%d cd=%d qd=%d an=%d ns=%d ar=%d "
            "qok=%d nopt=%d opt=%s optrc=%s optver=%s optrdlen=%s optowner=%s len=%d ms=%d lport=%d") % (
        RCODES.get(f & 15, "RCODE%d" % (f & 15)), i, f >> 15, (f >> 11) & 15, (f >> 10) & 1, (f >> 9) & 1,
        (f >> 8) & 1, (f >> 7) & 1, (f >> 6) & 1, (f >> 5) & 1, (f >> 4) & 1, qd, an, ns, ar,
        qok, nopt, opt, erc, ver, rdl, own, len(r), ms, lport)

def recvn(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c: return None
        b += c
    return b

def tcp_read(s, qsec, lport, t0):
    try:
        h = recvn(s, 2)
        if h is None: return "resp=CLOSED lport=%d" % lport
        body = recvn(s, struct.unpack(">H", h)[0])
        if body is None: return "resp=CLOSED lport=%d" % lport
        return summarize(body, qsec, lport, int((time.time() - t0) * 1000))
    except socket.timeout:
        return "resp=NONE lport=%d" % lport
    except ConnectionError:
        return "resp=CLOSED lport=%d" % lport

msg, qsec = (bytes.fromhex(a.raw), None) if a.raw is not None else build()
if a.proto == "udp":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(a.timeout)
    t0 = time.time(); s.sendto(msg, ("127.0.0.1", a.port)); lport = s.getsockname()[1]
    try:
        print(summarize(s.recvfrom(70000)[0], qsec, lport, int((time.time() - t0) * 1000)))
    except socket.timeout:
        print("resp=NONE lport=%d" % lport)
else:
    s = socket.create_connection(("127.0.0.1", a.port)); s.settimeout(a.timeout)
    lport = s.getsockname()[1]
    frame = struct.pack(">H", len(msg)) + msg
    t0 = time.time()
    if a.halfclose:
        s.sendall(frame[:1] if a.halfclose == "prefix" else frame[:2 + len(msg) // 2]); s.close()
        print("resp=HALFCLOSED lport=%d" % lport)
    elif a.pipeline_two:
        both = b""
        for k in (1, 2):
            a.id = k; m2, _ = build(); both += struct.pack(">H", len(m2)) + m2
        s.sendall(both)
        print(tcp_read(s, qsec, lport, t0)); print(tcp_read(s, qsec, lport, t0))
    else:
        if a.split:
            for ch in frame: s.sendall(bytes([ch])); time.sleep(0.005)
        else:
            s.sendall(frame)
        print(tcp_read(s, qsec, lport, t0))
        if a.second_valid:
            v = struct.pack(">HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + enc("msg.test") + struct.pack(">HH", 1, 1)
            s.sendall(struct.pack(">H", len(v)) + v)
            print(tcp_read(s, enc("msg.test") + struct.pack(">HH", 1, 1), lport, time.time()))
PY

# ---------- helpers ----------
D() { python3 -I "$T/dns.py" --port $PORT "$@"; }
m() { echo x >>"$T/sent"; D "$@"; }                       # one message = one expected log line
kv() { sed -n "s/.* $2=\([^ ]*\).*/\1/p" <<<" $1" | head -1; }
chk() { # chk "desc" "reply line" key=value ...
  local d="$1" line="$2" miss="" p k v got; shift 2
  for p in "$@"; do k=${p%%=*}; v=${p#*=}; got=$(kv "$line" "$k"); [ "$got" = "$v" ] || miss="$miss $k=$got(want $v)"; done
  [ -z "$miss" ] && ok "$d" || bad "$d" "${miss# } | $line"
}
chk_ge() { local v; v=$(kv "$2" "$3"); [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge "$4" ] && ok "$1" || bad "$1" "$3=$v (want >= $4)"; }
chk_le() { local v; v=$(kv "$2" "$3"); [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -le "$4" ] && ok "$1" || bad "$1" "$3=$v (want <= $4)"; }
logfix() { # logfix "desc" "reply line" "<qname> <qtype> <verdict> <rcode>"  -> a log line for that client port, fixed-string match
  local lp i; lp=$(kv "$2" lport)
  for i in $(seq 1 20); do grep -Fq -- " 127.0.0.1:$lp $3" "$T/out" && { ok "log: $1  [$3]"; return; }; sleep 0.05; done
  bad "log: $1" "wanted ' 127.0.0.1:$lp $3'; got: $(grep -F ":$lp " "$T/out" | head -2 | tr '\n' '|')"
}
rep() { local out="" i; for ((i=0;i<$2;i++)); do out="$out$1"; done; printf '%s' "$out"; }
T_SUFFIX="0474657374"                                      # label "test"

: >"$T/sent"
start_z || { bad "proxy did not start" "$(head -c 200 "$T/err")"; return; }
[ ! -s "$T/out" ] && ok "stdout is empty before the first message" || bad "stdout not empty at start"
D --id 1 >/dev/null; echo x >>"$T/sent"                    # warm-up query

echo "== steps 1-2: dropped (no response; logged as '- - dropped -')"
for hex in "" ff 1234 123401000001 1234010000010000000000; do
  s=$(m --raw "$hex" --timeout 0.7); chk "$(( ${#hex} / 2 ))-octet datagram gets no response" "$s" resp=NONE
  logfix "$(( ${#hex} / 2 ))-octet datagram" "$s" "- - dropped -"
done
s=$(m --raw 1234100000000000000000 --timeout 0.7); chk "11 octets with OPCODE=STATUS: step 1 comes first -> dropped" "$s" resp=NONE
logfix "11 octets, opcode 2" "$s" "- - dropped -"
s=$(m --qr 1 --timeout 0.7);                       chk "QR=1 with a valid question -> dropped" "$s" resp=NONE;    logfix "QR=1" "$s" "- - dropped -"
s=$(m --raw 123481800000000000000000 --timeout 0.7); chk "QR=1, bare 12-octet header -> dropped" "$s" resp=NONE;  logfix "QR=1 header only" "$s" "- - dropped -"
s=$(m --qr 1 --opcode 2 --qd 0 --timeout 0.7);     chk "QR=1 beats OPCODE and QDCOUNT (step 2 before 3 and 4) -> dropped" "$s" resp=NONE; logfix "QR=1, opcode 2, qd 0" "$s" "- - dropped -"

echo "== step 3: OPCODE != QUERY -> NOTIMP (the question is not parsed, QDCOUNT=0 in the response)"
for op in 1 2 3 4 5 6 15; do
  s=$(m --opcode $op); chk "opcode $op" "$s" resp=OK rcode=NOTIMP opcode=$op qr=1 aa=0 tc=0 ra=1 z=0 ad=0 qd=0 an=0 ns=0 ar=0 qok=0 nopt=0
  logfix "opcode $op" "$s" "- - invalid NOTIMP"
done
s=$(m --opcode 2 --rd 0 --cd 1);  chk "RD and CD are copied into the NOTIMP response" "$s" rcode=NOTIMP rd=0 cd=1 opcode=2
s=$(m --opcode 2 --opt 1232);     chk "no OPT in a response rejected in step 3 even if the query had one" "$s" rcode=NOTIMP ar=0 nopt=0
s=$(m --opcode 2 --qd 0);         chk "step 3 comes before step 4" "$s" rcode=NOTIMP
s=$(m --opcode 2 --qd 7);         chk "step 3 comes before step 4 (QDCOUNT 7)" "$s" rcode=NOTIMP
s=$(m --raw 123410000000000000000000); chk "OPCODE=STATUS in a bare header" "$s" rcode=NOTIMP id=4660 opcode=2

echo "== step 4: QDCOUNT != 1 -> FORMERR"
for n in 0 2 3 65535; do
  s=$(m --qd $n); chk "QDCOUNT=$n" "$s" rcode=FORMERR qd=0 qok=0 an=0 ns=0 ar=0 nopt=0 ra=1 qr=1
  logfix "QDCOUNT=$n" "$s" "- - invalid FORMERR"
done
s=$(m --raw 123401000000000000000000); chk "QDCOUNT=0 in a bare header" "$s" rcode=FORMERR qd=0
s=$(m --qd 2 --tail-hex 01610000010001); chk "two real questions" "$s" rcode=FORMERR qd=0
s=$(m --qd 0 --opt 1232);         chk "no OPT in a response rejected in step 4" "$s" rcode=FORMERR ar=0 nopt=0
s=$(m --opcode 2 --qd 0 --rd 0);  chk "RD copied into a FORMERR/NOTIMP response for a bare header" "$s" rd=0

echo "== step 5: the question does not parse -> FORMERR, QDCOUNT=0 in the response"
LAB63="3f$(rep 61 63)"
bad_names=(
  "40$(rep 61 64)00|label length 64"
  "64$(rep 61 100)00|label length 100"
  "7f$(rep 61 127)00|label length 127"
  "bf$(rep 61 191)00|label length 191 (0xBF)"
  "c00c|compression pointer (0xC00C)"
  "c000|compression pointer (0xC000)"
  "0161c00c|pointer after a label"
  "${LAB63}${LAB63}${LAB63}${LAB63}00|name of 257 octets"
  "${LAB63}${LAB63}${LAB63}3e$(rep 61 62)00|name of 256 octets"
)
for e in "${bad_names[@]}"; do
  s=$(m --qname-hex "${e%%|*}"); chk "${e#*|}" "$s" rcode=FORMERR qd=0 qok=0 ar=0 nopt=0
  logfix "${e#*|}" "$s" "- - invalid FORMERR"
done
s=$(m --raw 123401000001000000000000056162);      chk "name runs past the end of the message" "$s" rcode=FORMERR qd=0
s=$(m --raw 12340100000100000000000005616263646500); chk "name complete, QTYPE and QCLASS missing" "$s" rcode=FORMERR qd=0
s=$(m --qtail none);   chk "QTYPE and QCLASS missing" "$s" rcode=FORMERR qd=0
s=$(m --qtail half);   chk "QCLASS missing" "$s" rcode=FORMERR qd=0
s=$(m --raw 123401000001000000000000); chk "QDCOUNT=1 but the message ends after the header" "$s" rcode=FORMERR qd=0
s=$(m --qname-hex c00c --opt 1232); chk "no OPT in a response rejected in step 5" "$s" rcode=FORMERR ar=0 nopt=0
s=$(m --qname-hex "40$(rep 61 64)00" --cls 3); chk "step 5 comes before step 7 (bad name + CH class)" "$s" rcode=FORMERR
s=$(m --qname-hex "${LAB63}${LAB63}${LAB63}3d$(rep 61 61)00"); chk "name of exactly 255 octets is valid" "$s" rcode=SERVFAIL qd=1 qok=1
s=$(m --qname-hex "${LAB63}0474657374""00"); chk "label of exactly 63 octets is valid" "$s" rcode=SERVFAIL qd=1 qok=1
s=$(m --name .); chk "the root name is a valid question" "$s" rcode=SERVFAIL qd=1 qok=1
logfix "root name" "$s" ". A forwarded SERVFAIL"

echo "== step 6: remaining sections -> FORMERR (question copied, no OPT)"
step6=(
  "--an 1|ANCOUNT=1 with no record"
  "--ns 1|NSCOUNT=1 with no record"
  "--ar 1|ARCOUNT=1 with no record"
  "--ar 3|ARCOUNT=3 with no records"
  "--an 65535|ANCOUNT=65535"
  "--ar 1 --tail-hex 00|record cut after the owner"
  "--ar 1 --tail-hex 000029|record cut inside the fixed fields"
  "--opt 1232 --opt-rdlen 10|OPT with RDLENGTH past the end"
  "--opt 1232 --opt2|two OPT records"
  "--opt 1232 --opt-section an|OPT in the answer section"
  "--opt 1232 --opt-section ns|OPT in the authority section"
  "--opt 1232 --opt-owner-hex 016100|OPT with a non-root owner"
  "--opt 1232 --opt-owner-hex c00c|OPT with a pointer as owner"
)
for e in "${step6[@]}"; do
  s=$(eval "m ${e%%|*}"); chk "${e#*|}" "$s" resp=OK rcode=FORMERR qd=1 qok=1 an=0 ns=0 ar=0 nopt=0 ra=1
  logfix "${e#*|}" "$s" "msg.test. A invalid FORMERR"
done
s=$(m --opt 1232 --opt2 --cls 3);  chk "step 6 comes before step 7 (two OPT + CH class)" "$s" rcode=FORMERR
s=$(m --extra-rr an);   chk "an extra record in the answer section is skipped, not an error" "$s" rcode=SERVFAIL qd=1 qok=1 an=0
s=$(m --extra-rr ns);   chk "an extra record in the authority section is skipped" "$s" rcode=SERVFAIL
s=$(m --extra-rr ar);   chk "an extra non-OPT record in the additional section is skipped" "$s" rcode=SERVFAIL ar=0 nopt=0
s=$(m --extra-rr ar --opt 1232); chk "OPT plus another record: still one OPT" "$s" rcode=SERVFAIL ar=1 nopt=1

echo "== step 7: QCLASS != IN -> NOTIMP (question copied)"
for c in 0 2 3 4 254 255 65535; do
  s=$(m --cls $c); chk "QCLASS=$c" "$s" rcode=NOTIMP qd=1 qok=1 an=0 ns=0 ar=0 nopt=0 qr=1 ra=1
  logfix "QCLASS=$c" "$s" "msg.test. A invalid NOTIMP"
done
s=$(m --cls 255 --type ANY); logfix "QCLASS=ANY, QTYPE=ANY" "$s" "msg.test. ANY invalid NOTIMP"
s=$(m --cls 3 --type AXFR); chk "step 7 comes before step 8 (CH + AXFR)" "$s" rcode=NOTIMP

echo "== step 8: AXFR / IXFR -> REFUSED (question copied)"
for t in AXFR IXFR; do
  s=$(m --type $t); chk "$t" "$s" rcode=REFUSED qd=1 qok=1 an=0 ns=0 ar=0 nopt=0
  logfix "$t" "$s" "msg.test. $t invalid REFUSED"
done

echo "== step 9: everything else is forwarded (upstream down -> SERVFAIL from the proxy); QTYPE shown as IANA mnemonic"
for t in A NS CNAME SOA PTR MX TXT AAAA SRV NAPTR DS RRSIG DNSKEY SVCB HTTPS CAA ANY; do
  s=$(m --type $t); chk "QTYPE $t" "$s" rcode=SERVFAIL qd=1 qok=1 an=0 ns=0 ar=0
  logfix "QTYPE $t" "$s" "msg.test. $t forwarded SERVFAIL"
done
for n in 9999 65280 65534; do
  s=$(m --type $n); logfix "unknown QTYPE $n is logged as TYPE$n" "$s" "msg.test. TYPE$n forwarded SERVFAIL"
done

echo "== header of every response the proxy builds"
s=$(m --id 4660); chk "plain valid query" "$s" resp=OK rcode=SERVFAIL id=4660 qr=1 opcode=0 aa=0 tc=0 rd=1 ra=1 z=0 ad=0 cd=0 qd=1 an=0 ns=0 ar=0 qok=1 nopt=0
for id in 0 1 255 256 43981 65535; do s=$(m --id $id); chk "ID $id copied" "$s" id=$id rcode=SERVFAIL; done
s=$(m --rd 0);          chk "RD=0 copied"  "$s" rd=0 cd=0 ra=1
s=$(m --cd 1);          chk "CD=1 copied"  "$s" rd=1 cd=1
s=$(m --rd 0 --cd 1);   chk "RD=0 CD=1 copied" "$s" rd=0 cd=1
for fl in 0x0400 0x0200 0x0080 0x0040 0x0020 0x06E0; do
  s=$(m --flags-or $fl); chk "query flag bits $fl (AA/TC/RA/Z/AD) are no error, and AA=TC=Z=AD=0 in the response" "$s" rcode=SERVFAIL aa=0 tc=0 ra=1 z=0 ad=0
done
s=$(m --name ExAmPlE.CoM); chk "question copied byte-for-byte (mixed case QNAME)" "$s" rcode=SERVFAIL qok=1
logfix "mixed-case QNAME is logged in lowercase" "$s" "example.com. A forwarded SERVFAIL"
for e in "--opcode 2|NOTIMP" "--qd 0|FORMERR" "--cls 3|NOTIMP" "--type AXFR|REFUSED" "--an 1|FORMERR"; do
  s=$(eval "m ${e%%|*} --id 999"); chk "error response ${e%%|*}: QR=1 RA=1 AA=0 AD=0 Z=0 and the client's ID" "$s" rcode=${e#*|} id=999 qr=1 ra=1 aa=0 ad=0 z=0
done

echo "== OPT in responses"
for sz in 0 1 511 512 1231 1232 1233 4096 65535; do
  s=$(m --opt $sz); chk "query OPT size $sz -> one bare OPT in the response" "$s" rcode=SERVFAIL ar=1 nopt=1 optver=0 optrdlen=0 optowner=root optrc=0
  chk_ge "  ... advertised payload size >= 1232" "$s" opt 1232
done
for v in 1 5 255; do s=$(m --opt 1232 --opt-version $v); chk "query OPT version $v is not checked; response OPT version is 0" "$s" rcode=SERVFAIL optver=0 nopt=1; done
s=$(m --opt 1232 --opt-flags 0x8000);                       chk "DO bit in the query is accepted" "$s" rcode=SERVFAIL nopt=1
s=$(m --opt 1232 --opt-rdata-hex 000a00080102030405060708); chk "query OPT with an option: response OPT has none" "$s" rcode=SERVFAIL nopt=1 optrdlen=0
s=$(m);                                                      chk "no OPT in the query -> none in the response" "$s" ar=0 nopt=0
s=$(m --cls 3 --opt 1232);   chk "step 7 response carries an OPT when the query had one" "$s" rcode=NOTIMP qd=1 ar=1 nopt=1 optver=0 optrdlen=0
s=$(m --type AXFR --opt 1232); chk "step 8 response carries an OPT when the query had one" "$s" rcode=REFUSED qd=1 ar=1 nopt=1 optver=0 optrdlen=0
chk_ge "  ... payload size >= 1232 (step 8)" "$s" opt 1232
s=$(m --cls 3);              chk "step 7 response without OPT when the query had none" "$s" ar=0 nopt=0
s=$(m --type AXFR);          chk "step 8 response without OPT when the query had none" "$s" ar=0 nopt=0

echo "== latency of invalid responses (after the warm-up query)"
s=$(m --opcode 2);   chk_le "NOTIMP within 200 ms" "$s" ms 200
s=$(m --qd 0);       chk_le "FORMERR within 200 ms" "$s" ms 200
s=$(m --type AXFR);  chk_le "REFUSED within 200 ms" "$s" ms 200

echo "== query log: QNAME formatting (lowercase, trailing dot, RFC 1035 escapes)"
while IFS='|' read -r hx exp; do
  [ -z "$hx" ] && continue
  s=$(m --qname-hex "${hx}${T_SUFFIX}00")
  logfix "label bytes $hx" "$s" "$exp A forwarded SERVFAIL"
done <<'ESC'
03612e62|a\.b.test.
03413b42|a\;b.test.
03287829|\(x\).test.
03614062|a\@b.test.
022478|\$x.test.
03227122|\"q\".test.
03615c62|a\\b.test.
03612062|a\032b.test.
03610162|a\001b.test.
03617f62|a\127b.test.
0361ff62|a\255b.test.
0361e962|a\233b.test.
03610062|a\000b.test.
0361217e|a!~.test.
074578416d506c45|example.test.
03612d5f|a-_.test.
03313233|123.test.
ESC

echo "== TCP: two-octet length prefix, same processing as UDP"
s=$(m --proto tcp --id 77);          chk "valid query over TCP" "$s" resp=OK rcode=SERVFAIL id=77 qr=1 ra=1 qd=1 qok=1 ar=0
logfix "TCP valid query" "$s" "msg.test. A forwarded SERVFAIL"
s=$(m --proto tcp --opt 1232);       chk "OPT in the response over TCP" "$s" rcode=SERVFAIL ar=1 nopt=1 optver=0 optrdlen=0
s=$(m --proto tcp --opcode 2);       chk "NOTIMP over TCP" "$s" rcode=NOTIMP qd=0; logfix "TCP opcode 2" "$s" "- - invalid NOTIMP"
s=$(m --proto tcp --qd 0);           chk "FORMERR over TCP (QDCOUNT=0)" "$s" rcode=FORMERR qd=0
s=$(m --proto tcp --cls 3);          chk "NOTIMP over TCP (CH)" "$s" rcode=NOTIMP qd=1 qok=1
s=$(m --proto tcp --type AXFR);      chk "REFUSED over TCP (AXFR)" "$s" rcode=REFUSED qd=1 qok=1; logfix "TCP AXFR" "$s" "msg.test. AXFR invalid REFUSED"
s=$(m --proto tcp --split);          chk "frame sent one octet at a time is reassembled and answered" "$s" resp=OK rcode=SERVFAIL qok=1
logfix "TCP split frame" "$s" "msg.test. A forwarded SERVFAIL"

echo "== TCP: a dropped message closes the connection"
s=$(m --proto tcp --raw 1234010000010000000000);  chk "11-octet frame: no response, connection closed" "$s" resp=CLOSED; logfix "TCP 11 octets" "$s" "- - dropped -"
s=$(m --proto tcp --raw "");                      chk "zero-length frame: connection closed" "$s" resp=CLOSED;            logfix "TCP zero-length frame" "$s" "- - dropped -"
s=$(m --proto tcp --qr 1);                        chk "QR=1: connection closed" "$s" resp=CLOSED;                         logfix "TCP QR=1" "$s" "- - dropped -"

echo "== TCP: several messages on one connection; invalid messages do not close it"
out=$(m --proto tcp --opcode 2 --second-valid); echo x >>"$T/sent"
chk "first message: NOTIMP" "$(sed -n 1p <<<"$out")" rcode=NOTIMP
chk "second message on the same connection is answered" "$(sed -n 2p <<<"$out")" resp=OK rcode=SERVFAIL id=16962 qok=1
logfix "second message" "$(sed -n 2p <<<"$out")" "msg.test. A forwarded SERVFAIL"
out=$(m --proto tcp --type AXFR --second-valid); echo x >>"$T/sent"
chk "REFUSED does not close the connection either" "$(sed -n 2p <<<"$out")" resp=OK rcode=SERVFAIL
out=$(m --proto tcp --pipeline-two); echo x >>"$T/sent"
chk "pipelined queries: first reply" "$(sed -n 1p <<<"$out")" resp=OK rcode=SERVFAIL qok=1
chk "pipelined queries: second reply" "$(sed -n 2p <<<"$out")" resp=OK rcode=SERVFAIL qok=1
ids=$( (kv "$(sed -n 1p <<<"$out")" id; kv "$(sed -n 2p <<<"$out")" id) | sort | tr '\n' ' ')
[ "$ids" = "1 2 " ] && ok "pipelined queries: IDs 1 and 2 each answered once (any order)" || bad "pipelined IDs" "got: $ids"

echo "== TCP: a client that closes in the middle of a message produces no log line"
sleep 0.3; before=$(wc -l <"$T/out")
D --proto tcp --halfclose frame  >/dev/null
D --proto tcp --halfclose prefix >/dev/null
sleep 0.5; after=$(wc -l <"$T/out")
[ "$before" = "$after" ] && ok "no log line for half-sent messages" || bad "log line for a message the client never completed" "$before -> $after lines"
s=$(m --id 5); chk "the proxy still answers afterwards" "$s" rcode=SERVFAIL id=5

echo "== query log: overall checks"
sleep 0.5
sent=$(wc -l <"$T/sent"); got=$(wc -l <"$T/out")
[ "$sent" = "$got" ] && ok "exactly one log line per message ($got messages)" || bad "log lines vs. messages" "sent $sent, logged $got"
badlines=$(grep -vcP '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2}) ((?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-f:]+\]):\d{1,5} (-|\.|(?:(?:[^\sA-Z\\.;()@$"]|\\[0-9]{3}|\\[.;()@$"\\])+\.)+) (-|[A-Z][A-Z0-9-]*|TYPE\d+) (local|blocked|forwarded|invalid|dropped) (-|[A-Z]+|RCODE\d+)$' "$T/out")
[ "$badlines" = "0" ] && ok "every stdout line matches the specification's regex" || bad "stdout lines that do not match the regex" "$badlines: $(grep -vP '^\d{4}-' "$T/out" | head -2 | tr '\n' '|')"
ts=$(head -1 "$T/out" | cut -d' ' -f1); tsn=$(date -d "$ts" +%s 2>/dev/null || echo 0); now=$(date +%s)
[ $(( now - tsn )) -lt 300 ] && [ $(( tsn - now )) -lt 300 ] && ok "timestamp is the current time ($ts)" || bad "timestamp" "$ts"
grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(Z|[+-][0-9]{2}:[0-9]{2}) ' "$T/out" && ok "timestamp has seconds precision and a numeric offset or Z" || bad "timestamp format"
stop
}

# ======================================================================================
# shared tools of the sections "local", "blocked" and "forward"
#   rr.py  query client that decodes the whole response (header, answer and authority records)
#   up.py  fake DoH upstream (HTTP/1.1 POST, optionally TLS); the FIRST LABEL of the queried name
#          selects its behaviour; every request is appended to $T/upreq
# ======================================================================================
tools_init() {
cat >"$T/rr.py" <<'PY'
import argparse, socket, struct, sys, time
TN = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA"}
TV = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "ANY": 255, "HTTPS": 65}
RC = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
p = argparse.ArgumentParser()
p.add_argument("--port", type=int, required=True)
p.add_argument("--proto", default="udp")
p.add_argument("--name", required=True)
p.add_argument("--type", default="A")
p.add_argument("--opt", type=int)
p.add_argument("--id", type=int, default=0x4242)
p.add_argument("--hex", action="store_true")        # print the query (ID 0) as hex and exit
p.add_argument("--timeout", type=float, default=3.0)
a = p.parse_args()

def enc(n):
    n = n.rstrip(".")
    return b"\0" if not n else b"".join(bytes([len(l)]) + l.encode("latin1") for l in n.split(".")) + b"\0"

qsec = enc(a.name) + struct.pack(">HH", TV[a.type], 1)
def build(i):
    m = struct.pack(">HHHHHH", i, 0x0100, 1, 0, 0, 1 if a.opt is not None else 0) + qsec
    if a.opt is not None:
        m += b"\0" + struct.pack(">HHIH", 41, a.opt, 0, 0)
    return m
msg = build(a.id)
if a.hex:
    print(build(0).hex()); sys.exit(0)

def name(m, i):
    labels, end, hops = [], None, 0
    while True:
        l = m[i]
        if l == 0:
            i += 1; break
        if l & 0xC0 == 0xC0:
            if end is None: end = i + 2
            i = ((l & 0x3F) << 8) | m[i + 1]; hops += 1
            if hops > 50: raise ValueError("pointer loop")
            continue
        labels.append(m[i + 1:i + 1 + l].decode("latin1").lower()); i += 1 + l
    return ".".join(labels) + ".", (end if end is not None else i)

def rdata(m, t, i, n):
    if t == 1: return socket.inet_ntop(socket.AF_INET, m[i:i + 4])
    if t == 28: return socket.inet_ntop(socket.AF_INET6, m[i:i + 16])
    if t in (2, 5): return name(m, i)[0]
    if t == 15: return "%d %s" % (struct.unpack(">H", m[i:i + 2])[0], name(m, i + 2)[0])
    if t == 6:
        mn, j = name(m, i); rn, j = name(m, j)
        return "%s %s %s" % (mn, rn, " ".join(str(x) for x in struct.unpack(">IIIII", m[j:j + 20])))
    return m[i:i + n].hex()

def show(r, lport, ms):
    if len(r) < 12: print("HDR resp=SHORT lport=%d ms=%d" % (lport, ms)); return
    i, f, qd, an, ns, ar = struct.unpack(">HHHHHH", r[:12])
    qok = int(r[12:12 + len(qsec)] == qsec)
    pos = 12
    for _ in range(qd): pos = name(r, pos)[1] + 4
    lines, nopt, osz = [], 0, "-"
    for sec, cnt in (("AN", an), ("NS", ns), ("AR", ar)):
        for _ in range(cnt):
            own, pos = name(r, pos)
            t, c, ttl, n = struct.unpack(">HHIH", r[pos:pos + 10]); pos += 10
            if t == 41:
                nopt += 1; osz = c
            else:
                lines.append("%s %s %s %d %s" % (sec, own, TN.get(t, "TYPE%d" % t), ttl, rdata(r, t, pos, n)))
            pos += n
    print("HDR resp=OK rcode=%s id=%d aa=%d tc=%d rd=%d ra=%d ad=%d qd=%d an=%d ns=%d ar=%d qok=%d nopt=%d optsize=%s len=%d lport=%d ms=%d" % (
        RC.get(f & 15, "RCODE%d" % (f & 15)), i, (f >> 10) & 1, (f >> 9) & 1, (f >> 8) & 1, (f >> 7) & 1,
        (f >> 5) & 1, qd, an, ns, ar, qok, nopt, osz, len(r), lport, ms))
    for l in lines: print(l)

def rd(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c: raise ConnectionError
        b += c
    return b

t0 = time.time()
try:
    if a.proto == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(a.timeout)
        s.sendto(msg, ("127.0.0.1", a.port)); lport = s.getsockname()[1]
        show(s.recvfrom(70000)[0], lport, int((time.time() - t0) * 1000))
    else:
        s = socket.create_connection(("127.0.0.1", a.port)); s.settimeout(a.timeout)
        lport = s.getsockname()[1]
        s.sendall(struct.pack(">H", len(msg)) + msg)
        show(rd(s, struct.unpack(">H", rd(s, 2))[0]), lport, int((time.time() - t0) * 1000))
except socket.timeout:
    print("HDR resp=NONE lport=0 ms=%d" % int((time.time() - t0) * 1000))
except (ConnectionError, ValueError, IndexError, struct.error) as e:
    print("HDR resp=BROKEN err=%s lport=0 ms=%d" % (e, int((time.time() - t0) * 1000)))
PY

cat >"$T/up.py" <<'PY'
import argparse, re, socket, ssl, struct, threading, time, zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
p = argparse.ArgumentParser()
p.add_argument("--port", type=int, required=True)
p.add_argument("--log", required=True)
p.add_argument("--cert"); p.add_argument("--key")
a = p.parse_args()
lock = threading.Lock()

def logline(s):
    with lock:
        with open(a.log, "a") as f: f.write(s + "\n")

def labels_of(b, pos):
    out = []
    while b[pos]:
        l = b[pos]; out.append(b[pos + 1:pos + 1 + l].decode("latin1")); pos += 1 + l
    return out, pos + 1

def enc(labels):
    return b"".join(bytes([len(l)]) + l.encode("latin1") for l in labels) + b"\0"

def addr(name):
    c = zlib.crc32(name.lower().encode()) & 0xffffff
    return bytes([10, c >> 16, (c >> 8) & 255, c & 255])

def build(req, kind):
    rid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", req[:12])
    lab, pos = labels_of(req, 12)
    qt, qc = struct.unpack(">HH", req[pos:pos + 4])
    name = ".".join(lab).lower()
    qlab = [l.upper() for l in lab] if kind == "caseq" else lab
    if kind == "wrongq": qlab = ["wrong"] + lab
    qtype = qt + 1 if kind == "wrongtype" else qt
    question = enc(qlab) + struct.pack(">HH", qtype, qc)
    f = 0x8000 | (flags & 0x0100) | 0x0080
    if kind == "ad": f |= 0x0020
    if kind == "qr0": f &= ~0x8000
    if kind == "op1": f |= 1 << 11
    rc = {"nx": 3, "servfail": 2, "refused": 5}.get(kind, 0)
    f |= rc
    answers, cnt = b"", 0
    if rc == 0 and qt in (1, 255):
        for i in range(40 if kind == "big" else 1):
            answers += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 37, 4) + (addr(name) if i == 0 else bytes([10, 200, 0, i])); cnt += 1
    auth, nsc = b"", 0
    if kind == "nx":
        auth = b"\0" + struct.pack(">HHIH", 6, 1, 37, 22) + b"\0\0" + bytes(20); nsc = 1
    opt, arc = b"", 0
    if ar > 0 or kind == "ad":
        opt = b"\0" + struct.pack(">HHIH", 41, 1452, 0, 0); arc = 1
    body = struct.pack(">HHHHHH", rid, f, 0 if kind == "qd0" else 1, cnt, nsc, arc) + (b"" if kind == "qd0" else question) + answers + auth + opt
    if kind == "short": body = b"12345"
    if kind == "empty": body = b""
    return body

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *x): pass
    def reply(self, code, body=b"", ctype="application/dns-message", extra=()):
        self.send_response(code)
        if body: self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra: self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        logline("REQ method=GET path=%s ct=- accept=%s id=- q=- t=- len=0 hex=-" % (self.path.replace(" ", "_"), self.headers.get("Accept", "-")))
        self.reply(200, b"x", "text/plain")
    def do_POST(self):
        req = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        try:
            lab, pos = labels_of(req, 12); qt = struct.unpack(">H", req[pos:pos + 2])[0]
            rid = struct.unpack(">H", req[:2])[0]
        except Exception:
            lab, qt, rid = ["?"], 0, -1
        logline("REQ method=POST path=%s ct=%s accept=%s id=%d q=%s. t=%d len=%d hex=%s" % (
            self.path.replace(" ", "_"), self.headers.get("Content-Type", "-"), self.headers.get("Accept", "-"), rid,
            ".".join(lab).lower(), qt, len(req), (b"\0\0" + req[2:]).hex()))
        first = lab[0].lower()
        m = re.match(r"delay(\d+)$", first)
        kind = "ok" if m else first
        if m: time.sleep(int(m.group(1)))
        if kind == "close":
            self.close_connection = True
            try: self.connection.shutdown(socket.SHUT_RDWR)
            except Exception: pass
            return
        if kind == "r500": return self.reply(500, b"oops", "text/plain")
        if kind == "r404": return self.reply(404, b"nope", "text/plain")
        if kind == "redir": return self.reply(302, b"", "text/plain", [("Location", "/redir-target")])
        if kind == "r204": return self.reply(204, b"")
        self.reply(200, build(req, kind))

class S(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128
    def handle_error(self, *x): pass

srv = S(("127.0.0.1", a.port), H)
if a.cert:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(a.cert, a.key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
srv.serve_forever()
PY
}

UPPIDS=""
UP=$((PORT + 1)); UPS=$((PORT + 2)); UPB=$((PORT + 3))
# up_start [port cert key]  -> fake upstream; waits until it accepts connections
up_start() {
  local port="${1:-$UP}"
  python3 -I "$T/up.py" --port $port --log "$T/upreq" ${2:+--cert "$2" --key "$3"} 2>/dev/null &
  UPPIDS="$UPPIDS $!"
  for _ in $(seq 1 50); do
    python3 -c "import socket;socket.create_connection(('127.0.0.1',$port),0.2).close()" 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}
up_stop() { [ -n "$UPPIDS" ] && kill $UPPIDS 2>/dev/null; wait $UPPIDS 2>/dev/null; UPPIDS=""; }

# start_f args...  -> proxy in front of the fake upstream. FURL overrides -u, FENV is passed to env(1).
start_f() {
  stop; : >"$T/out"; : >"$T/err"; : >"$T/lsent"; LBASE=0
  env ${FENV:--u SSL_CERT_FILE} "$BIN" -u "${FURL:-http://127.0.0.1:$UP/dns}" -a 127.0.0.1 -p $PORT "$@" >"$T/out" 2>"$T/err" &
  PROXY=$!
  for _ in $(seq 1 60); do
    grep -q '^listening on ' "$T/err" && return 0
    kill -0 $PROXY 2>/dev/null || { PROXY=""; return 1; }
    sleep 0.1
  done
  return 1
}

lkv() { sed -n "s/.* $2=\([^ ]*\).*/\1/p" <<<" $1" | head -1; }
lq() { python3 -I "$T/rr.py" --port $PORT "$@"; }
ea() { python3 -c "import zlib,sys;c=zlib.crc32(sys.argv[1].lower().encode())&0xffffff;print('10.%d.%d.%d'%(c>>16,(c>>8)&255,c&255))" "$1"; }

# lt "desc" "proto name type [opt|-]" "header k=v ..." "answer RRs, | separated" "authority RRs" "verdict rcode"
#   answer/authority are compared as sets, or in order when ORD=1. opt defaults to 1232, '-' sends no OPT.
#   Optional environment: REQS=n (upstream must have seen exactly n requests for this name),
#   LAT=ms / LATMIN=ms (answer time bounds).
lt() {
  local desc="$1" proto qn qt opt; read -r proto qn qt opt <<<"$2"
  local eh="$3" ean="$4" ens="$5" elog="$6"
  [ -z "$opt" ] && opt=1232
  local args=(--proto $proto --name "$qn" --type $qt)
  if [ "$opt" = "-" ]; then eh="$eh nopt=0"; else args+=(--opt $opt); eh="$eh nopt=1"; fi
  echo "-- $desc"
  local out hdr; out=$(lq "${args[@]}"); hdr=$(head -1 <<<"$out")
  local bads="" kvp k v g
  for kvp in $eh; do k=${kvp%%=*}; v=${kvp#*=}; g=$(lkv "$hdr" "$k"); [ "$g" = "$v" ] || bads="$bads $k=$g(want $v)"; done
  if [ "$opt" != "-" ]; then g=$(lkv "$hdr" optsize); [[ "$g" =~ ^[0-9]+$ ]] && [ "$g" -ge 1232 ] || bads="$bads optsize=$g(want >=1232)"; fi
  [ -z "$bads" ] && ok "header" || bad "header" "${bads# }"
  local sec exp act
  for sec in AN NS; do
    if [ $sec = AN ]; then exp="$ean"; else exp="$ens"; fi
    act=$(awk -v s=$sec '$1==s { sub(/^[A-Z]+ /, ""); print }' <<<"$out")
    exp=$(tr '|' '\n' <<<"$exp" | sed '/^$/d')
    if [ -z "$ORD" ]; then act=$(sort <<<"$act" | sed '/^$/d'); exp=$(sort <<<"$exp"); fi
    [ "$act" = "$exp" ] && ok "$([ $sec = AN ] && echo answer || echo authority) section" \
      || bad "$([ $sec = AN ] && echo answer || echo authority) section" "got: $(tr '\n' '|' <<<"$act") want: $(tr '\n' '|' <<<"$exp")"
  done
  local lp name_re; lp=$(lkv "$hdr" lport)
  name_re=$(tr 'A-Z' 'a-z' <<<"${qn%.}" | sed 's/\./\\./g')
  local found=0
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    grep -Eq " 127\.0\.0\.1:$lp ${name_re}\. $qt $elog\$" "$T/out" && { found=1; break; }
    sleep 0.1
  done
  [ $found = 1 ] && ok "log: $qt $elog" || bad "log line" "wanted '127.0.0.1:$lp ${qn%.}. $qt $elog'; stdout has: $(tail -2 "$T/out" | tr '\n' '|')"
  if [ -n "$REQS" ]; then
    local n; n=$(grep -c -- " q=${name_re}\. " "$T/upreq" 2>/dev/null)
    [ "$n" = "$REQS" ] && ok "upstream saw $n request(s) for this name" || bad "upstream requests for this name" "got $n, want $REQS"
  fi
  local ms; ms=$(lkv "$hdr" ms)
  if [ -n "$LAT" ]; then [[ "$ms" =~ ^[0-9]+$ ]] && [ "$ms" -lt "$LAT" ] && ok "answered in $ms ms (< $LAT)" || bad "answer time" "$ms ms, want < $LAT"; fi
  if [ -n "$LATMIN" ]; then [[ "$ms" =~ ^[0-9]+$ ]] && [ "$ms" -ge "$LATMIN" ] && ok "answered after $ms ms (>= $LATMIN)" || bad "answer time" "$ms ms, want >= $LATMIN"; fi
  echo x >>"$T/lsent"
}

# lcount "desc": one log line per query sent through lt, every line valid
lcount() {
  sleep 0.3
  local sent total got; sent=$(wc -l <"$T/lsent"); total=$(wc -l <"$T/out"); got=$(( total - LBASE ))
  [ "$sent" = "$got" ] && ok "$1: exactly one log line per query ($got)" || bad "$1: log lines vs. queries" "sent $sent, logged $got"
  : >"$T/lsent"; LBASE=$total
}

# upcheck "desc" qname type [opt]  -> the last upstream request for qname is a correct RFC 8484 POST
upcheck() {
  echo "-- $1"
  local re line g exp; re=$(tr 'A-Z' 'a-z' <<<"$2" | sed 's/\./\\./g')
  line=$(grep -- " q=${re}\. " "$T/upreq" | tail -1)
  [ -n "$line" ] || { bad "no upstream request for $2"; return; }
  [ "$(lkv "$line" method)" = POST ] && ok "method POST" || bad "method" "$(lkv "$line" method)"
  [ "$(lkv "$line" path)" = /dns ] && ok "path of the -u URL (/dns)" || bad "path" "$(lkv "$line" path)"
  [ "$(lkv "$line" ct)" = application/dns-message ] && ok "Content-Type application/dns-message" || bad "Content-Type" "$(lkv "$line" ct)"
  [ "$(lkv "$line" accept)" = application/dns-message ] && ok "Accept application/dns-message" || bad "Accept" "$(lkv "$line" accept)"
  [ "$(lkv "$line" id)" = 0 ] && ok "ID 0 in the upstream query (SHOULD)" || bad "ID in the upstream query is not 0 (SHOULD)" "$(lkv "$line" id)"
  local oargs=(); [ -n "$4" ] && oargs=(--opt $4)
  exp=$(lq --name "$2" --type "$3" "${oargs[@]}" --hex)
  [ "$(lkv "$line" hex)" = "$exp" ] && ok "query relayed unchanged except the ID" || bad "query body differs from the client's query" "got $(lkv "$line" hex) want $exp"
}

# ======================================================================================
# section "local": answers served from zone files (no upstream is ever needed; it is dead)
# ======================================================================================
# start_l args...  -> proxy with the given options (dead upstream); waits up to 6 s for 'listening on'
start_l() {
  stop; : >"$T/out"; : >"$T/err"; LBASE=0
  "$BIN" -u http://127.0.0.1:1/dns -w 2 -a 127.0.0.1 -p $PORT "$@" >"$T/out" 2>"$T/err" &
  PROXY=$!
  for _ in $(seq 1 60); do
    grep -q '^listening on ' "$T/err" && return 0
    kill -0 $PROXY 2>/dev/null || { PROXY=""; return 1; }
    sleep 0.1
  done
  return 1
}

section_local() {
banner local

tools_init

# ---------- zones ----------
# l.test: SOA TTL 900 > MINIMUM 600, so negative answers carry TTL 600
cat >"$T/l.zone" <<'EOF'
$ORIGIN l.test.
$TTL 300
@        900 IN SOA   ns1 admin 2026101601 7200 3600 1209600 600
@        IN NS    ns1
@        IN NS    ns2.other.example.
@        IN MX    10 mail
@        IN MX    20 mail2.other.example.
@        IN A     192.0.2.1
ns1      IN A     192.0.2.53
ns1      IN AAAA  2001:db8::53
mail     IN A     192.0.2.25
www      7200 IN A 192.0.2.80
www      7200 IN A 192.0.2.81
www      7200 IN AAAA 2001:db8::80
Mixed    IN A     192.0.2.7
alias    IN CNAME mail
alias2   IN CNAME alias
alias3   IN CNAME alias2
out      IN CNAME elsewhere.example.
missing  IN CNAME nothere.l.test.
loop1    IN CNAME loop2
loop2    IN CNAME loop1
self     IN CNAME self
xz       IN CNAME h.sub.l.test.
xzmiss   IN CNAME nothere.sub.l.test.
toapex   IN CNAME @
txtonly  IN TXT   hello
a.b.c    IN A     192.0.2.99
EOF
for i in $(seq 1 12); do echo "hop$i IN CNAME hop$((i+1))" >>"$T/l.zone"; done
echo "hop13 IN A 192.0.2.13" >>"$T/l.zone"
# m.test: SOA TTL 100 < MINIMUM 600, so negative answers carry TTL 100
printf '%s\n' '$ORIGIN m.test.' '$TTL 60' '@ 100 IN SOA ns.m.test. a.m.test. 1 2 3 4 600' 'host IN A 192.0.2.200' >"$T/m.zone"
# sub.l.test: nested inside l.test
printf '%s\n' '$ORIGIN sub.l.test.' '$TTL 60' '@ 50 IN SOA ns a 1 2 3 4 50' 'h IN A 192.0.2.150' >"$T/sub.zone"
# big.test: record sets that do not fit into 512 / 1232 octets
{ printf '%s\n' '$ORIGIN big.test.' '$TTL 60' '@ IN SOA ns a 1 2 3 4 60'
  for i in $(seq 1 40); do echo "big IN A 10.0.0.$i"; done
  for i in $(seq 1 90); do echo "huge IN A 10.1.0.$i"; done; } >"$T/big.zone"

start_l -z "$T/l.zone" -z "$T/m.zone" -z "$T/sub.zone" -z "$T/big.zone" \
  && ok "four zone files load" || { bad "zones did not load" "$(head -c 300 "$T/err" | tr '\n' '|')"; return; }
: >"$T/lsent"

OK="rcode=NOERROR aa=1 tc=0 rd=1 ra=1 ad=0 qd=1 qok=1"
NX="rcode=NXDOMAIN aa=1 tc=0 rd=1 ra=1 ad=0 qd=1 qok=1"
SOA_L="l.test. SOA 600 ns1.l.test. admin.l.test. 2026101601 7200 3600 1209600 600"
SOA_M="m.test. SOA 100 ns.m.test. a.m.test. 1 2 3 4 600"
SOA_S="sub.l.test. SOA 50 ns.sub.l.test. a.sub.l.test. 1 2 3 4 50"
SOA_B="big.test. SOA 60 ns.big.test. a.big.test. 1 2 3 4 60"

echo "== positive answers (AA=1, no authority section, TTLs unchanged)"
lt "A with two records" "udp www.l.test A" "$OK an=2 ns=0" "www.l.test. A 7200 192.0.2.80|www.l.test. A 7200 192.0.2.81" "" "local NOERROR"
lt "AAAA" "udp www.l.test AAAA" "$OK an=1 ns=0" "www.l.test. AAAA 7200 2001:db8::80" "" "local NOERROR"
lt "AAAA with a compressed address" "udp ns1.l.test AAAA" "$OK an=1 ns=0" "ns1.l.test. AAAA 300 2001:db8::53" "" "local NOERROR"
lt "SOA at the apex keeps its own TTL (900), not min(TTL,MINIMUM)" "udp l.test SOA" "$OK an=1 ns=0" "l.test. SOA 900 ns1.l.test. admin.l.test. 2026101601 7200 3600 1209600 600" "" "local NOERROR"
lt "NS at the apex (relative and absolute names in rdata)" "udp l.test NS" "$OK an=2 ns=0" "l.test. NS 300 ns1.l.test.|l.test. NS 300 ns2.other.example." "" "local NOERROR"
lt "MX (relative and absolute exchange)" "udp l.test MX" "$OK an=2 ns=0" "l.test. MX 300 10 mail.l.test.|l.test. MX 300 20 mail2.other.example." "" "local NOERROR"
lt "A at the apex" "udp l.test A" "$OK an=1 ns=0" "l.test. A 300 192.0.2.1" "" "local NOERROR"
lt "qname with a trailing dot" "udp www.l.test. A" "$OK an=2 ns=0" "www.l.test. A 7200 192.0.2.80|www.l.test. A 7200 192.0.2.81" "" "local NOERROR"
lt "query in upper case: question echoed byte for byte, owner compared case-insensitively" "udp WwW.L.TeSt A" "$OK an=2 ns=0" "www.l.test. A 7200 192.0.2.80|www.l.test. A 7200 192.0.2.81" "" "local NOERROR"
lt "owner written with capitals in the zone file" "udp mixed.l.test A" "$OK an=1 ns=0" "mixed.l.test. A 300 192.0.2.7" "" "local NOERROR"
lt "same query without OPT: no OPT in the response" "udp www.l.test A -" "$OK an=2 ns=0" "www.l.test. A 7200 192.0.2.80|www.l.test. A 7200 192.0.2.81" "" "local NOERROR"
lt "answer in a second zone (m.test)" "udp host.m.test A" "$OK an=1 ns=0" "host.m.test. A 60 192.0.2.200" "" "local NOERROR"
lt "name in the nested zone (longest apex wins)" "udp h.sub.l.test A" "$OK an=1 ns=0" "h.sub.l.test. A 60 192.0.2.150" "" "local NOERROR"
lt "SOA of the nested zone" "udp sub.l.test SOA" "$OK an=1 ns=0" "sub.l.test. SOA 50 ns.sub.l.test. a.sub.l.test. 1 2 3 4 50" "" "local NOERROR"

echo "== ANY returns every record set of the name"
lt "ANY at www" "udp www.l.test ANY" "$OK an=3 ns=0" "www.l.test. A 7200 192.0.2.80|www.l.test. A 7200 192.0.2.81|www.l.test. AAAA 7200 2001:db8::80" "" "local NOERROR"
lt "ANY at the apex" "udp l.test ANY" "$OK an=6 ns=0" "l.test. SOA 900 ns1.l.test. admin.l.test. 2026101601 7200 3600 1209600 600|l.test. NS 300 ns1.l.test.|l.test. NS 300 ns2.other.example.|l.test. MX 300 10 mail.l.test.|l.test. MX 300 20 mail2.other.example.|l.test. A 300 192.0.2.1" "" "local NOERROR"
lt "ANY at a CNAME owner returns the CNAME only" "udp alias.l.test ANY" "$OK an=1 ns=0" "alias.l.test. CNAME 300 mail.l.test." "" "local NOERROR"

echo "== names that exist without the queried type (NOERROR, empty answer, SOA with TTL min(SOA TTL, MINIMUM))"
lt "MX at www" "udp www.l.test MX" "$OK an=0 ns=1" "" "$SOA_L" "local NOERROR"
lt "AAAA at the apex" "udp l.test AAAA" "$OK an=0 ns=1" "" "$SOA_L" "local NOERROR"
lt "SOA TTL below MINIMUM (m.test): TTL 100" "udp host.m.test AAAA" "$OK an=0 ns=1" "" "$SOA_M" "local NOERROR"
lt "empty non-terminal b.c.l.test" "udp b.c.l.test A" "$OK an=0 ns=1" "" "$SOA_L" "local NOERROR"
lt "empty non-terminal c.l.test" "udp c.l.test AAAA" "$OK an=0 ns=1" "" "$SOA_L" "local NOERROR"
lt "skipped TXT record: the owner exists, TXT is NODATA" "udp txtonly.l.test TXT" "$OK an=0 ns=1" "" "$SOA_L" "local NOERROR"
lt "skipped TXT record: A is NODATA, not NXDOMAIN" "udp txtonly.l.test A" "$OK an=0 ns=1" "" "$SOA_L" "local NOERROR"
lt "apex of the nested zone has no A: SOA of the nested zone" "udp sub.l.test A" "$OK an=0 ns=1" "" "$SOA_S" "local NOERROR"
lt "type without any record anywhere (HTTPS)" "udp www.l.test HTTPS" "$OK an=0 ns=1" "" "$SOA_L" "local NOERROR"

echo "== names that do not exist (NXDOMAIN, SOA of the zone containing the name)"
lt "plain missing name" "udp nosuch.l.test A" "$NX an=0 ns=1" "" "$SOA_L" "local NXDOMAIN"
lt "missing name, other type" "udp nosuch.l.test MX" "$NX an=0 ns=1" "" "$SOA_L" "local NXDOMAIN"
lt "below an existing leaf" "udp z.a.b.c.l.test A" "$NX an=0 ns=1" "" "$SOA_L" "local NXDOMAIN"
lt "below a name that only has a skipped record" "udp x.txtonly.l.test A" "$NX an=0 ns=1" "" "$SOA_L" "local NXDOMAIN"
lt "missing name in m.test (TTL 100)" "udp nosuch.m.test A" "$NX an=0 ns=1" "" "$SOA_M" "local NXDOMAIN"
lt "missing name in the nested zone uses the nested SOA" "udp x.sub.l.test A" "$NX an=0 ns=1" "" "$SOA_S" "local NXDOMAIN"
lt "missing name in big.test" "udp nosuch.big.test A" "$NX an=0 ns=1" "" "$SOA_B" "local NXDOMAIN"
lt "NXDOMAIN without OPT" "udp nosuch.l.test A -" "$NX an=0 ns=1" "" "$SOA_L" "local NXDOMAIN"

echo "== CNAME handling"
ORD=1
lt "A at a CNAME owner: CNAME first, then the target's A" "udp alias.l.test A" "$OK an=2 ns=0" "alias.l.test. CNAME 300 mail.l.test.|mail.l.test. A 300 192.0.2.25" "" "local NOERROR"
lt "chain of three CNAMEs" "udp alias3.l.test A" "$OK an=4 ns=0" "alias3.l.test. CNAME 300 alias2.l.test.|alias2.l.test. CNAME 300 alias.l.test.|alias.l.test. CNAME 300 mail.l.test.|mail.l.test. A 300 192.0.2.25" "" "local NOERROR"
lt "chain ends at a name without the type: NOERROR, CNAMEs, SOA" "udp alias3.l.test AAAA" "$OK an=3 ns=1" "alias3.l.test. CNAME 300 alias2.l.test.|alias2.l.test. CNAME 300 alias.l.test.|alias.l.test. CNAME 300 mail.l.test." "$SOA_L" "local NOERROR"
lt "chain crossing into the nested zone" "udp xz.l.test A" "$OK an=2 ns=0" "xz.l.test. CNAME 300 h.sub.l.test.|h.sub.l.test. A 60 192.0.2.150" "" "local NOERROR"
lt "CNAME to @ (the apex)" "udp toapex.l.test A" "$OK an=2 ns=0" "toapex.l.test. CNAME 300 l.test.|l.test. A 300 192.0.2.1" "" "local NOERROR"
lt "chain of 7 CNAMEs resolves fully" "udp hop6.l.test A" "$OK an=8 ns=0" "hop6.l.test. CNAME 300 hop7.l.test.|hop7.l.test. CNAME 300 hop8.l.test.|hop8.l.test. CNAME 300 hop9.l.test.|hop9.l.test. CNAME 300 hop10.l.test.|hop10.l.test. CNAME 300 hop11.l.test.|hop11.l.test. CNAME 300 hop12.l.test.|hop12.l.test. CNAME 300 hop13.l.test.|hop13.l.test. A 300 192.0.2.13" "" "local NOERROR"
ORD=
lt "CNAME query returns only the CNAME" "udp alias.l.test CNAME" "$OK an=1 ns=0" "alias.l.test. CNAME 300 mail.l.test." "" "local NOERROR"
lt "target outside all zones: CNAME only, NOERROR, no SOA" "udp out.l.test A" "$OK an=1 ns=0" "out.l.test. CNAME 300 elsewhere.example." "" "local NOERROR"
lt "target inside the zone but missing: CNAME + NXDOMAIN + SOA" "udp missing.l.test A" "$NX an=1 ns=1" "missing.l.test. CNAME 300 nothere.l.test." "$SOA_L" "local NXDOMAIN"
lt "target missing in the nested zone: SOA of the zone of the last name" "udp xzmiss.l.test A" "$NX an=1 ns=1" "xzmiss.l.test. CNAME 300 nothere.sub.l.test." "$SOA_S" "local NXDOMAIN"
lt "CNAME loop: each CNAME once, NOERROR, no SOA" "udp loop1.l.test A" "$OK an=2 ns=0" "loop1.l.test. CNAME 300 loop2.l.test.|loop2.l.test. CNAME 300 loop1.l.test." "" "local NOERROR"
lt "CNAME pointing to itself" "udp self.l.test A" "$OK an=1 ns=0" "self.l.test. CNAME 300 self.l.test." "" "local NOERROR"
echo "-- chain of 13 names: stops after at most 8 hops"
out=$(lq --name hop1.l.test --type A --opt 1232); hdr=$(head -1 <<<"$out")
an=$(lkv "$hdr" an); notc=$(awk '$1=="AN" && $3!="CNAME"' <<<"$out" | wc -l)
[ "$(lkv "$hdr" rcode)" = NOERROR ] && ok "NOERROR" || bad "rcode" "$(lkv "$hdr" rcode)"
{ [ "$an" -ge 8 ] && [ "$an" -le 9 ]; } 2>/dev/null && ok "8 or 9 CNAMEs (first record plus 8 hops)" || bad "number of CNAMEs after the hop limit" "an=$an"
[ "$notc" = 0 ] && ok "the A record at the end is not reached" || bad "chain longer than 8 hops was followed to the end"
echo x >>"$T/lsent"

echo "== outside every zone: not answered locally (the upstream is dead, so forwarded SERVFAIL)"
FW="rcode=SERVFAIL aa=0 tc=0 rd=1 ra=1 ad=0 qd=1 qok=1 an=0 ns=0"
lt "unrelated name" "udp other.example A" "$FW" "" "" "forwarded SERVFAIL"
lt "shares only a string suffix with the apex (xl.test vs l.test)" "udp xl.test A" "$FW" "" "" "forwarded SERVFAIL"
lt "name above the apex (test)" "udp test A" "$FW" "" "" "forwarded SERVFAIL"
lt "parent of a nested zone is still the outer zone, the root is not a zone" "udp . A" "$FW" "" "" "forwarded SERVFAIL"
lcount "positive, negative, CNAME, outside"

echo "== truncation (UDP only; TCP is never truncated)"
TCH="rcode=NOERROR aa=1 tc=1 rd=1 ra=1 ad=0 qd=1 qok=1 an=0 ns=0"
lt "40 A records without OPT: limit 512 -> TC=1, empty, no OPT" "udp big.big.test A -" "$TCH ar=0" "" "" "local NOERROR"
lt "same with advertised size 100 (clamped up to 512) -> TC=1, own OPT" "udp big.big.test A 100" "$TCH ar=1" "" "" "local NOERROR"
lt "same with advertised size 512 -> TC=1" "udp big.big.test A 512" "$TCH ar=1" "" "" "local NOERROR"
out=$(lq --name big.big.test --type A --opt 1232); hdr=$(head -1 <<<"$out")
echo "-- 40 A records with advertised size 1232: fits, no truncation"
[ "$(lkv "$hdr" tc)" = 0 ] && [ "$(lkv "$hdr" an)" = 40 ] && ok "tc=0 an=40" || bad "tc/an" "$hdr"
[ "$(lkv "$hdr" len)" -le 1232 ] 2>/dev/null && [ "$(lkv "$hdr" len)" -gt 512 ] && ok "response of $(lkv "$hdr" len) octets (> 512, <= 1232)" || bad "response size" "$(lkv "$hdr" len)"
echo x >>"$T/lsent"
lt "90 A records with advertised size 4096 (clamped to 1232) -> TC=1" "udp huge.big.test A 4096" "$TCH ar=1" "" "" "local NOERROR"
out=$(lq --name huge.big.test --type A --opt 100); hdr=$(head -1 <<<"$out")
[ "$(lkv "$hdr" len)" -lt 100 ] 2>/dev/null && ok "truncated response is only header + question + OPT ($(lkv "$hdr" len) octets)" || bad "truncated response size" "$(lkv "$hdr" len)"
echo x >>"$T/lsent"
lt "TCP: 40 A records, no truncation" "tcp big.big.test A" "$OK an=40 ns=0" "$(for i in $(seq 1 40); do printf 'big.big.test. A 60 10.0.0.%d|' $i; done)" "" "local NOERROR"
out=$(lq --proto tcp --name huge.big.test --type A --opt 1232); hdr=$(head -1 <<<"$out")
echo "-- TCP: 90 A records (more than 1232 octets), no truncation"
[ "$(lkv "$hdr" tc)" = 0 ] && [ "$(lkv "$hdr" an)" = 90 ] && ok "tc=0 an=90" || bad "tc/an" "$hdr"
echo x >>"$T/lsent"

echo "== the same answers over TCP"
lt "TCP: A" "tcp www.l.test A" "$OK an=2 ns=0" "www.l.test. A 7200 192.0.2.80|www.l.test. A 7200 192.0.2.81" "" "local NOERROR"
lt "TCP: ANY at the apex" "tcp l.test ANY" "$OK an=6 ns=0" "l.test. SOA 900 ns1.l.test. admin.l.test. 2026101601 7200 3600 1209600 600|l.test. NS 300 ns1.l.test.|l.test. NS 300 ns2.other.example.|l.test. MX 300 10 mail.l.test.|l.test. MX 300 20 mail2.other.example.|l.test. A 300 192.0.2.1" "" "local NOERROR"
lt "TCP: NXDOMAIN with SOA" "tcp nosuch.l.test A" "$NX an=0 ns=1" "" "$SOA_L" "local NXDOMAIN"
ORD=1
lt "TCP: CNAME chain" "tcp alias.l.test A" "$OK an=2 ns=0" "alias.l.test. CNAME 300 mail.l.test.|mail.l.test. A 300 192.0.2.25" "" "local NOERROR"
ORD=
lcount "truncation and TCP"

echo "== zone vs. blocklist: names in a loaded zone are never blocked, even below a blocklist entry"
printf '%s\n' '# entries that cover the zones' 'l.test' 'www.l.test' 'test' 'blocked.example' '0.0.0.0 tracker.example' >"$T/bl.txt"
start_l -z "$T/l.zone" -z "$T/m.zone" -z "$T/sub.zone" -b "$T/bl.txt" && ok "zones + blocklist load" || { bad "start" "$(head -c 300 "$T/err" | tr '\n' '|')"; stop; return; }
: >"$T/lsent"
BL="rcode=NXDOMAIN aa=0 tc=0 rd=1 ra=1 ad=0 qd=1 qok=1 an=0 ns=0"
lt "www.l.test is on the blocklist and in the zone: local answer" "udp www.l.test A" "$OK an=2 ns=0" "www.l.test. A 7200 192.0.2.80|www.l.test. A 7200 192.0.2.81" "" "local NOERROR"
lt "blocklist entry equal to the apex: apex SOA still local" "udp l.test SOA" "$OK an=1 ns=0" "l.test. SOA 900 ns1.l.test. admin.l.test. 2026101601 7200 3600 1209600 600" "" "local NOERROR"
lt "missing name below the apex is local NXDOMAIN with SOA, not blocked" "udp nosuch.l.test A" "$NX an=0 ns=1" "" "$SOA_L" "local NXDOMAIN"
lt "name in the nested zone below the blocked apex: local" "udp h.sub.l.test A" "$OK an=1 ns=0" "h.sub.l.test. A 60 192.0.2.150" "" "local NOERROR"
lt "entry above the apex ('test') covers m.test: zone name still local" "udp host.m.test A" "$OK an=1 ns=0" "host.m.test. A 60 192.0.2.200" "" "local NOERROR"
lt "blocked name outside every zone below 'test': blocked, no AA, no SOA" "udp other.test A" "$BL" "" "" "blocked NXDOMAIN"
lt "blocked, any QTYPE (AAAA)" "udp tracker.example AAAA" "$BL" "" "" "blocked NXDOMAIN"
lt "xl.test is below 'test', not below the zone l.test: blocked" "udp xl.test A" "$BL" "" "" "blocked NXDOMAIN"
lt "not on the list and not in a zone: forwarded (dead upstream: SERVFAIL)" "udp free.example A" "$FW" "" "" "forwarded SERVFAIL"
lcount "zone vs. blocklist"
stop
}

# ======================================================================================
# section "blocked": blocklist verdicts (a fake upstream is running; it must never see a blocked name)
# ======================================================================================
section_blocked() {
banner blocked
tools_init
up_start || { bad "fake upstream did not start"; return; }
: >"$T/upreq"

printf '%s\n' '# comment' 'blocked.example' '0.0.0.0 tracker.example' 'MiXed.Case.Example' 'trail.example.' \
  'deep.sub.example' >"$T/bl.txt"
start_f -b "$T/bl.txt" && ok "proxy started with blocklist" || { bad "start" "$(head -c 300 "$T/err" | tr '\n' '|')"; up_stop; stop; return; }
: >"$T/lsent"
BL="rcode=NXDOMAIN aa=0 tc=0 rd=1 ra=1 ad=0 qd=1 qok=1 an=0 ns=0 id=16962"
FO="rcode=NOERROR aa=0 tc=0 rd=1 ra=1 ad=0 qd=1 qok=1"

echo "== exact and subdomain match"
lt "exact entry, UDP" "udp blocked.example A" "$BL" "" "" "blocked NXDOMAIN"
lt "exact entry, TCP" "tcp blocked.example A" "$BL" "" "" "blocked NXDOMAIN"
lt "subdomain of an entry" "udp www.blocked.example A" "$BL" "" "" "blocked NXDOMAIN"
lt "deep subdomain of an entry" "udp a.b.c.blocked.example A" "$BL" "" "" "blocked NXDOMAIN"
lt "hosts-format line ('0.0.0.0 name'): the name is blocked" "udp tracker.example A" "$BL" "" "" "blocked NXDOMAIN"
lt "subdomain of a hosts-format entry" "udp x.tracker.example A" "$BL" "" "" "blocked NXDOMAIN"
lt "entry written with a trailing dot" "udp trail.example A" "$BL" "" "" "blocked NXDOMAIN"
lt "entry written in mixed case matches a lower-case query" "udp mixed.case.example A" "$BL" "" "" "blocked NXDOMAIN"
lt "entry with several labels" "udp deep.sub.example A" "$BL" "" "" "blocked NXDOMAIN"

echo "== query name case does not matter"
out=$(lq --name BLOCKED.Example --type A); h=$(head -1 <<<"$out")
[ "$(lkv "$h" rcode)" = NXDOMAIN ] && ok "upper-case query is blocked" || bad "upper-case query not blocked" "$h"
sleep 0.2; grep -Eiq " blocked\.example\. A blocked NXDOMAIN\$" "$T/out" && ok "logged as blocked" || bad "log line for BLOCKED.Example" "$(tail -1 "$T/out")"
echo x >>"$T/lsent"

echo "== every QTYPE of a blocked name is blocked"
for t in A AAAA MX NS SOA CNAME TXT HTTPS ANY; do
  lt "QTYPE $t" "udp blocked.example $t" "$BL" "" "" "blocked NXDOMAIN"
done

echo "== EDNS"
lt "no OPT in the query: no OPT in the answer" "udp blocked.example A -" "$BL" "" "" "blocked NXDOMAIN"
lt "client OPT size 512: answer still has our OPT" "udp blocked.example A 512" "$BL" "" "" "blocked NXDOMAIN"
lt "client OPT size 4096" "tcp blocked.example A 4096" "$BL" "" "" "blocked NXDOMAIN"

echo "== names that are NOT blocked"
lt "sibling with the entry as a string suffix (xblocked.example) is forwarded" "udp xblocked.example A" "$FO an=1 ns=0 id=16962" "xblocked.example. A 37 $(ea xblocked.example)" "" "forwarded NOERROR"
lt "parent of an entry (example) is forwarded" "udp example A" "$FO an=1 ns=0 id=16962" "example. A 37 $(ea example)" "" "forwarded NOERROR"
lt "unrelated name is forwarded" "udp free.test A" "$FO an=1 ns=0 id=16962" "free.test. A 37 $(ea free.test)" "" "forwarded NOERROR"
lt "blocked label in another position (blocked.example.org) is forwarded" "udp blocked.example.org A" "$FO an=1 ns=0 id=16962" "blocked.example.org. A 37 $(ea blocked.example.org)" "" "forwarded NOERROR"
lcount "blocked"

echo "== nothing blocked reached the upstream"
n=$(grep -Ec ' q=([a-z0-9.]*\.)?(blocked\.example|tracker\.example|mixed\.case\.example|trail\.example|deep\.sub\.example)\. ' "$T/upreq")
[ "$n" = 0 ] && ok "the upstream never saw a blocked name" || bad "blocked name reached the upstream" "$(grep -Eo ' q=[^ ]+' "$T/upreq" | tr '\n' ' ')"
echo "== response ID is the client's, also for other IDs"
for id in 0 1 43981 65535; do
  h=$(lq --name blocked.example --type A --id $id | head -1); [ "$(lkv "$h" id)" = $id ] && ok "ID $id copied" || bad "ID $id" "$h"
done
sleep 0.3
stop; up_stop
}

# ======================================================================================
# section "forward": DoH forwarding against the fake upstream (first label of the name = behaviour)
#   ok* answer 1 A | nx NXDOMAIN+SOA | big 40 A | delayN answers after N s | close drops the connection
#   r500 r404 redir r204 short empty qd0 wrongq wrongtype qr0 op1 = defective upstreams | caseq upper-case question
# ======================================================================================
section_forward() {
banner forward
tools_init
up_start || { bad "fake upstream did not start"; return; }
: >"$T/upreq"
FO="rcode=NOERROR aa=0 tc=0 rd=1 ra=1 ad=0 qd=1 qok=1 id=16962"
FW="rcode=SERVFAIL aa=0 tc=0 rd=1 ra=1 ad=0 qd=1 qok=1 an=0 ns=0 id=16962"

start_f -w 3 && ok "proxy started" || { bad "start" "$(head -c 300 "$T/err" | tr '\n' '|')"; up_stop; stop; return; }
: >"$T/lsent"

echo "== a normal forwarded answer"
REQS=1 lt "UDP A" "udp ok.example A" "$FO an=1 ns=0" "ok.example. A 37 $(ea ok.example)" "" "forwarded NOERROR"
upcheck "the upstream request for ok.example (with the client's OPT)" ok.example A 1232
REQS=1 lt "TCP A" "tcp tcp.example A" "$FO an=1 ns=0" "tcp.example. A 37 $(ea tcp.example)" "" "forwarded NOERROR"
REQS=1 lt "no OPT in the query" "udp noopt.example A -" "$FO an=1 ns=0" "noopt.example. A 37 $(ea noopt.example)" "" "forwarded NOERROR"
upcheck "the upstream request without OPT" noopt.example A
REQS=1 lt "AAAA (upstream has no data: NOERROR, empty)" "udp v6.example AAAA" "$FO an=0 ns=0" "" "" "forwarded NOERROR"
REQS=1 lt "NXDOMAIN with the upstream's SOA is relayed" "udp nx.example A" "rcode=NXDOMAIN aa=0 tc=0 rd=1 ra=1 ad=0 qd=1 qok=1 id=16962 an=0 ns=1" "" ". SOA 37 . . 0 0 0 0 0" "forwarded NXDOMAIN"
REQS=1 lt "REFUSED from the upstream is relayed" "udp refused.example A" "rcode=REFUSED aa=0 tc=0 rd=1 ra=1 ad=0 qd=1 qok=1 id=16962 an=0 ns=0" "" "" "forwarded REFUSED"
REQS=1 lt "SERVFAIL from the upstream is relayed" "udp servfail.example A" "$FW" "" "" "forwarded SERVFAIL"
REQS=1 lt "upstream writes the question in upper case: still the same question" "udp caseq.example A" "rcode=NOERROR an=1 id=16962" "caseq.example. A 37 $(ea caseq.example)" "" "forwarded NOERROR"
for id in 0 1 43981 65535; do
  h=$(lq --name id$id.example --type A --id $id | head -1); [ "$(lkv "$h" id)" = $id ] && ok "client ID $id restored in the answer" || bad "ID $id" "$h"
  echo x >>"$T/lsent"
done
n=$(grep -c ' id=0 ' "$T/upreq"); t=$(wc -l <"$T/upreq")
[ "$n" = "$t" ] && ok "every upstream query had ID 0" || bad "upstream query IDs" "$n of $t have ID 0"
lcount "forward basics"

echo "== truncation of a large forwarded answer (40 A records, ~700 bytes)"
BIGANS="big.example. A 37 $(ea big.example)"; for i in $(seq 1 39); do BIGANS="$BIGANS|big.example. A 37 10.200.0.$i"; done
lt "UDP, no OPT: TC=1, no records" "udp big.example A -" "rcode=NOERROR aa=0 tc=1 rd=1 ra=1 ad=0 qd=1 qok=1 an=0 ns=0 ar=0 id=16962" "" "" "forwarded NOERROR"
lt "UDP, OPT 512: TC=1, only our OPT" "udp big.example A 512" "rcode=NOERROR aa=0 tc=1 rd=1 ra=1 ad=0 qd=1 qok=1 an=0 ns=0 ar=1 id=16962" "" "" "forwarded NOERROR"
lt "UDP, OPT 600: still too small" "udp big.example A 600" "rcode=NOERROR tc=1 an=0 ns=0 ar=1 id=16962" "" "" "forwarded NOERROR"
lt "UDP, OPT 1232: fits, all 40 records" "udp big.example A 1232" "$FO an=40 ns=0 tc=0" "$BIGANS" "" "forwarded NOERROR"
lt "TCP is never truncated (no OPT)" "tcp big.example A -" "$FO an=40 ns=0 tc=0" "$BIGANS" "" "forwarded NOERROR"
lcount "forward truncation"

echo "== defective upstream answers -> SERVFAIL, exactly one upstream request, answered quickly"
for k in r500 r404 redir r204 short empty qd0 wrongq wrongtype qr0 op1; do
  REQS=1 LAT=1500 lt "upstream behaviour '$k'" "udp $k.example A" "$FW" "" "" "forwarded SERVFAIL"
done
n=$(grep -c 'path=/redir-target' "$T/upreq"); [ "$n" = 0 ] && ok "redirect (302) was not followed" || bad "redirect was followed" "$n request(s) to the Location"
LAT=1500 lt "upstream closes the connection without answering" "udp close.example A" "$FW" "" "" "forwarded SERVFAIL"
LAT=1500 lt "upstream closes the connection (TCP client)" "tcp close.tcp.example A" "$FW" "" "" "forwarded SERVFAIL"
lcount "forward errors"
n=$(grep -c 'method=GET' "$T/upreq"); [ "$n" = 0 ] && ok "no GET was ever sent (POST only)" || bad "GET request seen" "$n"

echo "== slow upstream: the proxy does not block"
python3 -I "$T/rr.py" --port $PORT --name delay2.slow.example --type A --timeout 8 >"$T/slow.out" &
SP=$!; sleep 0.4
LAT=500 lt "a fast query is answered while another one waits" "udp fast.example A" "$FO an=1 ns=0" "fast.example. A 37 $(ea fast.example)" "" "forwarded NOERROR"
wait $SP; h=$(head -1 "$T/slow.out")
[ "$(lkv "$h" rcode)" = NOERROR ] && [ "$(lkv "$h" ms)" -ge 1900 ] && ok "the slow query got its answer after $(lkv "$h" ms) ms" || bad "slow query" "$h"
sleep 0.3
echo "== 20 slow queries in parallel finish in about one delay, not twenty"
t0=$(date +%s%N)
seq 1 20 | xargs -P20 -I{} python3 -I "$T/rr.py" --port $PORT --name delay1.p{}.example --type A --timeout 8 >"$T/par.out"
t1=$(date +%s%N); ms=$(( (t1 - t0) / 1000000 ))
n=$(grep -c 'rcode=NOERROR' "$T/par.out"); [ "$n" = 20 ] && ok "all 20 answered NOERROR" || bad "parallel answers" "$n of 20 NOERROR"
[ $ms -lt 4000 ] && ok "took $ms ms" || bad "parallel queries ran serially?" "$ms ms"
sleep 0.5
n=$(grep -c ' q=p[0-9]*\.' "$T/upreq"); m=$(grep -Ec ' q=delay1\.p[0-9]+\.example\. ' "$T/upreq")
[ "$m" = 20 ] && ok "exactly 20 upstream requests for 20 queries" || bad "upstream request count" "$m"
sleep 0.3; got=$(grep -c 'delay1\.p[0-9]*\.example\. A forwarded NOERROR' "$T/out")
[ "$got" = 20 ] && ok "20 log lines" || bad "log lines for the parallel queries" "$got of 20"
LBASE=$(wc -l <"$T/out"); : >"$T/lsent"

echo "== -w timeout (1 s)"
start_f -w 1 && ok "restarted with -w 1" || { bad "start" "$(head -c 200 "$T/err")"; up_stop; return; }
LATMIN=900 LAT=2200 lt "upstream answers after 3 s: SERVFAIL after about 1 s" "udp delay3.example A" "$FW" "" "" "forwarded SERVFAIL"
lt "a fast answer is not affected" "udp quick.example A" "$FO an=1 ns=0" "quick.example. A 37 $(ea quick.example)" "" "forwarded NOERROR"
lcount "forward timeout"

echo "== outstanding-request cap"
start_f -w 6 && ok "restarted" || { bad "start" "$(head -c 200 "$T/err")"; up_stop; return; }
cap=$(sed -n 's/^outstanding upstream request cap: \([0-9][0-9]*\).*/\1/p' "$T/err" | head -1)
if [[ "$cap" =~ ^[0-9]+$ ]] && [ "$cap" -ge 1 ] && [ "$cap" -le 600 ]; then
  ok "stderr reports the cap ($cap)"
  cat >"$T/cap.py" <<'PY'
import select, socket, struct, sys, time
port, n = int(sys.argv[1]), int(sys.argv[2])
def q(name):
    return struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
socks = []
for i in range(n):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(q("delay2.c%d.example" % i), ("127.0.0.1", port)); socks.append(s)
res = {"ok": 0, "servfail": 0, "other": 0, "none": 0}; first_sf = None; t0 = time.time(); pend = set(socks)
while pend and time.time() - t0 < 10:
    r, _, _ = select.select(list(pend), [], [], 0.5)
    for s in r:
        d = s.recv(2000); pend.discard(s); rc = d[3] & 15
        if rc == 0: res["ok"] += 1
        elif rc == 2:
            res["servfail"] += 1
            if first_sf is None: first_sf = time.time() - t0
        else: res["other"] += 1
res["none"] = len(pend)
print("ok=%d servfail=%d other=%d none=%d first_servfail_ms=%d" % (res["ok"], res["servfail"], res["other"], res["none"], int((first_sf or 0) * 1000)))
PY
  extra=$(( cap + 10 ))
  r=$(python3 -I "$T/cap.py" $PORT $extra); echo "     $extra simultaneous slow queries: $r"
  [ "$(lkv "$r" none)" = 0 ] && ok "every query got an answer" || bad "unanswered queries" "$r"
  [ "$(lkv "$r" ok)" = "$cap" ] && ok "exactly $cap were forwarded and answered" || bad "forwarded answers" "want $cap, $r"
  [ "$(lkv "$r" servfail)" = 10 ] && ok "the 10 over the cap got SERVFAIL" || bad "SERVFAIL over the cap" "want 10, $r"
  [ "$(lkv "$r" first_servfail_ms)" -lt 1500 ] && ok "over-cap SERVFAIL came immediately ($(lkv "$r" first_servfail_ms) ms)" || bad "over-cap SERVFAIL was late" "$r"
  sleep 3
  m=$(grep -Ec ' q=delay2\.c[0-9]+\.example\. ' "$T/upreq"); [ "$m" = "$cap" ] && ok "the upstream saw $cap requests, not $extra" || bad "upstream requests" "$m (cap $cap)"
  LAT=1000 lt "after the burst the proxy forwards again" "udp after.example A" "$FO an=1 ns=0" "after.example. A 37 $(ea after.example)" "" "forwarded NOERROR"
  got=$(grep -c 'delay2\.c[0-9]*\.example\. A forwarded' "$T/out"); [ "$got" = $extra ] && ok "$extra log lines for the burst" || bad "burst log lines" "$got of $extra"
else
  bad "cap line on stderr missing or unreasonable (>600: test skipped)" "cap='$cap' stderr: $(head -c 200 "$T/err" | tr '\n' '|')"
fi

echo "== shutdown with a query in flight"
start_f -w 10 && ok "restarted" || { bad "start" "$(head -c 200 "$T/err")"; up_stop; return; }
python3 -I "$T/rr.py" --port $PORT --name delay5.sd.example --type A --timeout 6 >"$T/sd.out" &
SP=$!; sleep 0.5
t0=$(date +%s%N); kill -TERM $PROXY; wait $PROXY; rc=$?; t1=$(date +%s%N); PROXY=""
ms=$(( (t1 - t0) / 1000000 ))
[ $rc -eq 0 ] && ok "exit status 0" || bad "exit status" "rc=$rc"
[ $ms -lt 2000 ] && ok "exited within 2 s ($ms ms)" || bad "slow shutdown" "$ms ms"
wait $SP; h=$(head -1 "$T/sd.out"); [ "$(lkv "$h" rcode)" = SERVFAIL ] && ok "the in-flight client got SERVFAIL" || bad "in-flight client" "$h"
grep -q 'delay5\.sd\.example\. A forwarded SERVFAIL$' "$T/out" && ok "and the log line was written" || bad "log line of the in-flight query" "$(tail -2 "$T/out" | tr '\n' '|')"
start_f -w 10 && ok "restarted" || { bad "start" "$(head -c 200 "$T/err")"; up_stop; return; }
python3 -I "$T/rr.py" --port $PORT --proto tcp --name delay5.sd2.example --type A --timeout 6 >"$T/sd.out" &
SP=$!; sleep 0.5; kill -INT $PROXY; wait $PROXY; rc=$?; PROXY=""
[ $rc -eq 0 ] && ok "SIGINT: exit status 0" || bad "SIGINT exit status" "rc=$rc"
wait $SP; h=$(head -1 "$T/sd.out"); [ "$(lkv "$h" rcode)" = SERVFAIL ] && ok "SIGINT, TCP client in flight: SERVFAIL" || bad "TCP in-flight client" "$h"
grep -q 'delay5\.sd2\.example\. A forwarded SERVFAIL$' "$T/out" && ok "log line written" || bad "log line of the in-flight TCP query" "$(tail -2 "$T/out" | tr '\n' '|')"

echo "== unreachable / unresolvable upstream"
FURL="http://127.0.0.1:1/dns" start_f -w 3 && ok "started (nothing listens on the upstream port)" || { bad "start"; up_stop; return; }
LAT=1500 lt "connection refused -> SERVFAIL" "udp refused.example A" "$FW" "" "" "forwarded SERVFAIL"
FURL="http://no-such-host.invalid/dns" start_f -w 2 && ok "started (host does not resolve)" || { bad "start"; up_stop; return; }
LAT=2900 lt "name resolution failure -> SERVFAIL" "udp resolve.example A" "$FW" "" "" "forwarded SERVFAIL"
lcount "forward unreachable"
stop

echo "== TLS: certificate verification against SSL_CERT_FILE, --insecure"
if command -v openssl >/dev/null; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/k1.pem" -out "$T/c1.pem" -days 2 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/k2.pem" -out "$T/c2.pem" -days 2 -subj "/CN=other.test" \
    -addext "subjectAltName=DNS:other.test" 2>/dev/null
  if [ -s "$T/c1.pem" ] && [ -s "$T/c2.pem" ] && up_start $UPS "$T/c1.pem" "$T/k1.pem" && up_start $UPB "$T/c2.pem" "$T/k2.pem"; then
    : >"$T/upreq"
    FURL="https://localhost:$UPS/dns" FENV="SSL_CERT_FILE=$T/c1.pem" start_f -w 3 && ok "started with SSL_CERT_FILE" || bad "start" "$(head -c 200 "$T/err")"
    : >"$T/lsent"
    LAT=2500 lt "trusted certificate, host name matches (localhost)" "udp tls1.example A" "$FO an=1 ns=0" "tls1.example. A 37 $(ea tls1.example)" "" "forwarded NOERROR"
    FURL="https://127.0.0.1:$UPS/dns" FENV="SSL_CERT_FILE=$T/c1.pem" start_f -w 3
    LAT=2500 lt "trusted certificate, IP address matches" "udp tls2.example A" "$FO an=1 ns=0" "tls2.example. A 37 $(ea tls2.example)" "" "forwarded NOERROR"
    FURL="https://localhost:$UPB/dns" FENV="SSL_CERT_FILE=$T/c2.pem" start_f -w 3
    : >"$T/upreq"
    LAT=2500 lt "certificate is trusted but valid for another host name: SERVFAIL" "udp tls3.example A" "$FW" "" "" "forwarded SERVFAIL"
    n=$(grep -c 'method=POST' "$T/upreq"); [ "$n" = 0 ] && ok "the query was not sent over the unverified connection" || bad "query sent despite the host name mismatch" "$n"
    FURL="https://localhost:$UPS/dns" FENV="SSL_CERT_FILE=$T/c2.pem" start_f -w 3
    : >"$T/upreq"
    LAT=2500 lt "certificate not signed by the trusted file: SERVFAIL" "udp tls4.example A" "$FW" "" "" "forwarded SERVFAIL"
    n=$(grep -c 'method=POST' "$T/upreq"); [ "$n" = 0 ] && ok "no query sent" || bad "query sent to an untrusted server" "$n"
    FURL="https://localhost:$UPS/dns" start_f -w 3
    LAT=2500 lt "self-signed certificate, default trust store: SERVFAIL" "udp tls5.example A" "$FW" "" "" "forwarded SERVFAIL"
    FURL="https://localhost:$UPB/dns" start_f -w 3 --insecure
    LAT=2500 lt "--insecure accepts the wrong host name and the unknown CA" "udp tls6.example A" "$FO an=1 ns=0" "tls6.example. A 37 $(ea tls6.example)" "" "forwarded NOERROR"
    FURL="https://localhost:$UPB/dns" FENV="SSL_CERT_FILE=$T/c2.pem" start_f -w 3 --insecure
    LAT=2500 lt "--insecure with a trust file works too" "tcp tls7.example A" "$FO an=1 ns=0" "tls7.example. A 37 $(ea tls7.example)" "" "forwarded NOERROR"
    upcheck "request over TLS is the same POST" tls7.example A 1232
    lcount "forward TLS"
  else
    bad "TLS fixtures (openssl / https test servers) could not be created"
  fi
else
  echo "  (openssl not found: TLS part skipped)"
fi
stop; up_stop
}

# ======================================================================================
# main
# ======================================================================================
WANT="${*:-$SECTIONS}"
for s in $WANT; do
  declare -F "section_$s" >/dev/null || { echo "unknown section '$s' (available: $SECTIONS)"; exit 2; }
done
for s in $WANT; do "section_$s"; done

echo
echo "================ SUMMARY ================"
TP=0; TF=0
for s in $WANT; do
  printf '  %-10s passed: %-4s failed: %s\n' "$s" "${P[$s]:-0}" "${F[$s]:-0}"
  TP=$((TP + ${P[$s]:-0})); TF=$((TF + ${F[$s]:-0}))
done
echo "  total      passed: $TP   failed: $TF"
[ $TF -eq 0 ]
# END AI-GENERATED CODE