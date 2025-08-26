#!/bin/bash
read -p "Username?: " USER
read -p "What was Target Domain or I.P. Address?: " TARGET
read -p "Location to save logs?: " DIR
mkdir -p "$DIR"
mv recon_ng.log recon_ng_curl.log recon_ng_nmap.log recon_ng_takeover.log sub.txt takeovers.txt "$DIR"
7z a "recon_ng_logs-$(date).7z" "$DIR"
