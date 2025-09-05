###Advanced Enumeration Tool for Pentesters###

##Setup recon_ng with the follow commands:
cd /path/to/setup_recon_ng.sh
./setup_recon_ng.sh
##Setup will take care of the rest of the dependencies##
####!!!!ONLY use this against a TARGET IF YOU HAVE PERMISSION!!!###


#Run recon_ng:
cd path/to/recon_ng
./recon_ng.sh
# This will create several logs, recon_ng_curl.log, recon_ng.log, recon_ng_takeovers.log (if y is selected for advanced) recon_ng_extended.log recon_ng_dns.log
#enumeration then there will be an additional dir of data.#


#Prepare.sh gets files archived into a 7z archive

#Convert.sh converts all .log to .txt

#search_takeovers.sh will parse the takeovers.txt and look for entries mark [VULNERABLE]

#cleanup.sh will remove any unwanted leftover log files
