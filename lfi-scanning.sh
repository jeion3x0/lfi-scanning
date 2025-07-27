#!/bin/bash

# LFI Scanner - Enhanced with Reduced False Positives

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
NC='\033[0m'

usage() {
    echo "Usage: $0 -u urls.txt -p payloads.txt -o output.txt [-t threads]"
    exit 1
}

THREADS=10
while getopts ":u:p:o:t:" opt; do
    case $opt in
        u) URLS_FILE="$OPTARG" ;;
        p) PAYLOADS_FILE="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        t) THREADS="$OPTARG" ;;
        *) usage ;;
    esac
done

if [[ -z "$URLS_FILE" || -z "$PAYLOADS_FILE" || -z "$OUTPUT_FILE" ]]; then
    usage
fi

if ! [[ -f "$URLS_FILE" ]]; then
    echo -e "${RED}URL file does not exist!${NC}"
    exit 2
fi
if ! [[ -f "$PAYLOADS_FILE" ]]; then
    echo -e "${RED}Payloads file does not exist!${NC}"
    exit 3
fi

USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    "Mozilla/5.0 (X11; Linux x86_64)"
    "curl/7.68.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
)

# REFINED REGEX PATTERNS FOR REDUCED FALSE POSITIVES
REGEX_PATTERNS=(
    # Linux / Unix files
    "^Ubuntu [0-9]+\\.[0-9]+ LTS|^Debian GNU/Linux [0-9]+"                # /etc/issue
    "^root:[^:]+:[0-9]+:[0-9]+:.*$"                                       # /etc/passwd
    "^root:[^:]+:[0-9]+:.*$"                                              # /etc/shadow
    "^[a-zA-Z0-9_-]+:[^:]+:[0-9]+:[0-9]+:.*$"                             # /etc/passwd lines
    "^[a-zA-Z0-9_-]+:[^:]*:[0-9]+:.*$"                                    # /etc/group lines
    "^127\.0\.0\.1\s+localhost|^::1\s+localhost"                           # /etc/hosts
    "^\[mysqld\]|user\s*=\s*[a-zA-Z0-9_-]+|password\s*="                  # /etc/mysql/my.cnf
    "^PATH=.*|^USER=.*|^HOME=.*|^SHELL=.*"                                # /proc/self/environ
    "^Linux version [0-9]+\\.[0-9]+\\.[0-9]+"                             # /proc/version
    "^cmdline=.*"                                                         # /proc/cmdline
    "^SchedDebug Version:.*|^sysctl_sched_latency"                        # /proc/sched_debug
    "^root\s+/dev/.*\s+ext4|^/dev/.*\s+proc"                              # /proc/mounts
    "^Iface\s+.*HWaddr|^Link encap:"                                      # /proc/net/arp
    "^sl\s+local_address|^proto\s+recv"                                   # /proc/net/tcp, /proc/net/udp
    "^<?php\s+.*(function|class|echo|require)"                           # /proc/self/cwd/index.php
    "^def\s+.*|^import\s+.*|^if __name__ == [\"']__main__[\"']"           # /proc/self/cwd/main.py
    "^session\.save_path|^memory_limit|^post_max_size"                     # php.ini
    "^cd\s+.*|^ls\s+.*|^sudo\s+.*|^passwd\s+.*"                          # /root/.bash_history
    "^-----BEGIN RSA PRIVATE KEY-----"                                    # /root/.ssh/id_rsa
    "^apiVersion:\s+.*|^kind:\s+.*|^namespace:"                           # /var/run/secrets/kubernetes.io/serviceaccount
    "^mlocate\.db|^filename:.*"                                           # /var/lib/mlocate/mlocate.db
    "^GET\s+/.*HTTP/|^POST\s+/.*HTTP/"                                    # access.log
    "^\[error\]|^PHP Fatal error|^client\s+\["                            # error.log
    "^vsftpd.*(connect|login|fail)"                                       # /var/log/vsftpd.log
    "^sshd.*(Accepted|Failed|session opened)"                             # /var/log/sshd.log
    "^mail.*(postfix|sendmail|imap|smtp)"                                 # /var/log/mail

    # Windows files
    "^\[boot loader\]"                                                    # boot.ini
    "^\[fonts\]|^\[drivers\]"                                             # win.ini
    "^SystemRoot=|^RegisteredOwner=|^ProductID="                          # system.ini
    "^\[ShellClassInfo\]"                                                 # desktop.ini
    "^REGEDIT4|^Windows Registry Editor"                                  # ntuser.dat, ntuser.ini
    "^\[PHP\]|^max_execution_time|^upload_max_filesize"                   # php.ini
    "^DocumentRoot\s+.*|^ServerRoot\s+.*|^Listen\s+[0-9]+"                # httpd.conf
    "^<configuration>|^<appSettings>|^<connectionStrings>"                # web.config
    "^global\.asa|^sub main|^application\("                               # global.asa
    "^<%@\s+Page|^<asp:|^runat=\"server\""                               # index.asp, .asax
    "^\[mysqld\]|datadir=|^bind-address="                                 # my.ini
    "^Tomcat.*Server version:|^Servlet.*|^Catalina"                       # tomcat files
    "^<FileZillaServer>"                                                  # filezilla server.xml
    "^MercuryMail|^IMAP.*|^SMTP.*"                                        # mercury.ini
    "^webalizer.*(Hits|Sites|Bandwidth)"                                  # webalizer.conf
    "^<SiteList>|^McAfee"                                                 # sitelist.xml
    "^<unattend>|^<sysprep>"                                              # sysprep.xml
    "^wpsettings\.dat|^System Volume Information"                         # wpsettings.dat
    "^<IIsWebServer>|^W3SVC|^AppPools"                                    # metabase.xml
    "^127\.0\.0\.1\s+localhost|^::1\s+localhost"                          # hosts
    "^\[Unattended\]|^\[GuiUnattended\]"                                  # unattend.xml
    "^AppData.*(Bookmarks|Cookies|History)"                               # Chrome user data
    "^ConsoleHost_history|^PSReadLine"                                    # consolehost_history.txt
    "^\[default\].*aws_access_key_id|^aws_secret_access_key"              # .aws/credentials
    "^\[global\].*application_name|^region="                              # .elasticbeanstalk/config
    "^\$db\s*=|^phpMyAdmin.*config\.inc"                                  # phpMyAdmin config
    "^sendmail.*(smtp|auth_user|auth_pass)"                               # sendmail.ini

    # Java / WebApp files
    "^<web-app|^<servlet>|^<context-param>"                               # web.xml
    "^Manifest-Version:|^Main-Class:|^Class-Path:"                        # MANIFEST.MF
    "^<jnlp|^<application-desc"                                           # APPLICATION.JNLP
    "^<jboss-web|^<jboss-app|^openwebbeans"                               # JBoss XMLs
    "^<liferay-web|^<portlet>"                                            # Liferay XMLs
    "^db\.properties|^config\.properties|^messages\.properties"           # Java properties
    "^<log4j:configuration|^logback"                                      # log4j.xml, logback.xml
    "^<faces-config|^<struts-config|^<tiles-defs"                         # Java framework XMLs
)

GREP_PATTERN="$(IFS='|'; echo "${REGEX_PATTERNS[*]}")"

export OUTPUT_FILE GREP_PATTERN RED GREEN YELLOW CYAN NC

urlencode() {
    python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1]))" "$1" 2>/dev/null || \
    printf '%s' "$1" | jq -s -R -r @uri
}

scan_one() {
    local url="$1"
    local param="$2"
    local payload="$3"
    local user_agent="$4"

    local encoded_payload
    encoded_payload=$(urlencode "$payload")

    local base="${url%%\?*}"
    local query="${url#*\?}"
    [[ "$url" == "$base" ]] && base="$url" && query=""
    local new_query=""
    IFS='&' read -ra pairs <<< "$query"
    for kv in "${pairs[@]}"; do
        key="${kv%%=*}"
        val="${kv#*=}"
        if [[ "$key" == "$param" ]]; then
            val="$encoded_payload"
        fi
        new_query+="${key}=${val}&"
    done
    new_query="${new_query%&}"
    local attack_url="$base"
    [[ -n "$new_query" ]] && attack_url+="?$new_query"

    local resp
    resp=$(curl -skL -A "$user_agent" --max-time 10 "$attack_url" 2>/dev/null)
    if [[ $? -gt 0 || -z "$resp" ]]; then
        return
    fi

    # Check only the first 10 lines to reduce false positives
    if echo "$resp" | head -n 10 | grep -aqE "$GREP_PATTERN"; then
        echo -e "${GREEN}[LFI FOUND]${NC} ${CYAN}${attack_url}${NC} ${YELLOW}(payload: $payload)${NC}"
        echo "$attack_url | $payload" >> "$OUTPUT_FILE"
    fi
}

export -f scan_one urlencode

> "$OUTPUT_FILE"

TMP_SCAN=$(mktemp)
trap 'rm -f "$TMP_SCAN"' EXIT

while IFS= read -r url; do
    [ -z "$url" ] && continue
    if [[ "$url" == *"?"* ]]; then
        paramlist=$(echo "$url" | cut -d'?' -f2 | tr '&' '\n' | cut -d'=' -f1)
    else
        continue
    fi
    while IFS= read -r payload; do
        [ -z "$payload" ] && continue
        for param in $paramlist; do
            ua="${USER_AGENTS[$((RANDOM % ${#USER_AGENTS[@]}))]}"
            echo "scan_one '$url' '$param' '$payload' '$ua'"
        done
    done < "$PAYLOADS_FILE"
done < "$URLS_FILE" > "$TMP_SCAN"

if [[ ! -s "$TMP_SCAN" ]]; then
    echo -e "${YELLOW}No scan jobs created. Check your input files.${NC}"
    exit 4
fi

cat "$TMP_SCAN" | parallel -j "$THREADS" --will-cite --eta

echo -e "${CYAN}Scan complete! Vulnerable URLs saved in ${OUTPUT_FILE}${NC}"
