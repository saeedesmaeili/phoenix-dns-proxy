#!/usr/bin/env bash
# DNS hijack + transparent proxy with wildcard support.
# - Whitelisted EXACT FQDNs and WILDCARD domains (*.example.com) resolve to this host (proxy).
# - Everything else resolves normally via upstream (CoreDNS forward).
# - sniproxy passes HTTP/TLS to real destinations by Host/SNI for those whitelisted names.

set -Eeuo pipefail
: "${DEBUG:=0}"
if [[ "$DEBUG" == "1" ]]; then
  export PS4='+ [${BASH_SOURCE##*/}:${LINENO}] '
  set -x
fi
trap 'rc=$?; echo "!! setup.sh failed at line $LINENO: $(sed -n ${LINENO}p "$0") (exit=$rc)" >&2; exit $rc' ERR

###############################################################################
# WHITELISTS
# EXACT_FQDNS  -> only that FQDN is hijacked
# WILDCARD_ZONES -> *.zone is hijacked (we also include the apex of the zone)
###############################################################################
EXACT_FQDNS=(
  "api2.amplitude.com"
  "amplitude.com"
  "amd.com"
  "atlassian.net"
  "api.cisco.com"
  "download-ssc.cisco.com"
  "software.cisco.com"
  "developers.google.com"
  "aistudio.google.com"
  "checks.google.com"
  "makersuite.google.com"
  "play.google.com"
  "privacysandbox.google.com"
  "firebaseextensions.clients6.google.com"
  "studio.firebase.google.com"
  "firebase.google.com"
  "ads.google.com"
  "analytics.google.com"
  "developers.googleblog.com"
  "ai.google.dev"
  "api.google.dev"
  "developer.android.com"
  "developer.chrome.com"
  "fonts.googleapis.com"
  "firebaseremoteconfig.googleapis.com"
  "storage.googleapis.com"
  "googletagmanager.com"
  "google.qualtrics.com"
  "epsilon.6sense.com"
  "hpe.com"
  "community.hpe.com"
  "intel.com"
  "ark.intel.com"
  "corpredirect.intel.com"
  "downloadcenter.intel.com"
  "lenovo.com"
  "linuxhostsupport.com"
  "login.live.com"
  "login.live.com"
  "login.microsoftonline.com"
  "login.microsoftonline.com"
  "ebay.com"
  "mysql.com"
  "repo.mysql.com"
  "www.mysql.com"
  "nvidia.com"
  "download.nvidia.com"
  "images.nvidia.com"
  "www.nvidia.com"
  "nvidiacorp.us-5.evergage.com"
  "gfwsl.geforce.com"
  "oracle.com"
  "oraclecloud.com"
  "cloud.oracle.com"
  "pub.dev"
  "sentry.io"
  "bot-ee.sentry.io"
  "o1.ingest.sentry.io"
  "de.sentry.io"
  "reload.getsentry.net"
  "slack.com"
  "oriondemo.solarwinds.com"
  "thwack.solarwinds.com"
  "account.mojang.com"
  "authserver.mojang.com"
  "sessionserver.mojang.com"
  "skins.minecraft.net"
  "textures.minecraft.net"
  "api.minecraftservices.com"
  "auth.xboxlive.com"
  "user.auth.xboxlive.com"
  "xsts.auth.xboxlive.com"
  "apt.kubernetes.io"
  "i.ytimg.com"
  "whatismyipaddress.com"
  "blogs.vmware.com"
  "code.vmware.com"
  "docs.vmware.com"
  "kb.vmware.com"
  "mon.vmware.com"
  "my.vmware.com"
  "ssc.vmware.com"
  "vsphereclient.vmware.com"
  "ws.zoominfo.com"
)

# Wildcards for your Minecraft auth stack (covers previous specific hosts):
WILDCARD_ZONES=(
  "download.nvidia.com"
  "clients6.google.com"
  "cloud.google.com"
  "tagmanager.google.com"
  "kaggle.com"
)

# If you prefer to whitelist only the previous exact hostnames, empty WILDCARD_ZONES
# and put them into EXACT_FQDNS instead.

###############################################################################
# DETECT PRIMARY IP (proxy IP returned by DNS)
###############################################################################
PRIMARY_IP="$(hostname -I | awk '{print $1}')"
if [[ -z "${PRIMARY_IP}" ]]; then
  echo "Could not determine PRIMARY_IP"; exit 1
fi
echo "Detected server IP: ${PRIMARY_IP}"

###############################################################################
# HELPERS
###############################################################################
free_port_53() {
  echo "[pre] Freeing port 53 from any previous Docker bindings..."
  if command -v docker >/dev/null 2>&1; then
    if [[ -f /opt/phoenix-dns-proxy/docker-compose.yml ]]; then
      (cd /opt/phoenix-dns-proxy && sudo docker compose down --remove-orphans || true)
    fi
    mapfile -t CIDS < <(sudo docker ps --format '{{.ID}} {{.Ports}}' | grep -E '(:53->|0\.0\.0\.0:53|:::53)' || true)
    if (( ${#CIDS[@]} )); then
      echo "[pre] Stopping containers publishing :53: ${CIDS[*]}"
      IDS=(); for line in "${CIDS[@]}"; do IDS+=("${line%% *}"); done
      sudo docker stop "${IDS[@]}" || true
    fi
  fi
  sleep 1
}

###############################################################################
# 0) systemd-resolved: keep DNS working but free :53
###############################################################################
free_port_53

echo "[0/8] Preparing systemd-resolved to free :53 but keep DNS working..."
sudo mkdir -p /etc/systemd/resolved.conf.d
sudo tee /etc/systemd/resolved.conf.d/dns-tproxy.conf >/dev/null <<'EOF'
[Resolve]
# Keep host DNS working via upstream resolvers while CoreDNS isn't up yet
DNS=1.1.1.1 8.8.8.8
# Stop binding to port 53 so our container can listen there
DNSStubListener=no
EOF

# Ensure host uses resolved's runtime resolv.conf
if [[ ! -L /etc/resolv.conf ]] || [[ "$(readlink -f /etc/resolv.conf)" != "/run/systemd/resolve/resolv.conf" ]]; then
  echo "[note] Re-pointing /etc/resolv.conf to /run/systemd/resolve/resolv.conf"
  sudo rm -f /etc/resolv.conf
  sudo ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
fi

sudo systemctl restart systemd-resolved
sleep 1

# Final gate: ensure :53 is free before continuing
if ss -lntup | grep -qE '(:53)\s'; then
  echo "Port 53 still in use. Current listeners:"; ss -lntup | grep ':53' || true
  echo "Resolve this (stop offending service) and re-run."; exit 1
fi

###############################################################################
# 1) Docker Engine + Compose
###############################################################################
echo "[1/8] Installing Docker..."
if ! command -v docker >/dev/null 2>&1; then
  sudo apt-get update -y
  sudo apt-get install -y ca-certificates curl gnupg lsb-release
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update -y
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
sudo usermod -aG docker "$USER" || true

###############################################################################
# 2) System TCP tuning (PLPMTUD)
###############################################################################
echo "[2/8] Enabling TCP MTU probing..."
sudo tee /etc/sysctl.d/99-dns-tproxy.conf >/dev/null <<'EOF'
# Packetization-Layer Path MTU Discovery (see kernel docs)
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_base_mss=1024
EOF
sudo sysctl --system >/dev/null

###############################################################################
# 3) Write configs
###############################################################################
echo "[3/8] Writing files..."
sudo mkdir -p /opt/phoenix-dns-proxy/{coredns,sniproxy,logs}
sudo mkdir -p /opt/phoenix-dns-proxy/logs/sniproxy

# docker-compose.yml — CoreDNS + sniproxy on a custom bridge (MTU 1450)
sudo tee /opt/phoenix-dns-proxy/docker-compose.yml >/dev/null <<'EOF'
services:
  coredns:
    image: coredns/coredns:1.11.1
    container_name: coredns
    restart: unless-stopped
    ports:
      - "53:53/udp"
      - "53:53/tcp"
    networks: [edge]
    volumes:
      - ./coredns/Corefile:/etc/coredns/Corefile:ro
    command: ["-conf", "/etc/coredns/Corefile"]

  sniproxy:
    image: tommylau/sniproxy:latest
    container_name: sniproxy
    restart: unless-stopped
    depends_on:
      - coredns
    ports:
      - "80:80/tcp"
      - "443:443/tcp"
    networks: [edge]
    volumes:
      - ./sniproxy/sniproxy.conf:/etc/sniproxy/sniproxy.conf:ro
      - ./logs/sniproxy:/var/log/sniproxy

networks:
  edge:
    driver: bridge
    driver_opts:
      com.docker.network.driver.mtu: "1450"
EOF

# CoreDNS Corefile: hijack exact & wildcard; else forward upstream
UP1="1.1.1.1"; UP2="8.8.8.8"
CORE_FILE="/opt/phoenix-dns-proxy/coredns/Corefile"
sudo bash -c "cat > '${CORE_FILE}'" <<EOF
.:53 {
  log
  errors
EOF

# EXACT FQDN templates (A -> proxy IP, AAAA -> NOERROR); fallthrough so non-matches proceed to forward
for host in "${EXACT_FQDNS[@]}"; do
  [[ -z "$host" ]] && continue
  esc="$(printf '%s' "$host" | sed 's/\./\\./g')"
  sudo bash -c "cat >> '${CORE_FILE}'" <<EOF
  # EXACT: ${host}
  template IN A . {
    match ^${esc}\.$
    answer "{{ .Name }} 60 IN A ${PRIMARY_IP}"
    fallthrough
  }
  template IN AAAA . {
    match ^${esc}\.$
    rcode NOERROR
    fallthrough
  }
EOF
done

# WILDCARD zones => match apex OR any subdomain: ^(.*\.)?zone\.tld\.$
for zone in "${WILDCARD_ZONES[@]}"; do
  [[ -z "$zone" ]] && continue
  base="$(printf '%s' "$zone" | sed 's/\./\\./g')"
  sudo bash -c "cat >> '${CORE_FILE}'" <<EOF
  # WILDCARD: *.${zone} (and apex ${zone})
  template IN A . {
    match ^(.*\.)?${base}\.$
    answer "{{ .Name }} 60 IN A ${PRIMARY_IP}"
    fallthrough
  }
  template IN AAAA . {
    match ^(.*\.)?${base}\.$
    rcode NOERROR
    fallthrough
  }
EOF
done

sudo bash -c "cat >> '${CORE_FILE}'" <<EOF
  cache 30
  forward . ${UP1} ${UP2}
}
EOF
# CoreDNS template/fallthrough behavior and forward plugin per docs. (coredns.io)  # refs: template/forward

# sniproxy.conf — resolver ipv4_only + regex tables
SNIPROXY_CONF="/opt/phoenix-dns-proxy/sniproxy/sniproxy.conf"
sudo tee "${SNIPROXY_CONF}" >/dev/null <<'EOF'
user daemon
pidfile /var/run/sniproxy.pid

error_log {
    filename /var/log/sniproxy/error.log
    priority notice
}

# Use IPv4 A-records only for backends (stable path)
resolver {
    nameserver 8.8.8.8
    nameserver 1.1.1.1
    mode ipv4_only
}

listen 80 {
    proto http
    table http_hosts
    access_log {
        filename /var/log/sniproxy/http_access.log
        priority notice
    }
    fallback 127.0.0.1:9
}

listen 443 {
    proto tls
    table https_hosts
    access_log {
        filename /var/log/sniproxy/https_access.log
        priority notice
    }
}
EOF

# Build sniproxy tables:
#  - EXACT: ^fqdn$
#  - WILDCARD: ^(.*\.)?zone$
{
  echo "table http_hosts {"
  for host in "${EXACT_FQDNS[@]}"; do
    [[ -z "$host" ]] && continue
    esc="$(printf '%s' "$host" | sed 's/\./\\./g')"
    echo "    ^${esc}\$ *"
  done
  for zone in "${WILDCARD_ZONES[@]}"; do
    [[ -z "$zone" ]] && continue
    base="$(printf '%s' "$zone" | sed 's/\./\\./g')"
    echo "    ^(.*\\.)?${base}\$ *"
  done
  echo "}"

  echo
  echo "table https_hosts {"
  for host in "${EXACT_FQDNS[@]}"; do
    [[ -z "$host" ]] && continue
    esc="$(printf '%s' "$host" | sed 's/\./\\./g')"
    echo "    ^${esc}\$ *"
  done
  for zone in "${WILDCARD_ZONES[@]}"; do
    [[ -z "$zone" ]] && continue
    base="$(printf '%s' "$zone" | sed 's/\./\\./g')"
    echo "    ^(.*\\.)?${base}\$ *"
  done
  echo "}"
} | sudo tee -a "${SNIPROXY_CONF}" >/dev/null

###############################################################################
# 4) Pull images
###############################################################################
echo "[4/8] Pulling images..."
sudo docker pull coredns/coredns:1.11.1
sudo docker pull tommylau/sniproxy:latest

###############################################################################
# 5) Start stack
###############################################################################
echo "[5/8] Starting containers..."
cd /opt/phoenix-dns-proxy
sudo docker compose up -d

sleep 1
if ! ss -lntup | grep -qE '(:53)\s.*docker'; then
  echo "CoreDNS does not appear to be listening on :53 yet. Logs:"
  sudo docker logs coredns || true
  exit 1
fi

###############################################################################
# 6) Health checks
###############################################################################
echo "[6/8] Health checks..."
SIP="${PRIMARY_IP}"
echo "- Whitelisted exact -> ${PRIMARY_IP}"
dig +short @"$SIP" A login.live.com || true
echo "- Whitelisted wildcard subdomain -> ${PRIMARY_IP}"
dig +short @"$SIP" A api.minecraftservices.com || true
echo "- Non-whitelisted -> real IP"
dig +short @"$SIP" A example.com || true

###############################################################################
# 7) Optional: Route the HOST itself through CoreDNS
###############################################################################
# Uncomment if you want the Ubuntu host to also use CoreDNS:
# echo "[7/8] Pointing host DNS to 127.0.0.1 (CoreDNS)..."
# sudo rm -f /etc/resolv.conf
# echo -e "nameserver 127.0.0.1\noptions timeout:2 attempts:1" | sudo tee /etc/resolv.conf >/dev/null

###############################################################################
# 8) Done
###############################################################################
echo "[8/8] Done."
echo "Proxy/DNS IP: ${PRIMARY_IP}"
echo "Clients must set their DNS server to this IP."
echo "Exact and wildcard zones are hijacked to the proxy; all others resolve normally."
