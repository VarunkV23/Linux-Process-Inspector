#!/usr/bin/env bash
# =============================================================================
# Self-Hosted Infra Setup: Pi-hole + WireGuard + Gitea
# Tested on: Debian 12 / Ubuntu 22.04+
# Run as root: sudo bash infra_setup.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
info() { echo -e "${CYAN}[→]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && die "Run as root: sudo bash $0"

# ─── CONFIG (edit before running) ────────────────────────────────────────────
WG_PORT=51820
WG_SERVER_IP="10.8.0.1"
WG_CLIENT_IP="10.8.0.2"
GITEA_PORT=3000
GITEA_SSH_PORT=2222
GITEA_USER="git"
GITEA_VERSION="1.21.11"
PIHOLE_PASSWORD="changeme123"   # <-- CHANGE THIS
SERVER_IFACE=$(ip route | awk '/default/ {print $5; exit}')
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo "=================================================="
echo "  Self-Hosted Infra Installer"
echo "  Pi-hole | WireGuard | Gitea"
echo "=================================================="
info "Detected network interface: ${SERVER_IFACE}"
echo ""

# ─── SYSTEM UPDATE ────────────────────────────────────────────────────────────
info "Updating system packages..."
apt-get update -qq && apt-get upgrade -y -qq
apt-get install -y -qq curl wget git unzip ufw gnupg2 \
    apt-transport-https ca-certificates lsb-release sudo openssl
log "System updated"

# ══════════════════════════════════════════════════════════════════════════════
# 1. PI-HOLE
# ══════════════════════════════════════════════════════════════════════════════
info "Installing Pi-hole..."

mkdir -p /etc/pihole
cat > /etc/pihole/setupVars.conf <<EOF
PIHOLE_INTERFACE=${SERVER_IFACE}
IPV4_ADDRESS=$(hostname -I | awk '{print $1}')/24
IPV6_ADDRESS=
PIHOLE_DNS_1=1.1.1.1
PIHOLE_DNS_2=1.0.0.1
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=true
CACHE_SIZE=10000
DNS_FQDN_REQUIRED=false
DNS_BOGUS_PRIV=true
DNSMASQ_LISTENING=local
WEBPASSWORD=$(echo -n "${PIHOLE_PASSWORD}" | sha256sum | awk '{print $1}')
BLOCKING_ENABLED=true
EOF

curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended
log "Pi-hole installed — admin at http://$(hostname -I | awk '{print $1}')/admin"

# ══════════════════════════════════════════════════════════════════════════════
# 2. WIREGUARD
# ══════════════════════════════════════════════════════════════════════════════
info "Installing WireGuard..."
apt-get install -y -qq wireguard wireguard-tools qrencode

WG_DIR="/etc/wireguard"
umask 077

SERVER_PRIVKEY=$(wg genkey)
SERVER_PUBKEY=$(echo "${SERVER_PRIVKEY}" | wg pubkey)
CLIENT_PRIVKEY=$(wg genkey)
CLIENT_PUBKEY=$(echo "${CLIENT_PRIVKEY}" | wg pubkey)
PRESHARED_KEY=$(wg genpsk)

cat > "${WG_DIR}/wg0.conf" <<EOF
[Interface]
Address     = ${WG_SERVER_IP}/24
ListenPort  = ${WG_PORT}
PrivateKey  = ${SERVER_PRIVKEY}

# NAT all VPN traffic out through the physical NIC
PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; \
           iptables -A FORWARD -o wg0 -j ACCEPT; \
           iptables -t nat -A POSTROUTING -o ${SERVER_IFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; \
           iptables -D FORWARD -o wg0 -j ACCEPT; \
           iptables -t nat -D POSTROUTING -o ${SERVER_IFACE} -j MASQUERADE

[Peer]
# Client 1
PublicKey    = ${CLIENT_PUBKEY}
PresharedKey = ${PRESHARED_KEY}
AllowedIPs   = ${WG_CLIENT_IP}/32
EOF

SERVER_PUBLIC_IP=$(curl -s https://api.ipify.org)
cat > "${WG_DIR}/client1.conf" <<EOF
[Interface]
Address    = ${WG_CLIENT_IP}/24
PrivateKey = ${CLIENT_PRIVKEY}
DNS        = ${WG_SERVER_IP}   # Pi-hole handles DNS inside the tunnel

[Peer]
PublicKey           = ${SERVER_PUBKEY}
PresharedKey        = ${PRESHARED_KEY}
Endpoint            = ${SERVER_PUBLIC_IP}:${WG_PORT}
AllowedIPs          = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

# Enable IP forwarding
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p -q

systemctl enable --now wg-quick@wg0
log "WireGuard running on UDP port ${WG_PORT}"
log "Client config: ${WG_DIR}/client1.conf"

echo ""
info "Scan in the WireGuard app:"
qrencode -t ansiutf8 < "${WG_DIR}/client1.conf"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# 3. GITEA
# ══════════════════════════════════════════════════════════════════════════════
info "Installing Gitea ${GITEA_VERSION}..."

if ! id "${GITEA_USER}" &>/dev/null; then
    adduser --system --shell /bin/bash --gecos 'Gitea' \
            --group --disabled-password --home /home/${GITEA_USER} ${GITEA_USER}
fi

mkdir -p /var/lib/gitea/{custom,data,log} /etc/gitea
chown -R ${GITEA_USER}:${GITEA_USER} /var/lib/gitea /etc/gitea
chmod 750 /etc/gitea

ARCH=$(dpkg --print-architecture | sed 's/armhf/arm-6/')
wget -q -O /usr/local/bin/gitea \
    "https://dl.gitea.io/gitea/${GITEA_VERSION}/gitea-${GITEA_VERSION}-linux-${ARCH}"
chmod +x /usr/local/bin/gitea

cat > /etc/systemd/system/gitea.service <<EOF
[Unit]
Description=Gitea
After=network.target

[Service]
Type=simple
User=${GITEA_USER}
Group=${GITEA_USER}
WorkingDirectory=/var/lib/gitea/
ExecStart=/usr/local/bin/gitea web --config /etc/gitea/app.ini
Restart=always
Environment=USER=${GITEA_USER} HOME=/home/${GITEA_USER} GITEA_WORK_DIR=/var/lib/gitea

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/gitea/app.ini <<EOF
APP_NAME = Varun's Git Server
RUN_USER = ${GITEA_USER}
RUN_MODE = prod

[server]
HTTP_PORT       = ${GITEA_PORT}
SSH_PORT        = ${GITEA_SSH_PORT}
SSH_LISTEN_PORT = ${GITEA_SSH_PORT}
ROOT_URL        = http://$(hostname -I | awk '{print $1}'):${GITEA_PORT}/

[database]
DB_TYPE = sqlite3
PATH    = /var/lib/gitea/data/gitea.db

[repository]
ROOT = /var/lib/gitea/data/repositories

[security]
INSTALL_LOCK   = false
SECRET_KEY     = $(openssl rand -hex 32)
INTERNAL_TOKEN = $(openssl rand -hex 32)

[service]
DISABLE_REGISTRATION = true
REQUIRE_SIGNIN_VIEW  = true

[log]
ROOT_PATH = /var/lib/gitea/log
LEVEL     = warn
EOF

chown ${GITEA_USER}:${GITEA_USER} /etc/gitea/app.ini
systemctl daemon-reload
systemctl enable --now gitea
log "Gitea running at http://$(hostname -I | awk '{print $1}'):${GITEA_PORT}"

# ══════════════════════════════════════════════════════════════════════════════
# 4. FIREWALL
# ══════════════════════════════════════════════════════════════════════════════
info "Configuring UFW firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp            # Pi-hole
ufw allow 443/tcp
ufw allow ${WG_PORT}/udp    # WireGuard
# Gitea is only reachable over the VPN tunnel (wg0), not the open internet
ufw allow in on wg0 to any port ${GITEA_PORT}
ufw allow in on wg0 to any port ${GITEA_SSH_PORT}
ufw --force enable
log "Firewall configured — Gitea is VPN-only"

# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=================================================="
echo "  All done!"
echo "=================================================="
echo "  Pi-hole  → http://$(hostname -I | awk '{print $1}')/admin"
echo "             Password: ${PIHOLE_PASSWORD}"
echo ""
echo "  WireGuard → UDP ${WG_PORT} | Client config: ${WG_DIR}/client1.conf"
echo ""
echo "  Gitea    → http://$(hostname -I | awk '{print $1}'):${GITEA_PORT}"
echo "             Connect via WireGuard first, then visit to finish setup."
echo "=================================================="
warn "Remember to change PIHOLE_PASSWORD at the top before sharing this script."
echo ""
