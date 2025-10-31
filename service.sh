#!/system/bin/sh
# VPN-Hotspot-Fixed service script - improved and complete
MODPATH="/data/adb/modules/VPN-Hotspot-Fixed"
LOGFILE="$MODPATH/log.txt"

log() {
    mkdir -p "$(dirname "$LOGFILE")"
    echo "$(date '+%F %T') | $*" >> "$LOGFILE"
}

# Cleanup on exit
cleanup() {
    log "Cleaning up and flushing rules"
    flush_rules "$PREV_T" "$PREV_V" "$PREV_DNS" >/dev/null 2>&1
    exit 0
}
trap cleanup INT TERM EXIT

log "=== SERVICE STARTED ==="

# Helpers to run iptables/ip6tables safely
run_cmd() {
    "$@" 2>/dev/null || true
}

# Detect likely VPN interfaces
detect_vpn() {
    for iface in tun0 tun1 tun2 wg0 wg1 vpn0 vpn1 ppp0 utun0; do
        if ip link show "$iface" >/dev/null 2>&1; then
            echo "$iface"
            return 0
        fi
    done
    # fallback: find interfaces with POINTTOPOINT or tun characteristics
    ip -o link show | awk -F': ' '{print $2}' | while read ifc; do
        if ip -d link show "$ifc" 2>/dev/null | grep -iqE 'tun|wireguard|vpn|point-to-point'; then
            echo "$ifc" && return 0
        fi
    done
    return 1
}

# Detect tethering (hotspot) interface: common names
detect_tether() {
    for iface in wlan0 ap0 rndis0 usb0 tether0; do
        if ip link show "$iface" >/dev/null 2>&1; then
            # check if it has an IP in 192.168/10/172 ranges typical for tether
            if ip -4 addr show dev "$iface" | grep -qE 'inet (10\.|192\.168|172\.(1[6-9]|2[0-9]|3[0-1]))'; then
                echo "$iface" && return 0
            fi
        fi
    done
    # fallback: any interface with 'ap' or 'wlan' and an IPv4 address
    ip -4 -o addr show | awk '{print $2}' | sort -u | while read ifc; do
        if echo "$ifc" | grep -qiE 'wlan|ap|rndis|usb|tether'; then
            echo "$ifc" && return 0
        fi
    done
    return 1
}

# Detect DNS server to use for forwarding
detect_dns() {
    # try Android system properties
    for p in net.dns1 net.dns2 net.dns3 net.dns4; do
        ip=$(getprop "$p" 2>/dev/null | sed -n '/[0-9]/p' | head -n1)
        if [ -n "$ip" ]; then
            echo "$ip" && return 0
        fi
    done
    # fallback resolv.conf
    if [ -r /etc/resolv.conf ]; then
        awk '/nameserver/ {print $2; exit}' /etc/resolv.conf
    fi
}

# Apply iptables rules for NAT/forwarding and DNS redirect
apply_rules() {
    TETHER="$1"
    VPN="$2"
    DNS="$3"

    log "Applying rules: TETHER=$TETHER VPN=$VPN DNS=$DNS"

    # Basic IPv4 forwarding and NAT
    run_cmd sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1

    # Allow forwarding between tether and vpn
    run_cmd iptables -C FORWARD -i "$TETHER" -o "$VPN" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$TETHER" -o "$VPN" -j ACCEPT
    run_cmd iptables -C FORWARD -i "$VPN" -o "$TETHER" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$VPN" -o "$TETHER" -m state --state RELATED,ESTABLISHED -j ACCEPT

    # NAT/masquerade outgoing traffic via VPN
    run_cmd iptables -t nat -C POSTROUTING -o "$VPN" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -o "$VPN" -j MASQUERADE

    # If DNS provided, redirect tether DNS queries to that DNS (both UDP and TCP)
    if [ -n "$DNS" ]; then
        run_cmd iptables -t nat -C PREROUTING -i "$TETHER" -p udp --dport 53 -j DNAT --to-destination "$DNS" 2>/dev/null || \
            iptables -t nat -A PREROUTING -i "$TETHER" -p udp --dport 53 -j DNAT --to-destination "$DNS"
        run_cmd iptables -t nat -C PREROUTING -i "$TETHER" -p tcp --dport 53 -j DNAT --to-destination "$DNS" 2>/dev/null || \
            iptables -t nat -A PREROUTING -i "$TETHER" -p tcp --dport 53 -j DNAT --to-destination "$DNS"
    fi

    # Optional: allow tether interface to access VPN management (IKE/UDP/etc)
    run_cmd iptables -C INPUT -i "$TETHER" -j ACCEPT 2>/dev/null || \
        iptables -A INPUT -i "$TETHER" -j ACCEPT

    # Try IPv6 handling if clat4 available (translate v4->v6)
    if ip link show clat4 >/dev/null 2>&1; then
        log "clat4 present - enabling IPv6 forwarding"
        run_cmd sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1
        run_cmd ip6tables -C FORWARD -i "$TETHER" -o "$VPN" -j ACCEPT 2>/dev/null || \
            ip6tables -A FORWARD -i "$TETHER" -o "$VPN" -j ACCEPT
    fi

    log "Rules applied"
}

# Flush rules previously applied for given interfaces
flush_rules() {
    OLD_T="$1"
    OLD_V="$2"
    OLD_DNS="$3"

    if [ -z "$OLD_T" ] && [ -z "$OLD_V" ]; then
        return 0
    fi

    log "Flushing old rules TETHER=$OLD_T VPN=$OLD_V DNS=$OLD_DNS"

    # remove forwarding rules
    if [ -n "$OLD_T" ] && [ -n "$OLD_V" ]; then
        run_cmd iptables -D FORWARD -i "$OLD_T" -o "$OLD_V" -j ACCEPT 2>/dev/null || true
        run_cmd iptables -D FORWARD -i "$OLD_V" -o "$OLD_T" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
        run_cmd iptables -t nat -D POSTROUTING -o "$OLD_V" -j MASQUERADE 2>/dev/null || true
    fi

    # remove DNS redirect rules if set
    if [ -n "$OLD_T" ] && [ -n "$OLD_DNS" ]; then
        run_cmd iptables -t nat -D PREROUTING -i "$OLD_T" -p udp --dport 53 -j DNAT --to-destination "$OLD_DNS" 2>/dev/null || true
        run_cmd iptables -t nat -D PREROUTING -i "$OLD_T" -p tcp --dport 53 -j DNAT --to-destination "$OLD_DNS" 2>/dev/null || true
    fi

    # best-effort IPv6 cleanup
    if ip link show clat4 >/dev/null 2>&1; then
        run_cmd ip6tables -D FORWARD -i "$OLD_T" -o "$OLD_V" -j ACCEPT 2>/dev/null || true
    fi

    log "Flush complete"
}

PREV_T=""
PREV_V=""
PREV_DNS=""

# Main loop: watch for VPN + Tether and apply rules when both present
while true; do
    VPN=$(detect_vpn 2>/dev/null || true)
    TETHER=$(detect_tether 2>/dev/null || true)
    DNS=$(detect_dns 2>/dev/null || true)

    # Normalize empty values
    [ -z "$VPN" ] && VPN=""
    [ -z "$TETHER" ] && TETHER=""
    [ -z "$DNS" ] && DNS=""

    if [ -n "$VPN" ] && [ -n "$TETHER" ]; then
        if [ "$VPN" != "$PREV_V" ] || [ "$TETHER" != "$PREV_T" ] || [ "$DNS" != "$PREV_DNS" ]; then
            flush_rules "$PREV_T" "$PREV_V" "$PREV_DNS"
            apply_rules "$TETHER" "$VPN" "$DNS"
            PREV_T="$TETHER"
            PREV_V="$VPN"
            PREV_DNS="$DNS"
        fi
    else
        if [ -n "$PREV_T" ] || [ -n "$PREV_V" ]; then
            flush_rules "$PREV_T" "$PREV_V" "$PREV_DNS"
            PREV_T=""
            PREV_V=""
            PREV_DNS=""
        fi
        log "Waiting for both VPN and hotspot interfaces to be present (VPN=$VPN TETHER=$TETHER)"
    fi

    sleep 3
done