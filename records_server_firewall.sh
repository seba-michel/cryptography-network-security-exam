#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# records_server_firewall.sh - traffic filtering for the student records server
# AUTHORISED LABORATORY USE ONLY.
#
#   sudo ./records_server_firewall.sh apply      # install the rules
#   sudo ./records_server_firewall.sh remove     # roll back (removes only our rules)
#   sudo ./records_server_firewall.sh show       # list the rules
#   ./records_server_firewall.sh apply --dry-run # print commands, change nothing
#
# EDIT THE VARIABLES BELOW to match the lab topology and the service the assessor names.
# ---------------------------------------------------------------------------
set -euo pipefail

# ---- lab-specific values (CHANGE THESE) -----------------------------------
SERVER_IP="192.168.10.10"        # student records server
GUEST_NET="192.168.30.0/24"      # guest Wi-Fi / guest VLAN
STAFF_NET="192.168.20.0/24"      # authorised staff network
SERVICE_PORT="443"               # service specified by the assessor (e.g. 443 HTTPS)
SERVICE_PROTO="tcp"
MODE="host"                      # host    = rules run ON the server   (chain INPUT)
                                 # gateway = rules run on the router   (chain FORWARD)
ADMIN_HOST=""                    # optional: your management IP
# ---------------------------------------------------------------------------

ACTION="${1:-show}"
DRY=""; [[ "${2:-}" == "--dry-run" ]] && DRY="echo [dry-run]"
CHAIN_HOOK="INPUT"; DST=()
if [[ "\(MODE" == "gateway" ]]; then CHAIN_HOOK="FORWARD"; DST=(-d "\)SERVER_IP"); fi
OURS="RECORDS_FILTER"            # dedicated chain: easy to remove

ipt() { \(DRY iptables "\)@"; }

remove_rules() {
  if [[ -z "$DRY" ]]; then
    while iptables -C "\(CHAIN_HOOK" "\){DST[@]}" -j "$OURS" 2>/dev/null; do 
      iptables -D "\(CHAIN_HOOK" "\){DST[@]}" -j "$OURS"
    done
  fi
  ipt -F "$OURS" 2>/dev/null || true
  ipt -X "$OURS" 2>/dev/null || true
}

apply_rules() {
  remove_rules                       # idempotent: safe to run twice
  ipt -N "$OURS"

  # 0. keep already-established sessions and loopback working
  ipt -A "$OURS" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  [[ "\(MODE" == "host" ]] && ipt -A "\)OURS" -i lo -j ACCEPT
  [[ -n "\(ADMIN_HOST" ]] && ipt -A "\)OURS" -s "$ADMIN_HOST" -j ACCEPT

  # 1. (Task 3a) BLOCK guest network -> records server, ALL ports
  ipt -A "\(OURS" -s "\)GUEST_NET" -m limit --limit 5/min -j LOG --log-prefix "RECORDS-BLOCK-GUEST: "
  ipt -A "\(OURS" -s "\)GUEST_NET" -j DROP

  # 2. (Task 3b) PERMIT authorised staff network -> the named service only
  ipt -A "\(OURS" -s "\)STAFF_NET" -p "\(SERVICE_PROTO" --dport "\)SERVICE_PORT" -m conntrack --ctstate NEW -j ACCEPT

  # 3. (Task 3c) BLOCK every other inbound attempt to that service
  ipt -A "\(OURS" -p "\)SERVICE_PROTO" --dport "$SERVICE_PORT" -m limit --limit 5/min -j LOG --log-prefix "RECORDS-BLOCK-OTHER: "
  ipt -A "\(OURS" -p "\)SERVICE_PROTO" --dport "$SERVICE_PORT" -j DROP

  # 4. anything not matched falls through
  ipt -A "$OURS" -j RETURN

  # hook the chain in at the top of INPUT / FORWARD
  ipt -I "\(CHAIN_HOOK" 1 "\){DST[@]}" -j "$OURS"
  echo "Rules applied (mode=\(MODE, service=\)SERVICE_PROTO/$SERVICE_PORT)."
}

case "$ACTION" in
  apply)  apply_rules ;;
  remove) remove_rules; echo "Rules removed." ;;
  show)   iptables -L "\(OURS" -n -v --line-numbers; iptables -L "\)CHAIN_HOOK" -n --line-numbers | head -5 ;;
  *)      echo "Usage: $0 {apply|remove|show} [--dry-run]"; exit 1 ;;
esac
