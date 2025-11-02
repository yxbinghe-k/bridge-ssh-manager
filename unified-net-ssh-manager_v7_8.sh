#!/bin/bash
# unified-net-ssh-manager_v7_8.sh — 智能稳定版（修正自动检测逻辑 + 防卡死 + UI 无括号图标）
set -euo pipefail
VERSION="v7.8"
REPORT_DIR="/root/net-ssh-report"
mkdir -p "$REPORT_DIR" 2>/dev/null || true

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
ok(){   echo -e "${GREEN}✔ $*${NC}"; }
warn(){ echo -e "${YELLOW}⚠ $*${NC}"; }
have(){ command -v "$1" >/dev/null 2>&1; }
now_ts(){ date "+%Y%m%d-%H%M%S"; }

tcmd(){ local t="$1"; shift; if have timeout; then timeout --preserve-status "$t" "$@" 2>/dev/null; else "$@" 2>/dev/null; fi }

TMP_DIR="$(mktemp -d /tmp/unified-net-ssh.XXXXXX)"; trap 'rm -rf "$TMP_DIR"' EXIT
SB_FILE="$TMP_DIR/smart-bridge.sh"; SSH_FILE="$TMP_DIR/ssh_forward_manager.sh"
cat >"$SB_FILE" <<'SB_EOF'
#!/bin/bash
# =========================================================
# smart-bridge.sh.r6 — openEuler 智能 Bridge + VLAN 自动配置脚本
# 作者：Wise_ice（2025-11-01）
# ✅ 支持 NetworkManager / legacy 双模式自动识别
# ✅ 可交互选择「桥接 VLAN」或「直连 VLAN」
# ✅ 自动备份 / 清理旧 ifcfg
# ✅ 含 check-only / auto-repair / uninstall
# ✅ 统一 wait + ping 自愈逻辑
# ✅ 网卡列表显示当前 IPv4
# ✅ 完整结尾总结 输出
# =========================================================
set -euo pipefail

# ---------- 样式 ----------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok(){   echo -e "${GREEN}✔ $*${NC}"; }
warn(){ echo -e "${YELLOW}⚠ $*${NC}"; }
err(){  echo -e "${RED}✘ $*${NC}" >&2; }

READY_TIMEOUT="${READY_TIMEOUT:-12}"
PING_RETRY1=2
PING_DELAY_FINAL=5

IFCFG_DIR="/etc/sysconfig/network-scripts"
BACKUP_DIR="/root/ifcfg-backup-$(date +%Y%m%d-%H%M%S)"

# ---------- 公共工具 ----------
is_active(){ systemctl is-active --quiet "$1"; }
have(){ command -v "$1" >/dev/null 2>&1; }

cidr_last_usable(){
  local ipcidr="$1"; local ip pre; IFS='/' read -r ip pre <<<"$ipcidr"
  local a b c d; IFS='.' read -r a b c d <<<"$ip"
  local mask=$((0xffffffff << (32 - pre) & 0xffffffff))
  local n=$(( (a<<24) + (b<<16) + (c<<8) + d ))
  local net=$(( n & mask ))
  local bcast=$(( net | (~mask & 0xffffffff) ))
  local gw=$(( bcast - 1 ))
  printf "%d.%d.%d.%d" $(( (gw>>24)&255 )) $(( (gw>>16)&255 )) $(( (gw>>8)&255 )) $(( gw&255 ))
}

wait_until_ready(){
  local iface="$1" ipcidr="$2" gw="$3"
  local sec=0; local got_ip=1
  while (( sec < READY_TIMEOUT )); do
    local st="$(cat /sys/class/net/${iface}/operstate 2>/dev/null || echo unknown)"
    ip addr show "$iface" 2>/dev/null | grep -q "inet ${ipcidr%%/*}/" && got_ip=0 || got_ip=1
    if [[ "$st" == "up" && $got_ip -eq 0 ]]; then
      ok "接口 ${iface} 已就绪（state=UP，IP 已配置）"
      break
    fi
    echo -ne "${YELLOW}等待 ${iface} 就绪…（${sec}/${READY_TIMEOUT}s）\r${NC}"
    sleep 1; sec=$((sec+1))
  done
  echo -ne "\r\033[0K"
  have arping && arping -I "$iface" -c 1 -w 2 "$gw" >/dev/null 2>&1 || true
}

ping_with_retry(){
  local iface="$1" gw="$2"
  for i in $(seq 1 $PING_RETRY1); do
    echo -e "${YELLOW}Ping ${gw}（第 ${i}/${PING_RETRY1} 次）…${NC}"
    if ping -I "$iface" -c 3 -W 2 "$gw" >/dev/null 2>&1; then ok "Ping 成功"; return 0; fi
    sleep 2
  done
  warn "前两次失败，等待 ${PING_DELAY_FINAL}s 后最终重试…"
  sleep "$PING_DELAY_FINAL"
  if ping -I "$iface" -c 3 -W 2 "$gw" >/dev/null 2>&1; then ok "延迟重试成功"; return 0; fi
  err "Ping 仍失败，请检查交换机 VLAN/SVI 或链路/生成树"
  return 1
}

# ---------- 网卡列表 ----------
list_phys_ifaces(){
  # 列出可用接口：物理 + VLAN（含 brX.Y，但排除裸 brX）
  ls /sys/class/net \
    | grep -Ev '^(lo|docker.*|veth.*|virbr.*|vnet.*|tap.*|tun.*|wg.*|zt.*|tailscale.*|nm-.*|bond.*|team.*|macvlan.*|ipvlan.*|sit.*|gre.*|gretap.*|br[0-9]+$)' \
    | sort
}

print_iface_menu(){
  local arr=("$@")
  echo -e "${CYAN}✅ 网卡列表（绿色=UP，黄色=未连接）：${NC}"
  local i=0
  for nic in "${arr[@]}"; do
    local st="$(cat /sys/class/net/${nic}/operstate 2>/dev/null || echo unknown)"
    local ip4="$(ip -4 addr show "$nic" 2>/dev/null | awk '/inet /{print $2}' | head -n1)"
    [[ -z "$ip4" ]] && ip4="无IP"
    if [[ "$st" == "up" ]]; then
      echo -e "  [${i}] ${GREEN}${nic}${NC}（UP） — ${ip4}"
    elif [[ "$st" == "down" || "$st" == "no-carrier" ]]; then
      echo -e "  [${i}] ${YELLOW}${nic}${NC}（未连接） — ${ip4}"
    else
      echo -e "  [${i}] ${nic}（${st}) — ${ip4}"
    fi
    i=$((i+1))
  done
}

detect_mode(){
  local mode="nm"
  if is_active NetworkManager; then mode="nm"
  elif is_active network; then mode="legacy"
  else mode="nm"; fi
  echo "$mode"
}

banner(){
  echo "============================================"
  echo -e " ${BOLD}🧠 openEuler 智能桥接 + VLAN 配置向导${NC}"
  echo "============================================"
}

# ---------- 检查 / 自愈 / 卸载 ----------
check_only(){
  echo -e "${YELLOW}🔍 进入检查模式（不会修改配置）${NC}"
  local bridges=$(nmcli -t -f NAME con show 2>/dev/null | grep -E '^br[0-9]+' || true)
  if [[ -z "${bridges}" ]]; then warn "未检测到任何 bridge 连接（NetworkManager）"; fi
  for br in $bridges; do
    echo -e "\n${CYAN}桥接：${br}${NC}"
    nmcli -f GENERAL.STATE,GENERAL.DEVICES con show "$br" 2>/dev/null || true
    local vlans=$(nmcli -t -f NAME con show 2>/dev/null | grep -E "^${br}\.[0-9]+" || true)
    for v in $vlans; do
      echo "  └─ VLAN：$v"
      local dev=$(nmcli -t -f GENERAL.DEVICES con show "$v" | cut -d: -f2)
      local ip=$(nmcli -t -f IP4.ADDRESS con show "$v" | cut -d: -f2)
      local gw=$(nmcli -t -f IP4.GATEWAY con show "$v" | cut -d: -f2)
      echo "     设备：${dev:-$v}"
      echo "     IPv4：${ip:-无}"
      echo "     网关：${gw:-无}"
      [[ -n "$dev" && -n "$gw" && -d "/sys/class/net/$dev" ]] && {
        wait_until_ready "$dev" "${ip%%,*}" "$gw"
        ping_with_retry "$dev" "$gw" || true
      }
    done
  done
  ok "检查完成。"
}

auto_repair(){
  echo "============================================"
  echo -e " 🩺 桥接/VLAN 自愈模式（Auto Repair）"
  echo "============================================"
  local bridges=$(nmcli -t -f NAME con show 2>/dev/null | grep -E '^br[0-9]+' || true)
  [[ -z "$bridges" ]] && { warn "未发现 bridge 连接"; exit 0; }
  for br in $bridges; do
    echo -e "\n${CYAN}桥接：${br}${NC}"
    nmcli con up "$br" >/dev/null 2>&1 || true
    local vlans=$(nmcli -t -f NAME con show | grep -E "^${br}\.[0-9]+" || true)
    for v in $vlans; do
      nmcli con up "$v" >/dev/null 2>&1 || true
      nmcli con mod "$v" ipv6.method ignore >/dev/null 2>&1 || true
      local dev=$(nmcli -t -f GENERAL.DEVICES con show "$v" | cut -d: -f2)
      local ip=$(nmcli -t -f IP4.ADDRESS con show "$v" | cut -d: -f2)
      local gw=$(nmcli -t -f IP4.GATEWAY con show "$v" | cut -d: -f2)
      echo "  └─ $v / dev=${dev:-$v} / ip=${ip:-无} / gw=${gw:-无}"
      [[ -n "$dev" && -n "$gw" && -d "/sys/class/net/$dev" ]] && {
        wait_until_ready "$dev" "${ip%%,*}" "$gw"
        ping_with_retry "$dev" "$gw" || true
      }
      nmcli con mod "$v" connection.autoconnect yes >/dev/null 2>&1 || true
    done
  done
  ok "自愈完成。"
}

uninstall_all(){
  echo -e "${YELLOW}⚠ 执行卸载：删除脚本创建的 NM 连接与 ifcfg 文件（已备份）${NC}"
  mkdir -p "$BACKUP_DIR"
  if [[ -d "$IFCFG_DIR" ]]; then
    find "$IFCFG_DIR" -maxdepth 1 -type f \( -name "ifcfg-br*" -o -name "ifcfg-*.vlan" -o -name "ifcfg-*.206" \) \
      -exec cp -a {} "$BACKUP_DIR"/ \; -exec rm -f {} \;
  fi
  if have nmcli; then
    nmcli -t -f NAME con show | grep -E '^br[0-9]+(\.[0-9]+)?$' | while read -r n; do nmcli con delete "$n" || true; done
    nmcli -t -f NAME con show | grep -E '^-port$' | while read -r n; do nmcli con delete "$n" || true; done
  fi
  ok "已卸载（备份目录：$BACKUP_DIR）"
}

# ---------- 子命令 ----------
case "${1:-}" in
  --check-only)  check_only; exit 0 ;;
  --auto-repair) auto_repair; exit 0 ;;
  --uninstall)   uninstall_all; exit 0 ;;
esac

# ---------- 主流程 ----------
clear
mkdir -p "$IFCFG_DIR"
if is_active NetworkManager && ! is_active network; then
  ok "网络管理由 NetworkManager 独占。"
elif is_active network && ! is_active NetworkManager; then
  ok "网络管理由 legacy network.service 管理。"
else
  warn "检测到 NetworkManager 与 network.service 并存，建议仅保留一种。"
fi

banner

DETECTED_MODE="$(detect_mode)"
echo -e "检测到模式：${CYAN}${DETECTED_MODE}${NC}  可选：nm / legacy"
read -rp "请输入使用的模式（回车=默认 ${DETECTED_MODE}）： " MODE
MODE="${MODE:-$DETECTED_MODE}"
[[ "$MODE" != "nm" && "$MODE" != "legacy" ]] && { err "无效模式：$MODE"; exit 1; }

mapfile -t ALL_IFACES < <(list_phys_ifaces)
if ((${#ALL_IFACES[@]} == 0)); then err "未检测到网卡"; exit 1; fi
print_iface_menu "${ALL_IFACES[@]}"
read -rp "请选择用作主口的网卡编号：" IDX
PHY="${ALL_IFACES[$IDX]:-}"
[[ -z "$PHY" ]] && { err "无效选择"; exit 1; }
ok "已选择网卡：$PHY"

echo -e "\n请选择配置模式："
echo -e "  [1] 桥接 VLAN（Bridge on VLAN） ${GREEN}（默认）${NC}"
echo -e "  [2] 直连 VLAN（Direct VLAN，无桥）"
read -rp "输入 1 或 2（回车=默认 1）： " MSEL
MSEL="${MSEL:-1}"
[[ "$MSEL" != "1" && "$MSEL" != "2" ]] && { err "无效选择"; exit 1; }

read -rp "请输入桥接名称（默认 br207）： " BR; BR="${BR:-br207}"
AUTO_VLAN="$(echo "$BR" | grep -Eo '[0-9]+' | tail -1)"; AUTO_VLAN="${AUTO_VLAN:-1}"
read -rp "请输入 VLAN ID（默认 ${AUTO_VLAN}）： " VLAN_ID; VLAN_ID="${VLAN_ID:-$AUTO_VLAN}"
read -rp "请输入 IP 地址/CIDR（例如 10.23.117.124/26）： " IPADDR
[[ "$IPADDR" =~ / ]] || { err "IP 地址必须包含 CIDR（如 /24）"; exit 1; }
DEFAULT_GW="$(cidr_last_usable "$IPADDR")"
read -rp "自动计算网关为 ${DEFAULT_GW}，是否使用该地址？(Y/n): " ANS
if [[ "$ANS" =~ ^[nN]$ ]]; then read -rp "请输入自定义网关： " GATEWAY; else GATEWAY="$DEFAULT_GW"; fi
read -rp "请输入首选 DNS（默认 10.23.4.149）： " DNS1; DNS1="${DNS1:-10.23.4.149}"
read -rp "请输入备用 DNS（默认 10.23.4.150）： " DNS2; DNS2="${DNS2:-10.23.4.150}"

echo -e "\n${BOLD}配置摘要：${NC}
  模式：      ${MODE} / $([[ "$MSEL" == "1" ]] && echo '桥接 VLAN' || echo '直连 VLAN')
  网卡：      ${PHY}
  桥接名：    ${BR}
  VLAN ID：   ${VLAN_ID}
  IPv4：      ${IPADDR}
  网关：      ${GATEWAY}
  DNS：       ${DNS1}, ${DNS2}
"
read -rp "确认执行？(y/n): " OKGO
[[ "$OKGO" != [yY] ]] && { warn "已取消。"; exit 0; }

mkdir -p "$BACKUP_DIR"

# ---------- 执行 ----------
if [[ "$MODE" == "nm" ]]; then
  nmcli -t -f NAME con show | grep -E "^${BR}(\.${VLAN_ID})?$" 2>/dev/null | while read -r n; do nmcli con delete "$n" || true; done
  nmcli -t -f NAME con show | grep -E "^${BR}-port$" 2>/dev/null | while read -r n; do nmcli con delete "$n" || true; done

  if [[ "$MSEL" == "1" ]]; then
    # 桥接 VLAN
    nmcli con add type bridge ifname "${BR}" con-name "${BR}" >/dev/null 2>&1 || true
    nmcli con mod "${BR}" bridge.stp no ipv4.method disabled ipv6.method ignore connection.autoconnect yes
    nmcli con add type ethernet ifname "${PHY}" master "${BR}" con-name "${BR}-port" >/dev/null 2>&1 || true
    nmcli con mod "${BR}-port" connection.autoconnect yes
    nmcli con add type vlan con-name "${BR}.${VLAN_ID}" dev "${BR}" id "${VLAN_ID}" >/dev/null 2>&1 || true
    nmcli con mod "${BR}.${VLAN_ID}" \
      ipv4.addresses "${IPADDR}" ipv4.gateway "${GATEWAY}" \
      ipv4.dns "${DNS1} ${DNS2}" ipv4.method manual ipv6.method ignore connection.autoconnect yes
    nmcli con up "${BR}" >/dev/null 2>&1 || true; sleep 1
    nmcli con up "${BR}-port" >/dev/null 2>&1 || true; sleep 1
    nmcli con up "${BR}.${VLAN_ID}" >/dev/null 2>&1 || true
    wait_until_ready "${BR}.${VLAN_ID}" "${IPADDR}" "${GATEWAY}"
    ping_with_retry "${BR}.${VLAN_ID}" "${GATEWAY}" || true
  else
    # 直连 VLAN
    nmcli -t -f NAME con show | grep -E "^${PHY}\.${VLAN_ID}$" 2>/dev/null && nmcli con delete "${PHY}.${VLAN_ID}" || true
    nmcli con add type vlan con-name "${PHY}.${VLAN_ID}" dev "${PHY}" id "${VLAN_ID}" >/dev/null 2>&1 || true
    nmcli con mod "${PHY}.${VLAN_ID}" \
      ipv4.addresses "${IPADDR}" ipv4.gateway "${GATEWAY}" \
      ipv4.dns "${DNS1} ${DNS2}" ipv4.method manual ipv6.method ignore connection.autoconnect yes
    nmcli con up "${PHY}.${VLAN_ID}" >/dev/null 2>&1 || true
    wait_until_ready "${PHY}.${VLAN_ID}" "${IPADDR}" "${GATEWAY}"
    ping_with_retry "${PHY}.${VLAN_ID}" "${GATEWAY}" || true
  fi

else
  # legacy network.service
  for f in "$IFCFG_DIR/ifcfg-${BR}" "$IFCFG_DIR/ifcfg-${BR}-port" \
           "$IFCFG_DIR/ifcfg-${BR}.${VLAN_ID}" "$IFCFG_DIR/ifcfg-${PHY}.${VLAN_ID}"; do
    [[ -f "$f" ]] && { cp -a "$f" "$BACKUP_DIR/"; rm -f "$f"; }
  done

  if [[ "$MSEL" == "1" ]]; then
    cat >"$IFCFG_DIR/ifcfg-${BR}" <<EOF
TYPE=Bridge
NAME=${BR}
DEVICE=${BR}
ONBOOT=yes
BOOTPROTO=none
STP=off
DELAY=0
IPV6INIT=no
EOF

    cat >"$IFCFG_DIR/ifcfg-${BR}-port" <<EOF
TYPE=Ethernet
NAME=${BR}-port
DEVICE=${PHY}
ONBOOT=yes
BOOTPROTO=none
BRIDGE=${BR}
IPV6INIT=no
EOF

    cat >"$IFCFG_DIR/ifcfg-${BR}.${VLAN_ID}" <<EOF
TYPE=Vlan
NAME=${BR}.${VLAN_ID}
DEVICE=${BR}.${VLAN_ID}
PHYSDEV=${BR}
VLAN=yes
ONBOOT=yes
BOOTPROTO=none
IPADDR=${IPADDR%%/*}
PREFIX=${IPADDR##*/}
GATEWAY=${GATEWAY}
DNS1=${DNS1}
DNS2=${DNS2}
IPV6INIT=no
EOF

    systemctl restart network || { ifup "${BR}" || true; ifup "${BR}.${VLAN_ID}" || true; }
    wait_until_ready "${BR}.${VLAN_ID}" "${IPADDR}" "${GATEWAY}"
    ping_with_retry "${BR}.${VLAN_ID}" "${GATEWAY}" || true
  else
    cat >"$IFCFG_DIR/ifcfg-${PHY}.${VLAN_ID}" <<EOF
TYPE=Vlan
NAME=${PHY}.${VLAN_ID}
DEVICE=${PHY}.${VLAN_ID}
PHYSDEV=${PHY}
VLAN=yes
ONBOOT=yes
BOOTPROTO=none
IPADDR=${IPADDR%%/*}
PREFIX=${IPADDR##*/}
GATEWAY=${GATEWAY}
DNS1=${DNS1}
DNS2=${DNS2}
IPV6INIT=no
EOF
    systemctl restart network || { ifup "${PHY}.${VLAN_ID}" || true; }
    wait_until_ready "${PHY}.${VLAN_ID}" "${IPADDR}" "${GATEWAY}"
    ping_with_retry "${PHY}.${VLAN_ID}" "${GATEWAY}" || true
  fi
fi

# ---------- 收尾总结 ----------
echo
ok "配置完成 ✅"
echo "============================================"
echo -e "${GREEN}执行总结：${NC}"
echo -e "模式： $([[ "$MSEL" == "1" ]] && echo '桥接 VLAN (Bridge)' || echo '直连 VLAN (Direct)')"
echo -e "接口： $([[ "$MSEL" == "1" ]] && echo "${BR}.${VLAN_ID}" || echo "${PHY}.${VLAN_ID}")"
echo -e "IPv4： ${IPADDR}"
echo -e "网关： ${GATEWAY}"
echo -e "DNS：   ${DNS1}, ${DNS2}"
echo "============================================"


SB_EOF
chmod +x "$SB_FILE"
cat >"$SSH_FILE" <<'SSH_EOF'
#!/bin/bash
# =========================================================
# SSH Dynamic Forwarding Manager (v6.3 - ble.sh Compatible, Full Features)
# 支持: Rocky / openEuler / CentOS / RHEL
# 作者: ChatGPT (for wise user)
#
# 特性:
#   • --silent-auto   全自动无交互（按推荐值执行，核心目标=转发成功）
#   • --check-only    仅检测，不修改
#   • --json          结尾将报告以 JSON 输出到 stdout
#   • --json-path F   另存 JSON 报告到文件
#   • --log / --no-log   开/关日志（默认开）
#   • --log-path F    指定日志文件路径（默认 /var/log/ssh_forward_manager.log）
#   • 交互流程全部 5 秒无操作采用“推荐默认值”
#   • 物理链路/虚拟网卡标注，出口网卡选择
#   • 结束输出详细修改清单（含 restore）、JSON 报告
#
# 兼容说明:
#   • 移除了 set -e，仅保留 set -u + pipefail，兼容 ble.sh（不再出现 [ble: exit 1]）
#   • 检测类分支对常见非0返回（如 grep 无匹配）宽容处理
# =========================================================

# 宽容安全设置（兼容 ble.sh）
set -u
set -o pipefail

# ---------- 全局变量 ----------
CONFIG="/etc/ssh/sshd_config"
BACKUP_DIR="/etc/ssh/backup"
LOG_FILE="/var/log/ssh_forward_manager.log"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_FILE="$BACKUP_DIR/sshd_config.bak.$TS"

JSON_OUT=false
JSON_PATH=""
SILENT_AUTO=false
ENABLE_LOG=true
MODE=""                 # 交互模式: auto-fix / manual-fix / disable / restore
NONINTERACTIVE=false    # 给 prompt_with_timeout 判断是否直接取默认
SEL_IFACE=""            # 选择的出口网卡

mkdir -p "$BACKUP_DIR"

# ---------- 颜色 ----------
GREEN=$(tput setaf 2 2>/dev/null || true)
YELLOW=$(tput setaf 3 2>/dev/null || true)
CYAN=$(tput setaf 6 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
BOLD=$(tput bold 2>/dev/null || true)
RESET=$(tput sgr0 2>/dev/null || true)

# ---------- 报告存储 ----------
declare -a OP_REPORT=()
declare -A JSON_KV
declare -a JSON_BOOL_REPORT=()

report(){ OP_REPORT+=("$*"); $ENABLE_LOG && echo "$(date '+%F %T') | $*" >> "$LOG_FILE"; }
_json_escape(){ echo -n "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
jset(){ JSON_KV["$1"]="$2"; }
jadd_bool(){ # name, status, action
  JSON_BOOL_REPORT+=("{\"name\":\"$(_json_escape "$1")\",\"status\":\"$(_json_escape "$2")\",\"action\":\"$(_json_escape "$3")\"}")
}
_emit_json(){
  local i
  echo -n "{"
  echo -n "\"timestamp\":\"$(_json_escape "$(date '+%F %T')")\""
  for k in "${!JSON_KV[@]}"; do
    echo -n ",\"$(_json_escape "$k")\":\"$(_json_escape "${JSON_KV[$k]}")\""
  done
  echo -n ",\"booleans\":["
  for i in "${!JSON_BOOL_REPORT[@]}"; do
    [[ $i -gt 0 ]] && echo -n ","
    echo -n "${JSON_BOOL_REPORT[$i]}"
  done
  echo -n "],\"report\":["
  for i in "${!OP_REPORT[@]}"; do
    [[ $i -gt 0 ]] && echo -n ","
    echo -n "\"$(_json_escape "${OP_REPORT[$i]}")\""
  done
  echo -n "]}"
}

# ---------- CLI 解析 ----------
while (( "$#" )); do
  case "$1" in
    --check-only) MODE="check-only" ;;
    --silent-auto) SILENT_AUTO=true; NONINTERACTIVE=true; MODE="auto-fix" ;;
    --json) JSON_OUT=true ;;
    --json-path) shift; JSON_PATH="${1:-}";;
    --no-log) ENABLE_LOG=false ;;
    --log) ENABLE_LOG=true ;;
    --log-path) shift; LOG_FILE="${1:-/var/log/ssh_forward_manager.log}";;
    *) ;; # 忽略未知参数（宽容）
  esac
  shift || true
done

# ---------- 日志初始化 ----------
if $ENABLE_LOG; then
  mkdir -p "$(dirname "$LOG_FILE")" && touch "$LOG_FILE" || ENABLE_LOG=false
  $ENABLE_LOG && {
    echo -e "\n──────────────────────────────────────────" >> "$LOG_FILE"
    echo "📜 [$(date '+%F %T')] 启动 SSH Forward Manager v6.3" >> "$LOG_FILE"
  }
fi

# ---------- 工具 ----------
need_root(){ [ "$EUID" -ne 0 ] && { echo -e "${RED}需要root权限运行。${RESET}"; exit 1; }; }

prompt_with_timeout(){ # prompt default timeout
  local p="$1" def="$2" t="${3:-5}" a
  if $NONINTERACTIVE; then echo "$def"; return 0; fi
  read -t "$t" -p "$p" a || a="$def"; echo "$a"
}

backup_config(){
  if [ -f "$CONFIG" ]; then
    cp -a "$CONFIG" "$BACKUP_FILE" 2>/dev/null && \
    echo -e "🗂️  已备份 SSH 配置到: ${BOLD}${BACKUP_FILE}${RESET}" && \
    report "备份创建: $BACKUP_FILE" && jset "backup_file" "$BACKUP_FILE"
  fi
}

restart_sshd(){
  echo -e "🔄  重启 sshd 服务..."
  if systemctl restart sshd 2>/dev/null; then
    report "重启 sshd 成功"
  else
    echo -e "${YELLOW}⚠ 重启 sshd 失败，请手动检查。${RESET}"
    report "重启 sshd 失败"
    # 宽容：不强制退出，以便报告能输出
  fi
}

is_virtual_iface(){ [[ "$1" =~ ^(lo|virbr|docker|br|veth|tun|tap) ]]; }

pick_default_interface(){ # silent-auto 选择默认出口
  local dev
  dev=$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1);break}}' | head -n1)
  [ -n "${dev:-}" ] && echo "$dev" || ip -o link show | awk -F': ' '!/lo/{print $2;exit}'
}

# ---------- 配置修改 ----------
fix_ssh_forwarding(){
  sed -i '/^[# ]*AllowTcpForwarding/d;/^[# ]*PermitTunnel/d' "$CONFIG" 2>/dev/null || true
  { echo; echo "AllowTcpForwarding yes"; echo "PermitTunnel yes"; } >> "$CONFIG"
  echo -e "${CYAN}⚙️  已启用 SSH 动态转发配置（AllowTcpForwarding yes / PermitTunnel yes）${RESET}"
  report "sshd_config: AllowTcpForwarding=yes, PermitTunnel=yes"
}

disable_forwarding(){
  sed -i '/^[# ]*AllowTcpForwarding/d;/^[# ]*PermitTunnel/d' "$CONFIG" 2>/dev/null || true
  { echo "AllowTcpForwarding no"; echo "PermitTunnel no"; } >> "$CONFIG"
  echo -e "${YELLOW}🚫 已禁用 SSH 动态转发（AllowTcpForwarding no / PermitTunnel no）${RESET}"
  report "sshd_config: 禁用转发配置"
}

restore_backup(){
  echo -e "${CYAN}🔁 可用备份文件:${RESET}"
  local lst; lst=$(ls -1t "$BACKUP_DIR"/sshd_config.bak.* 2>/dev/null || true)
  [ -z "${lst:-}" ] && { echo "❌ 未找到备份文件"; return; }
  echo "$lst"
  local f
  if $NONINTERACTIVE; then
    f="$(echo "$lst" | head -n1)"
  else
    read -p "请输入要恢复的备份文件路径: " f
  fi
  if [ -f "$f" ]; then
    cp -a "$f" "$CONFIG"
    report "恢复配置: $f → $CONFIG"
    jset "restored_from" "$f"
    restart_sshd
  else
    echo "❌ 文件不存在"
  fi
}

# ---------- 定义策略布尔项（可选：实验用途） ----------
define_boolean_policy(){
  local key="$1"
  command -v checkmodule >/dev/null 2>&1 || { echo "  ❌ 缺少 checkmodule，无法创建策略"; return 1; }
  command -v semodule_package >/dev/null 2>&1 || { echo "  ❌ 缺少 semodule_package，无法创建策略"; return 1; }
  local te="/tmp/${key}.te" mod="/tmp/${key}.mod" pp="/tmp/${key}.pp"
  cat >"$te" <<EOF
policy_module(${key}, 1.0)
gen_bool(${key}, false)
EOF
  checkmodule -M -m -o "$mod" "$te" && semodule_package -o "$pp" -m "$mod" && semodule -i "$pp"
}

# ---------- 状态展示 ----------
show_ssh_ports(){
  echo "──────────────────────────────────────────"
  echo -e "${BOLD}${CYAN}🔎 当前 SSH 监听端口:${RESET}"
  ss -tunlp 2>/dev/null | grep ssh || echo "  ⚠ 未检测到 SSH 监听进程"
}

check_status(){
  # 宽容处理：检测分支不触发退出
  local ACTIVE ALLOW PERMIT MODE0 v
  echo -e "${BOLD}${CYAN}🧠 SSH 转发检测报告${RESET}"
  echo "──────────────────────────────────────────"
  if systemctl is-active --quiet sshd 2>/dev/null; then ACTIVE="active"; else ACTIVE="inactive"; fi
  ALLOW=$(sshd -T 2>/dev/null | awk '/^allowtcpforwarding/{print $2}')
  PERMIT=$(grep -iE '^[[:space:]]*PermitTunnel' "$CONFIG" 2>/dev/null | tail -n1 | awk '{print $2}')
  [ -z "${PERMIT:-}" ] && PERMIT="未定义"
  MODE0=$(getenforce 2>/dev/null || echo "未知")

  echo "✔ SSH 服务: ${ACTIVE}"
  echo "✔ AllowTcpForwarding: ${ALLOW:-未知}"
  echo "✔ PermitTunnel: ${PERMIT}"
  echo "✔ SELinux 模式: ${MODE0}"
  echo "──────────────────────────────────────────"
  echo "SELinux 布尔项状态:"
  for k in ssh_use_tcpd ssh_sysadm_login allow_user_tcp_forwarding; do
    if semanage boolean -l 2>/dev/null | grep -q "^$k"; then
      v=$(getsebool "$k" 2>/dev/null | awk '{print $3}')
      case "$v" in on) echo "  🟩 $k: on";; off) echo "  🟥 $k: off";; *) echo "  ⚪ $k: 未知";; esac
    else
      echo "  ⚪ $k: 策略未定义"
    fi
  done

  # JSON 基本字段
  jset "ssh_active" "${ACTIVE}"
  jset "allowtcpforwarding" "${ALLOW:-unknown}"
  jset "permittunnel" "${PERMIT}"
  jset "selinux_mode" "${MODE0}"

  show_ssh_ports
}

# ---------- SELinux 配置（核心=保证转发成功） ----------
setup_selinux_booleans(){
  local MODE0 MODE1 choose act val ans
  echo -e "${BOLD}${CYAN}🔐 SELinux 环境检测${RESET}"
  MODE0=$(getenforce 2>/dev/null || echo "未知")
  echo -e "当前 SELinux 模式: ${YELLOW}${MODE0}${RESET}"
  jset "selinux_mode_before" "$MODE0"

  if [[ "$MODE0" == "Permissive" ]]; then
    echo "✅ 已满足核心目标（不会拦截转发）。可选：[1] Enforcing  [2] Permissive(推荐)  [3] Disabled"
    choose=$(prompt_with_timeout "选择(回车保持当前) [默认=保持]: " "" 5)
    case "${choose:-}" in
      1) setenforce 1 2>/dev/null && report "SELinux: Permissive → Enforcing（用户选择）" ;;
      2|"") : ;; # 保持
      3) sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config 2>/dev/null && report "SELinux: 写入 Disabled（重启生效）" ;;
      *) echo -e "${YELLOW}⏭ 无效输入，保持当前 Permissive。${RESET}" ;;
    esac
  else
    echo -e "${YELLOW}⚠ 当前不是 Permissive，推荐切换为 Permissive 以确保转发成功。${RESET}"
    choose=$(prompt_with_timeout "切换为 Permissive？(Y/n)[默认Y，5秒自动]: " "Y" 5)
    if [[ "$choose" =~ ^[Yy]$ ]]; then
      if setenforce 0 2>/dev/null; then
        echo "✅ 已切换为 Permissive"; report "SELinux: 切换为 Permissive（推荐）"
      else
        echo "❌ 切换失败，请检查 SELinux/权限"; report "SELinux: 切换 Permissive 失败"
      fi
    else
      echo -e "${YELLOW}⚠ 保持 ${MODE0} 可能影响转发。${RESET}"
      report "SELinux: 保持 ${MODE0}（用户选择，非推荐）"
    fi
  fi

  MODE1=$(getenforce 2>/dev/null || echo "未知")
  jset "selinux_mode_after" "$MODE1"
  echo

  echo -e "${BOLD}${CYAN}🧩 配置 SSH 相关 SELinux 布尔项（遵循『转发成功』）：${RESET}"
  for key in ssh_use_tcpd ssh_sysadm_login allow_user_tcp_forwarding; do
    if ! semanage boolean -l 2>/dev/null | grep -q "^$key"; then
      echo -e "  ⚪ ${key}: 未定义 — 推荐=跳过（不影响转发）"
      if $SILENT_AUTO; then
        report "${key}: 未定义 → 按推荐跳过"; jadd_bool "$key" "undefined" "skipped(recommended)"
        continue
      fi
      echo -e "     选项: [1] 跳过(推荐)  [2] 尝试创建并启用(实验)  [3] 忽略"
      act=$(prompt_with_timeout "  你的选择 [默认=1，5秒自动]: " "1" 5)
      case "$act" in
        1|"") echo "  👍 已按推荐保留现状"; report "${key}: 未定义 → 按推荐跳过"; jadd_bool "$key" "undefined" "skipped(recommended)";;
        2)
          echo "  尝试创建策略模块并开启..."
          if define_boolean_policy "$key" && setsebool -P "$key" on 2>/dev/null; then
            echo "  ✅ 已创建并开启 ${key}"
            report "${key}: 未定义 → 创建并启用(实验)"; jadd_bool "$key" "created" "enabled(experimental)"
          else
            echo "  ❌ 创建/开启失败，建议保留现状。"
            report "${key}: 未定义 → 创建失败，保留现状"; jadd_bool "$key" "undefined" "create_failed"
          fi
          ;;
        3) echo "  ⏭ 忽略，继续"; report "${key}: 未定义 → 用户忽略"; jadd_bool "$key" "undefined" "ignored";;
        *) echo "  ⏳ 无效输入，按推荐跳过"; report "${key}: 未定义 → 无效输入，按推荐跳过"; jadd_bool "$key" "undefined" "skipped(recommended)";;
      esac
      continue
    fi

    val=$(getsebool "$key" 2>/dev/null | awk '{print $3}')
    if [[ "$val" == "on" ]]; then
      echo -e "  🟩 ${key}: on（已满足，5秒后继续）"
      $SILENT_AUTO || sleep 5
      report "${key}: 已是 on（推荐）"; jadd_bool "$key" "on" "kept"
    else
      if $SILENT_AUTO; then
        if setsebool -P "$key" on 2>/dev/null; then
          echo "  ✅ ${key}: off → on（自动）"
          report "${key}: off → on（自动推荐）"; jadd_bool "$key" "on" "enabled(auto)"
        else
          echo "  ❌ ${key}: 自动开启失败"
          report "${key}: 开启失败(自动)"; jadd_bool "$key" "off" "enable_failed"
        fi
      else
        ans=$(prompt_with_timeout "  ${key} 当前 off，是否开启？(Y/n) [默认Y，5秒自动]: " "Y" 5)
        if [[ "$ans" =~ ^[Yy]$ ]]; then
          if setsebool -P "$key" on 2>/dev/null; then
            echo "  ✅ 已开启 $key"; report "${key}: off → on（推荐）"; jadd_bool "$key" "on" "enabled"
          else
            echo "  ❌ 开启失败"; report "${key}: off → on 失败"; jadd_bool "$key" "off" "enable_failed"
          fi
        else
          echo -e "  ⚠ 保持 off（不推荐）"
          report "${key}: 保持 off（用户选择）"; jadd_bool "$key" "off" "kept(user)"
        fi
      fi
    fi
  done
  echo -e "${GREEN}🎯 SELinux 布尔项配置完成。${RESET}\n"
}

# ---------- 网卡选择 ----------
select_interface(){
  if $SILENT_AUTO; then
    SEL_IFACE="$(pick_default_interface)"
    echo -e "✅ 已自动选择出口网卡: ${BOLD}${SEL_IFACE}${RESET}"
    report "选择出口网卡(自动): $SEL_IFACE"; jset "iface" "$SEL_IFACE"
    return
  fi

  echo -e "🧭 ${BOLD}网卡列表（${GREEN}绿色=UP${RESET}, ${YELLOW}黄色=未连接${RESET}）：${RESET}"
  mapfile -t ifs < <(ip -o link show | awk -F': ' '{print $2}')
  local idx=0
  for i in "${ifs[@]}"; do
    local state carrier ip virt color="$YELLOW" status="未连接"
    state=$(cat /sys/class/net/$i/operstate 2>/dev/null || echo down)
    [ -r "/sys/class/net/$i/carrier" ] && carrier=$(cat /sys/class/net/$i/carrier 2>/dev/null || echo 0)
    ip=$(ip -4 addr show dev "$i" | awk '/inet /{print $2}' | paste -sd',' -)
    [ -z "$ip" ] && ip="无IP"
    is_virtual_iface "$i" && virt="·虚拟" || virt=""
    if [[ "$state" == "up" || "$carrier" == "1" ]]; then color="$GREEN"; status="UP"; fi
    echo -e "  [${idx}] ${color}${i}${RESET} (${status}/${state}${virt}) — ${ip}"
    ((idx++))
  done
  echo
  read -p "请选择用作主出口的网卡编号: " sel
  SEL_IFACE=${ifs[$sel]}
  if [ -z "${SEL_IFACE:-}" ]; then echo -e "${RED}⚠ 无效选择，退出。${RESET}"; exit 1; fi
  echo -e "✅ 已选择出口网卡: ${BOLD}${SEL_IFACE}${RESET}"
  report "选择出口网卡: $SEL_IFACE"; jset "iface" "$SEL_IFACE"
}

# ---------- 模式选择（交互版） ----------
select_mode(){
  [[ -n "${MODE:-}" ]] && return
  echo -e "${BOLD}${CYAN}请选择运行模式:${RESET}"
  echo -e "  [${GREEN}1${RESET}] auto-fix    — 一键自动修复 SSH 动态转发"
  echo -e "  [${GREEN}2${RESET}] manual-fix  — 手动确认修复每一项"
  echo -e "  [${YELLOW}3${RESET}] disable     — 停用所有转发功能"
  echo -e "  [${CYAN}4${RESET}] restore     — 从备份恢复原配置"
  read -p "请输入模式编号 [1-4]: " choice
  case "$choice" in
    1) MODE="auto-fix";;
    2) MODE="manual-fix";;
    3) MODE="disable";;
    4) MODE="restore";;
    *) echo -e "${RED}❌ 输入无效，退出。${RESET}"; exit 1;;
  esac
}

# ================= 主程序 =================
need_root
jset "version" "6.3"
jset "log_file" "$LOG_FILE"

if [[ "${MODE:-}" == "check-only" ]]; then
  check_status
  $JSON_OUT && _emit_json
  exit 0
fi

backup_config
setup_selinux_booleans
select_interface
select_mode
echo

case "$MODE" in
  auto-fix)
    fix_ssh_forwarding
    restart_sshd
    report "执行模式: auto-fix 完成"
    jset "mode" "auto-fix"
    ;;
  manual-fix)
    echo -e "${CYAN}🧭 手动修复模式${RESET}"
    ALLOW=$(sshd -T 2>/dev/null | awk '/^allowtcpforwarding/{print $2}')
    SELMODE=$(getenforce 2>/dev/null || echo unknown)
    echo -e "🔹 AllowTcpForwarding: ${ALLOW:-unknown}"
    echo -e "🔹 SELinux 模式: ${SELMODE}"
    echo "----------------------------------------"
    if [[ "${ALLOW:-no}" != "yes" ]]; then
      echo -e "${YELLOW}⚠ AllowTcpForwarding 未启用。${RESET}"
      confirm && fix_ssh_forwarding
    else
      echo "✅ AllowTcpForwarding 正常。"
    fi
    restart_sshd
    echo -e "${GREEN}🟢 手动修复完成。${RESET}"
    report "执行模式: manual-fix 完成"
    jset "mode" "manual-fix"
    ;;
  disable)
    disable_forwarding
    restart_sshd
    echo -e "${YELLOW}🔒 已停用所有 SSH 转发功能。${RESET}"
    report "执行模式: disable 完成"
    jset "mode" "disable"
    ;;
  restore)
    restore_backup
    report "执行模式: restore 完成"
    jset "mode" "restore"
    ;;
  *)
    # 若传了 --silent-auto，MODE 已设为 auto-fix；该分支仅容错
    if $SILENT_AUTO; then
      MODE="auto-fix"
      fix_ssh_forwarding
      restart_sshd
      report "执行模式: auto-fix 完成（silent）"
      jset "mode" "auto-fix(silent)"
    fi
    ;;
esac

show_ssh_ports

echo -e "\n──────────────────────────────────────────"
echo -e "🧾 本次操作总结:"
for line in "${OP_REPORT[@]}"; do echo "  • $line"; done
echo -e "📦 日志: $LOG_FILE"
echo -e "──────────────────────────────────────────"

$JSON_OUT && _emit_json
if [[ -n "${JSON_PATH:-}" ]]; then
  _emit_json > "$JSON_PATH"
  echo "📝 JSON 报告已保存: $JSON_PATH"
fi

# ble.sh 兼容的“友好退出”
exit 0

# #!/bin/bash
# # =========================================================
# # SSH Dynamic Forwarding Manager
# # 支持: Rocky / CentOS / openEuler / RHEL 系
# # 作者: ChatGPT (for wise user)
# # 模式:
# #   auto-fix    自动检测并修复所有问题
# #   manual-fix  每一步手动确认修复
# #   disable     禁用所有端口转发功能
# #   restore     从备份恢复原始配置
# # =========================================================
# 
# CONFIG="/etc/ssh/sshd_config"
# BACKUP_DIR="/etc/ssh/backup"
# mkdir -p "$BACKUP_DIR"
# BACKUP_FILE="$BACKUP_DIR/sshd_config.bak.$(date +%Y%m%d-%H%M%S)"
# 
# # ---------- 工具函数 ----------
# confirm() {
#     read -p "是否修复此项？(y/n): " ans
#     [[ "$ans" =~ ^[Yy]$ ]]
# }
# 
# backup_config() {
#     if [ ! -f "$BACKUP_FILE" ]; then
#         cp "$CONFIG" "$BACKUP_FILE"
#         echo "🗂️ 已备份 SSH 配置到: $BACKUP_FILE"
#     fi
# }
# 
# restart_sshd() {
#     echo "🔄 重启 sshd 服务..."
#     systemctl restart sshd
# }
# 
# fix_ssh_forwarding() {
#     echo "⚙️ 启用 AllowTcpForwarding..."
#     sed -i '/^#\?AllowTcpForwarding/d' "$CONFIG"
#     sed -i '/^#\?PermitTunnel/d' "$CONFIG"
#     echo -e "\nAllowTcpForwarding yes\nPermitTunnel yes" >> "$CONFIG"
# }
# 
# fix_selinux() {
#     echo "⚙️ 启用 SELinux 布尔项..."
#     setsebool -P ssh_use_tcpd on 2>/dev/null || true
#     setsebool -P ssh_sysadm_login on 2>/dev/null || true
#     setsebool -P allow_user_tcp_forwarding on 2>/dev/null || true
# }
# 
# disable_forwarding() {
#     echo "🚫 禁用端口转发..."
#     sed -i '/AllowTcpForwarding/d' "$CONFIG"
#     sed -i '/PermitTunnel/d' "$CONFIG"
#     echo -e "AllowTcpForwarding no\nPermitTunnel no" >> "$CONFIG"
#     setsebool -P ssh_use_tcpd off 2>/dev/null || true
#     setsebool -P allow_user_tcp_forwarding off 2>/dev/null || true
# }
# 
# restore_backup() {
#     echo "🔁 可用备份文件列表："
#     ls -1t "$BACKUP_DIR"/sshd_config.bak.* 2>/dev/null || { echo "❌ 未找到备份文件"; exit 1; }
#     read -p "请输入要恢复的备份文件路径: " restore_file
#     if [ -f "$restore_file" ]; then
#         cp "$restore_file" "$CONFIG"
#         echo "✅ 已恢复配置: $restore_file"
#         restart_sshd
#     else
#         echo "❌ 文件不存在"
#         exit 1
#     fi
# }
# 
# # ---------- 模式选择 ----------
# MODE="$1"
# if [ -z "$MODE" ]; then
#     echo "用法: $0 [auto-fix|manual-fix|disable|restore]"
#     exit 0
# fi
# 
# backup_config
# 
# case "$MODE" in
# # ---------------------------------------------------------
# auto-fix)
#     echo "🔧 启动自动修复模式..."
#     fix_ssh_forwarding
#     fix_selinux
#     restart_sshd
#     echo "🎉 自动修复完成，可重新测试 ssh -D 代理。"
#     ;;
# # ---------------------------------------------------------
# manual-fix)
#     echo "🧭 启动手动修复模式..."
#     echo "检测中..."
#     ALLOW=$(sshd -T | grep allowtcpforwarding | awk '{print $2}')
#     SELINUX=$(getenforce)
# 
#     echo "🔹 AllowTcpForwarding 状态: $ALLOW"
#     echo "🔹 SELinux 状态: $SELINUX"
#     echo "--------------------------------------------"
# 
#     if [ "$ALLOW" != "yes" ]; then
#         echo "⚠️ 检测到 AllowTcpForwarding 未启用。"
#         confirm && fix_ssh_forwarding
#     else
#         echo "✅ AllowTcpForwarding 正常。"
#     fi
# 
#     if [ "$SELINUX" = "Enforcing" ]; then
#         echo "⚠️ SELinux 正在强制模式，可能拦截转发。"
#         confirm && fix_selinux
#     else
#         echo "✅ SELinux 非强制模式。"
#     fi
# 
#     restart_sshd
#     echo "🟢 手动修复完成。"
#     ;;
# # ---------------------------------------------------------
# disable)
#     echo "🚫 启动停用模式..."
#     disable_forwarding
#     restart_sshd
#     echo "🔒 已彻底关闭端口转发功能。"
#     ;;
# # ---------------------------------------------------------
# restore)
#     echo "🔁 启动恢复模式..."
#     restore_backup
#     ;;
# # ---------------------------------------------------------
# *)
#     echo "❌ 无效模式: $MODE"
#     echo "可选模式: auto-fix | manual-fix | disable | restore"
#     exit 1
#     ;;
# esac
# 

SSH_EOF
chmod +x "$SSH_FILE"

banner(){ echo "======================================================================"; echo -e "  ${BOLD}${CYAN}🧠  openEuler 智能桥接 + VLAN 与 SSH 动态转发 / SELinux 配置向导${NC}"; echo "======================================================================"; }
subtitle(){ echo "----------------------------------------------------------------------"; echo -e "  ${BOLD}${CYAN}$*${NC}"; echo "----------------------------------------------------------------------"; }
detect_net_mode(){ if have nmcli && systemctl is-active --quiet NetworkManager; then echo "nm"; else echo "legacy"; fi }
get_selinux_mode(){ have getenforce && (getenforce 2>/dev/null || true) || echo "Disabled"; }

ssh_forwarding_enabled(){ local svc allow; systemctl is-active --quiet sshd 2>/dev/null && svc=active || svc=inactive; allow=$(sshd -T 2>/dev/null | awk '/^allowtcpforwarding/{print $2}'); [ "${allow:-no}" = "yes" ] && [ "$svc" = "active" ]; }
bridge_or_vlan_exists(){ ip link show type bridge >/dev/null 2>&1 && return 0; ip -d -o link show type vlan >/devnull 2>&1 && return 0; return 1; }
bridge_and_ssh_ready(){ bridge_or_vlan_exists && ssh_forwarding_enabled; }

vlan_overview_line(){ local cnt=0; if ip -d -o link show type vlan >/dev/null 2>&1; then cnt=$(ip -d -o link show type vlan | wc -l); elif have nmcli; then cnt=$(nmcli -t -f TYPE connection show 2>/dev/null | awk -F: '$1=="vlan"{c++}END{print c+0}'); fi; [ "$cnt" -eq 0 ] && echo "VLANs：0 VLANs (无)" || echo "VLANs：${cnt} VLANs"; }
build_iface_lines_block(){ local lines=""; while read -r idx name fam addr rest; do local ip_net gw; ip_net=$(echo "$addr" | awk '{print $1}'); gw=$(ip route show dev "$name" 2>/dev/null | awk '/^default /{for(i=1;i<=NF;i++){if($i=="via"){print $(i+1);exit}}}'); [ -z "$gw" ] && gw="—"; if [[ "$name" =~ ^(virbr|docker|tun|veth|br-|vlan|tap|wg) ]]; then lines+=$(printf "       ${DIM}UP：%-12s — %-20s   gateway: %-15s${NC}\n" "$name" "$ip_net" "$gw"); else lines+=$(printf "       ${GREEN}${BOLD}UP：%-12s — %-20s   gateway: %-15s${NC}\n" "$name" "$ip_net" "$gw"); fi; done < <(ip -o -4 addr show up 2>/dev/null); printf "%b" "$lines"; }

get_iface_driver(){ have ethtool && tcmd 2 ethtool -i "$1" | awk -F': ' '/driver:/{print $2}' || echo "-"; }
get_iface_pci(){ [ -e "/sys/class/net/$1/device" ] && basename "$(readlink -f /sys/class/net/$1/device 2>/dev/null)" 2>/dev/null || echo "-"; }
get_iface_speed(){ have ethtool && tcmd 2 ethtool "$1" | awk -F': ' '/Speed:/{print $2}' || echo "-"; }
get_iface_duplex(){ have ethtool && tcmd 2 ethtool "$1" | awk -F': ' '/Duplex:/{print $2}' || echo "-"; }
get_iface_operstate(){ [ -r "/sys/class/net/$1/operstate" ] && cat "/sys/class/net/$1/operstate" 2>/dev/null || echo "-"; }
get_iface_carrier(){ [ -r "/sys/class/net/$1/carrier" ] && (cat "/sys/class/net/$1/carrier" | awk '{print ($1==1?"up":"down")}') || echo "-"; }
get_iface_mtu(){ [ -r "/sys/class/net/$1/mtu" ] && cat "/sys/class/net/$1/mtu" 2>/dev/null || echo "-"; }
get_iface_mac(){ ip link show dev "$1" 2>/dev/null | awk '/link\//{print $2;exit}' || echo "-"; }
get_iface_ipv4(){ ip -4 addr show dev "$1" 2>/dev/null | awk '/inet /{print $2}' | paste -sd',' -; }
get_iface_ipv6(){ ip -6 addr show dev "$1" 2>/dev/null | awk '/inet6 /{print $2}' | paste -sd',' -; }
get_iface_gateway(){ ip route show dev "$1" 2>/dev/null | awk '/^default /{for(i=1;i<=NF;i++){if($i=="via"){print $(i+1);exit}}}'; }
check_gateway_ping(){ local gw="$1" dev="$2"; [ -z "$gw" ] && { echo "n/a"; return; }; tcmd 2 ping -c1 -W1 -I "$dev" "$gw" >/dev/null && echo "ok" || echo "fail"; }

print_iface_block_deep(){
  local dev="$1"
  local ip4 ip6 mac mtu op car spd dup drv pci gw gwok
  ip4="$(get_iface_ipv4 "$dev")"; [ -z "$ip4" ] && ip4="—"
  ip6="$(get_iface_ipv6 "$dev")"; [ -z "$ip6" ] && ip6="—"
  mac="$(get_iface_mac "$dev")"; mtu="$(get_iface_mtu "$dev")"
  op="$(get_iface_operstate "$dev")"; car="$(get_iface_carrier "$dev")"
  spd="$(get_iface_speed "$dev")"; dup="$(get_iface_duplex "$dev")"
  drv="$(get_iface_driver "$dev")"; pci="$(get_iface_pci "$dev")"
  gw="$(get_iface_gateway "$dev")"; [ -z "$gw" ] && gw="—"
  gwok="$(check_gateway_ping "${gw/—/}" "$dev")"

  local color_open=""; local color_close="${NC}"
  if [[ "$dev" =~ ^(virbr|docker|tun|veth|br-|vlan|tap|wg) ]]; then color_open="${DIM}"; else color_open="${GREEN}${BOLD}"; fi

  printf "  %s🔌 %-12s%s | 🚦state:%-5s 📶carrier:%-5s 🧱mtu:%-6s ⚡speed:%-8s 🔁duplex:%-6s\n" "$color_open" "$dev" "$color_close" "$op" "$car" "$mtu" "$spd" "$dup"
  printf "      🪪MAC: %-17s  🌐IPv4: %-30s  🧭IPv6: %s\n" "$mac" "$ip4" "$ip6"
  printf "      🛣 GW : %-15s  🔍连通性: %-4s  🧩驱动: %-10s  ♟ PCI: %s\n" "$gw" "$gwok" "$drv" "$pci"
}

print_vlan_block_deep(){
  echo -e "${BOLD}🏷️ VLAN 概览：${NC}"
  if ip -d -o link show type vlan >/dev/null 2>&1; then
    while read -r l; do
      local name parent tag ip4
      name=$(echo "$l" | awk -F': ' '{print $2}' | awk -F'@' '{print $1}')
      parent=$(echo "$l" | awk -F'@' '{print $2}' | awk -F: '{print $1}')
      tag=$(ip -d link show "$name" 2>/dev/null | awk '/vlan id/{print $3;exit}'); [ -z "$tag" ] && tag=0
      ip4=$(ip -4 addr show dev "$name" 2>/dev/null | awk '/inet /{print $2}' | paste -sd',' -); [ -z "$ip4" ] && ip4="无IP"
      printf "  • %-10s parent:%-10s tag:%-4s ip:%s\n" "$name" "$parent" "$tag" "$ip4"
    done < <(ip -d -o link show type vlan 2>/dev/null)
  else
    echo "  (无)"
  fi
}

print_routes_grouped(){
  echo -e "${BOLD}🗺️ 路由（按接口分组）：${NC}"
  for d in $(ls /sys/class/net); do
    local lines; lines="$(ip route show dev "$d" 2>/dev/null)"
    [ -z "$lines" ] && continue
    echo "  • $d"; echo "$lines" | sed 's/^/      /'
  done
  local def; def="$(ip route show default 2>/dev/null | sed 's/^/  default: /')"
  [ -n "$def" ] && echo "$def"
}

collect_ssh_info(){
  SSH_ALLOW=$(sshd -T 2>/dev/null | awk '/^allowtcpforwarding/{print $2}' || echo "no")
  SSH_PORTS_CONF=$(sshd -T 2>/dev/null | awk '/^port /{print $2}' | paste -sd',' -); [ -z "$SSH_PORTS_CONF" ] && SSH_PORTS_CONF="22"
  if systemctl is-active --quiet sshd 2>/dev/null; then SSH_SERVICE="active"; else SSH_SERVICE="inactive"; fi
}

ssh_brief_line(){
  local allow ports service
  allow=$(sshd -T 2>/dev/null | awk '/^allowtcpforwarding/{print $2}'); [ -z "$allow" ] && allow="no"
  ports=$(sshd -T 2>/dev/null | awk '/^port /{print $2}' | paste -sd',' -); [ -z "$ports" ] && ports="22"
  if systemctl is-active --quiet sshd 2>/dev/null; then service="active"; else service="inactive"; fi
  [ "$allow" = "yes" ] && echo "已配置：TCP 转发启用（Port ${ports}, service ${service}）" || echo "未配置：未启用 TCP 转发（Port ${ports}, service ${service}）"
}

do_check_bridge_deep(){
  subtitle "🧪 Bridge 全面检测（深度）"
  local start=$(date +%s)
  for dev in $(ip -o -4 addr show up | awk '{print $2}' | sort -u); do
    print_iface_block_deep "$dev"
  done
  echo; print_vlan_block_deep; echo; print_routes_grouped; echo
  local end=$(date +%s); echo -e "${DIM}（检测完成，用时 $((end-start)) 秒）${NC}"
}

do_check_ssh_deep(){
  subtitle "🧪 SSH 全面检测（深度）"
  local start=$(date +%s)
  collect_ssh_info
  echo -e "  🔍 服务：${SSH_SERVICE}  🔒 AllowTcpForwarding=${SSH_ALLOW}  🔌 端口(配置)：${SSH_PORTS_CONF}"
  local end=$(date +%s); echo -e "${DIM}（检测完成，用时 $((end-start)) 秒）${NC}"
}

submenu_bridge(){
  clear; subtitle "🌐 Bridge + VLAN 配置子菜单"
  if have nmcli && systemctl is-active --quiet NetworkManager; then
    echo -e "🌐 检测到 ${BOLD}NetworkManager 独占${NC}"
  else
    echo -e "🌐 检测到 ${BOLD}Legacy 网络${NC}"
  fi
  echo -e "\n${BOLD}当前接口状态：${NC}\n"
  while read -r idx name fam addr rest; do
    ip_net=$(echo "$addr" | awk '{print $1}')
    gw=$(ip route show dev "$name" 2>/dev/null | awk '/^default /{for(i=1;i<=NF;i++){if($i=="via"){print $(i+1);exit}}}'); [ -z "$gw" ] && gw="—"
    if [[ "$name" =~ ^(virbr|docker|tun|veth|br-|vlan|tap|wg) ]]; then
      printf "  ${DIM}UP：%-12s — %-20s   gateway: %-15s${NC}\n" "$name" "$ip_net" "$gw"
    else
      printf "  ${GREEN}${BOLD}UP：%-12s — %-20s   gateway: %-15s${NC}\n" "$name" "$ip_net" "$gw"
    fi
  done < <(ip -o -4 addr show up 2>/dev/null)
  echo "  $(vlan_overview_line)"
  echo
  echo "  [1] 自动配置"
  echo "  [2] 手动配置"
  echo "  [3] 返回上一级"
  echo "  [4] 重建模块"
  echo

  if bridge_and_ssh_ready; then
    echo -e "${CYAN}🧩 检测到 Bridge/VLAN 与 SSH 转发均已启用，将在 10 秒后自动进入综合深度检测...${NC}"
    for ((i=10;i>0;i--)); do printf "\r⏱ %2ds 后开始检测..." "$i"; sleep 1; done
    echo
    do_check_bridge_deep
    do_check_ssh_deep
    return
  else
    if ip -d -o link show type vlan >/dev/null 2>&1 || ip link show type bridge >/dev/null 2>&1 || ssh_forwarding_enabled; then
      warn "当前仅检测到其中之一（Bridge/VLAN 或 SSH 转发）。请手动选择操作。"
    else
      warn "未检测到 Bridge/VLAN 或 SSH 转发配置。请手动选择操作。"
    fi
  fi

  read -rp "请选择 [1-4]: " K
  case "$K" in
    1) "$SB_FILE" auto   || "$SB_FILE";;
    2) "$SB_FILE" manual || "$SB_FILE";;
    3) return ;;
    4) if "$SB_FILE" rebuild all 2>/dev/null; then :; else warn "当前 smart-bridge 不支持重建 all，已跳过。"; fi ;;
    *) warn "无效输入";;
  esac
}

submenu_ssh(){
  clear; subtitle "🔐 SSH 动态转发与管理子菜单"
  local brief="$(ssh_brief_line)"
  echo "当前状态：${brief}"
  echo
  echo "  [1] 自动配置（启用 AllowTcpForwarding 等推荐项）"
  echo "  [2] 手动配置（逐项设置）"
  echo "  [3] 返回上一级"
  echo
  read -rp "请选择 [1-3]: " K
  case "$K" in
    1) "$SSH_FILE" auto || "$SSH_FILE" ;;
    2) "$SSH_FILE" manual || "$SSH_FILE" ;;
    3) ;;
    *) warn "无效输入";;
  esac
}

submenu_check(){
  clear; subtitle "🧪 检查模式子菜单（深度）"
  echo "  [1] Bridge 全面检测（单项/深度）"
  echo "  [2] SSH 全面检测（单项/深度）"
  echo "  [3] Bridge + SSH 全面检测（综合/深度）"
  echo "  [4] 输出 JSON 报告（直接生成并保存）"
  echo "  [5] 返回上一级"
  echo
  read -rp "请选择 [1-5]: " K
  case "$K" in
    1) do_check_bridge_deep ;;
    2) do_check_ssh_deep ;;
    3) do_check_bridge_deep ; do_check_ssh_deep ;;
    4) out="${REPORT_DIR}/net-ssh-report-$(now_ts).json"; echo "{}" > "$out"; ok "JSON 报告占位已生成：$out" ;;
    5) ;;
    *) warn "无效输入";;
  esac
  echo -e "${DIM}（按任意键返回上级菜单）${NC}"; read -rsn1 -t 0.1 _ || true; read -rsn1 -p "" _ || true
}

submenu_selinux(){
  clear; subtitle "🔐 SELinux 模式修改"
  local CUR="$(get_selinux_mode)"
  echo "当前模式：${CUR}（推荐：Permissive）"
  echo
  echo "  [1] Enforcing"
  echo "  [2] Permissive (推荐)"
  echo "  [3] Disabled"
  echo "  [4] 返回上一级"
  echo
  if [[ "$CUR" == "Permissive" ]]; then
    for ((i=10;i>0;i--)); do printf "\r⏱ %2ds 后自动返回上一级..." "$i"; sleep 1; done
    echo; return 0
  fi
  read -rp "请选择模式 [1-4]: " SEL
  case "$SEL" in
    1) have setenforce && setenforce 1 || warn "无法切到 Enforcing" ;;
    2) have setenforce && setenforce 0 || warn "无法切到 Permissive" ;;
    3) warn "运行时无法直接设为 Disabled；需改 /etc/selinux/config 并重启。" ;;
    4) ;;
    *) warn "无效输入";;
  esac
}

main_menu(){
  clear; banner
  local NET_MODE="$(detect_net_mode)"
  local SE_MODE="$(get_selinux_mode)"
  if [ "$NET_MODE" = "nm" ]; then
    echo -e "🌐 网络管理由 ${BOLD}NetworkManager${NC} 独占。"
  else
    echo -e "🌐 当前为 ${BOLD}Legacy${NC} 网络模式。"
  fi
  echo -e "🔐 当前 SELinux 模式：${BOLD}${SE_MODE}${NC}（推荐：Permissive）"
  echo
  local IFBLOCK; IFBLOCK="$(build_iface_lines_block)"
  local VLLINE; VLLINE="$(vlan_overview_line)"
  echo "  📘 [1] SELinux 模式修改"
  echo -e "  📘 [2] Bridge + VLAN 配置（已配置接口：\n${IFBLOCK}       ${VLLINE}）"
  echo "  📘 [3] SSH 动态转发与管理（$(ssh_brief_line)）"
  echo "  📘 [4] 检查模式（Bridge + SSH 全面检测）"
  echo "  📘 [5] 卸载 / 恢复"
  echo
  read -rp "👉 请输入选项 [1-5]: " CH
  case "$CH" in
    1) submenu_selinux ;;
    2) submenu_bridge ;;
    3) submenu_ssh ;;
    4) submenu_check ;;
    5) echo "（占位）";;
    *) warn "无效输入";;
  esac
}

while true; do
  main_menu
done
