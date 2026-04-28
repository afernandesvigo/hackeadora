#!/usr/bin/env bash
# mcp/status.sh — Estado y gestión de MCP servers
MCP_SERVERS=(filesystem github playwright telegram nvd)
MCP_PORTS=(3001 3002 3003 3004 3005)

CMD="${1:-status}"

case "$CMD" in
  status)
    echo "═══════════════════════════════════════════"
    echo "  Hackeadora MCP Servers"
    echo "═══════════════════════════════════════════"
    for i in "${!MCP_SERVERS[@]}"; do
      SRV="${MCP_SERVERS[$i]}"
      PORT="${MCP_PORTS[$i]}"
      STATUS=$(systemctl is-active "hackeadora-mcp-${SRV}" 2>/dev/null || echo "inactive")
      COLOR="\033[0;32m"; [[ "$STATUS" != "active" ]] && COLOR="\033[0;31m"
      echo -e "  ${COLOR}● ${STATUS}\033[0m  hackeadora-mcp-${SRV}"
    done
    echo ""
    ;;
  start)
    for SRV in "${MCP_SERVERS[@]}"; do
      sudo systemctl start "hackeadora-mcp-${SRV}" && \
        echo "✓ Arrancado: hackeadora-mcp-${SRV}"
    done
    ;;
  stop)
    for SRV in "${MCP_SERVERS[@]}"; do
      sudo systemctl stop "hackeadora-mcp-${SRV}" && \
        echo "✓ Detenido: hackeadora-mcp-${SRV}"
    done
    ;;
  restart)
    for SRV in "${MCP_SERVERS[@]}"; do
      sudo systemctl restart "hackeadora-mcp-${SRV}" && \
        echo "✓ Reiniciado: hackeadora-mcp-${SRV}"
    done
    ;;
  logs)
    SRV="${2:-filesystem}"
    journalctl -u "hackeadora-mcp-${SRV}" -f --no-pager
    ;;
  *)
    echo "Uso: $0 [status|start|stop|restart|logs <servidor>]"
    ;;
esac
