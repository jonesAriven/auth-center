#!/usr/bin/env bash
# ============================================================
# deploy.sh — auth-center 独立部署脚本（在 mykng 服务器上执行）
# ============================================================
# 触发方式：由 auth-center 仓库自带的 Woodpecker 流水线调用，不要手工 SSH 跑（铁律：部署走流水线）
#   CI build  -> mvn package，产物打成 auth-center-latest.tar.gz 推到 /mnt/shared/woodScript/publish/
#   CI deploy -> 解压到 /mnt/shared/auth-center-build/ 后执行本脚本
#
# 产物内容：auth-center.jar、Dockerfile、deploy.sh（自包含，服务器无需 git clone / 无需 mvn）
#
# 为什么自包含而不 source /mnt/shared/woodScript/lib-deploy.sh：
#   auth-center 是 12 个应用的 SSO 枢纽，部署链路越短越好排查。
#   lib-deploy.sh 由 devtools 流水线同步，缺了会导致枢纽部署失败——不值得为复用几行逻辑引入这个依赖。
#
# 退出码：0 成功；非 0 失败（Woodpecker 会标红）
# ============================================================
set -euo pipefail

# ====== 配置 ======
BUILD_DIR="/mnt/shared/auth-center-build"
COMPOSE_FILE="/mnt/shared/mykng/docker/docker-compose.app.yml"
COMPOSE_PROJECT="kb-app"
SERVICE="auth-center"
CONTAINER="auth-center"
HEALTH_URL="http://localhost:8085/actuator/health"
HEALTH_MAX_RETRIES=60      # 60 × 10s = 最多等 10 分钟
HEALTH_INTERVAL=10

log() { echo "[$(date '+%H:%M:%S')] $*"; }
die() { echo ""; echo "❌ $*"; echo "--- 最近 80 行容器日志 ---"; docker logs --tail 80 "${CONTAINER}" 2>&1 || true; exit 1; }

log "=========================================="
log " auth-center 部署开始"
log " 构建上下文: ${BUILD_DIR}"
log " Compose   : ${COMPOSE_FILE} (project ${COMPOSE_PROJECT})"
log "=========================================="

# ====== Step 1: 校验产物 ======
log "[1/5] 校验产物"
[ -f "${BUILD_DIR}/auth-center.jar" ] || die "缺少 ${BUILD_DIR}/auth-center.jar（CI 产物未正确解压）"
[ -f "${BUILD_DIR}/Dockerfile" ]       || die "缺少 ${BUILD_DIR}/Dockerfile（CI 产物未正确解压）"
[ -f "${COMPOSE_FILE}" ]               || die "缺少 compose 文件 ${COMPOSE_FILE}（由 devtools 流水线同步）"
JAR_SIZE=$(du -h "${BUILD_DIR}/auth-center.jar" | cut -f1)
log "  OK auth-center.jar (${JAR_SIZE}) + Dockerfile"

# ====== Step 2: 清理 legacy 容器 ======
# 旧 kb-auth 服务下线后仍占用 8085，必须清理，否则端口冲突导致新容器起不来。幂等。
log "[2/5] 清理 legacy kb-auth 容器（幂等）"
docker stop kb-auth 2>/dev/null && log "  已停止 kb-auth" || log "  无 kb-auth 容器，跳过"
docker rm kb-auth 2>/dev/null && log "  已移除 kb-auth" || true

# ====== Step 3: 重建容器 ======
log "[3/5] 重建容器（--build 重新打镜像，--force-recreate 强制替换，--no-deps 不影响其他服务）"
docker compose -p "${COMPOSE_PROJECT}" -f "${COMPOSE_FILE}" up -d \
  --build --force-recreate --no-deps "${SERVICE}" 2>&1 | tail -20 \
  || die "docker compose up 失败"

# ====== Step 4: 健康检查 ======
# 这里是本脚本相对旧流程的关键改进：以前 deploy-mykng.sh 的 health_check 只探 4 个 mykng 服务，
# 不含 auth-center（台账 L042），枢纽重启后坏了流水线也不会拦。这里单独探 8085。
log "[4/5] 健康检查 ${HEALTH_URL}（最多 ${HEALTH_MAX_RETRIES} 次 × ${HEALTH_INTERVAL}s）"
i=1
while [ $i -le $HEALTH_MAX_RETRIES ]; do
  # 容器必须先处于 running，避免 health 端点还没监听就判失败
  STATUS=$(docker inspect -f '{{.State.Status}}' "${CONTAINER}" 2>/dev/null || echo "missing")
  if [ "${STATUS}" = "exited" ] || [ "${STATUS}" = "dead" ]; then
    die "容器状态异常: ${STATUS}（启动即退出，通常是配置/依赖错误）"
  fi
  CODE=$(curl -s -o /dev/null -m 5 -w '%{http_code}' "${HEALTH_URL}" || echo "000")
  if [ "${CODE}" = "200" ]; then
    log "  ✅ 健康检查通过 (${i}/${HEALTH_MAX_RETRIES})"
    break
  fi
  log "  ⏳ [${i}/${HEALTH_MAX_RETRIES}] 未就绪 HTTP=${CODE} container=${STATUS}"
  i=$((i + 1))
  [ $i -le $HEALTH_MAX_RETRIES ] && sleep $HEALTH_INTERVAL
done

if [ $i -gt $HEALTH_MAX_RETRIES ]; then
  die "健康检查超时（${HEALTH_MAX_RETRIES} 次未通过）"
fi

# ====== Step 5: 汇总 ======
log "[5/5] 部署完成"
docker ps --filter "name=${CONTAINER}" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
log "=========================================="
log " ✅ auth-center 部署成功"
log "   Health : ${HEALTH_URL}"
log "   OIDC   : $(curl -s -o /dev/null -w '%{http_code}' http://localhost:8085/.well-known/openid-configuration) (/.well-known/openid-configuration)"
log "=========================================="
