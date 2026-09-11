#!/usr/bin/env bash
# ============================================================
# deploy.sh — auth-center 独立部署脚本（在 mykng 服务器上执行）
# ============================================================
# 触发方式：由 auth-center 仓库自带的 Woodpecker 流水线调用，不要手工 SSH 跑（铁律：部署走流水线）
#   CI build  -> mvn package，产物直写 /mnt/shared/auth-center-build/（不打包 tar.gz，见下）
#   CI deploy -> SSH 到 mykng 执行 /mnt/shared/auth-center-build/deploy.sh
#
# 产物布局（★ 关键）：target/auth-center.jar + Dockerfile + deploy.sh
#   build context = /mnt/shared/auth-center-build，仓库 Dockerfile 写的是
#   `COPY target/auth-center.jar`，所以 jar 必须落在 target/ 子目录，否则镜像构建失败。
#
# 自包含，服务器无需 git clone / 无需 mvn。
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
# ★ 校验的是 target/auth-center.jar（不是根目录的 auth-center.jar）：Dockerfile 的 COPY 路径即此。
log "[1/5] 校验产物"
JAR="${BUILD_DIR}/target/auth-center.jar"
[ -f "${JAR}" ]                        || die "缺少 ${JAR}（CI 产物未正确落盘）"
[ -f "${BUILD_DIR}/Dockerfile" ]       || die "缺少 ${BUILD_DIR}/Dockerfile（CI 产物未正确落盘）"
[ -f "${COMPOSE_FILE}" ]               || die "缺少 compose 文件 ${COMPOSE_FILE}（由 devtools 流水线 sync-ci-scripts 同步）"
JAR_SIZE=$(du -h "${JAR}" | cut -f1)
JAR_MD5=$(md5sum "${JAR}" | cut -d' ' -f1)
log "  OK target/auth-center.jar (${JAR_SIZE}) md5=${JAR_MD5} + Dockerfile"

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

# ====== Step 5: 产物一致性 + 关键页面探针 ======
# ★ 反「假成功」硬门禁。2026-09-11 流水线 #5 曾报 success，实际容器跑的是旧 jar：
#   compose 的 build context 还指着 /root/auth-center（旧克隆），CI 产物被完全忽略，
#   健康检查照样 200 —— 只看 health 根本发现不了。这里用 md5 把「CI 产物 == 容器内 jar」钉死。
log "[5/5] 产物一致性校验（CI jar md5 == 容器内 /app/auth-center.jar md5）"
RUN_MD5=$(docker exec "${CONTAINER}" md5sum /app/auth-center.jar 2>/dev/null | cut -d' ' -f1 || echo "unknown")
if [ -n "${JAR_MD5}" ] && [ "${JAR_MD5}" = "${RUN_MD5}" ]; then
  log "  ✅ 一致 md5=${RUN_MD5}"
else
  die "容器内 jar 与 CI 产物不一致（CI=${JAR_MD5:-?} 容器=${RUN_MD5}）—— 多半是 compose 的 build context 没指向 ${BUILD_DIR}"
fi

# 品牌登录页探针：SecurityConfig.loginPage = /login.html，一旦 404，整条 SSO 授权码流程会在登录页断链。
LOGIN_CODE=$(curl -s -o /dev/null -m 5 -w '%{http_code}' "http://localhost:8085/login.html" || echo "000")
if [ "${LOGIN_CODE}" = "200" ]; then
  log "  ✅ /login.html HTTP 200"
else
  die "/login.html 不可达 HTTP=${LOGIN_CODE}（品牌登录页缺失会导致 SSO 登录断链）"
fi

log "[5/5] 部署完成"
docker ps --filter "name=${CONTAINER}" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
log "=========================================="
log " ✅ auth-center 部署成功"
log "   Health : ${HEALTH_URL}"
log "   OIDC   : $(curl -s -o /dev/null -w '%{http_code}' http://localhost:8085/.well-known/openid-configuration) (/.well-known/openid-configuration)"
log "=========================================="
