#!/bin/bash
# =============================================================================
# Nacos v2.2.3-bzz 发行包构建脚本
#
# 用法:
#   bash build-release.sh          # 使用 mvnd（默认，mise.toml 约束 0.8.2）
#   bash build-release.sh mvn      # 使用 mvn （mise.toml 约束 3.6.3）
#   bash build-release.sh mvnd     # 同默认
#
# 设计原则:
#   1. 严格使用官方 BUILDING 文档的全量 reactor 命令，不加 -pl/-am。
#      -pl xxx -am 会改变 Maven 对上游 POM 的解析路径，与 easyj-maven-plugin
#      替换 .flattened-pom.xml 叠加后打乱 protobuf-maven-plugin 执行时序，
#      导致 nacos-consistency / nacos-istio jar 丢失 grpc 生成类（随机触发）。
#   2. 强制使用 mise.toml 约束的 JDK 8，非 JDK 8 直接退出。
#   3. 构建后自动校验产物完整性，任一项失败即以非 0 退出，产物不可部署。
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

MODE="${1:-mvnd}"

# ---------------------------- 1. 环境 --------------------------------------
if ! command -v mise >/dev/null 2>&1; then
  echo "ERROR: 未安装 mise (https://mise.jv.dev)，无法保证 JDK/Maven 版本一致"; exit 1
fi
export JAVA_HOME="$(mise where java 2>/dev/null)"
export PATH="$JAVA_HOME/bin:$PATH"

JAVA_LINE="$(java -version 2>&1 | head -1)"
echo "==> $JAVA_LINE"
case "$JAVA_LINE" in *'"1.8.'*) ;; *)
  echo "ERROR: 必须使用 JDK 8 构建，当前: $JAVA_LINE"; exit 1;;
esac

case "$MODE" in
  mvnd)
    MVND_HOME="$(mise where mvnd 2>/dev/null || true)"
    [ -z "$MVND_HOME" ] && { echo "ERROR: mise 未解析到 mvnd，请确认 mise.toml 已声明 mvnd"; exit 1; }
    MVN_BIN="$MVND_HOME/bin/mvnd" ;;
  mvn)
    MVN_BIN="$(mise where maven)/bin/mvn" ;;
  *)
    echo "用法: bash build-release.sh [mvnd|mvn]"; exit 1 ;;
esac
echo "==> 构建工具: $MVN_BIN"
"$MVN_BIN" -version 2>&1 | grep -E "^(mvnd|Apache Maven|Java version)" | sed 's/^/    /'

# ---------------------------- 2. 构建 --------------------------------------
# 官方 BUILDING 原始命令：mvn -Prelease-nacos -Dmaven.test.skip=true clean install -U
# 仅额外加 -Drat.skip：仓库内 .vscode/settings.json 等本地文件无 license 头会触发 RAT 失败
echo "==> 开始构建 $(date '+%H:%M:%S')"
"$MVN_BIN" -B -Prelease-nacos -Dmaven.test.skip=true -Drat.skip=true clean install -U
echo "==> 构建结束 $(date '+%H:%M:%S')"

# ---------------------------- 3. 产物自检 ------------------------------------
J="$ROOT/console/target/nacos-server.jar"
echo "==> 自检 $(basename "$J")"
fail=0

echo "--- [1] 之前随机丢失的 protobuf 生成类 ---"
check_class() {  # $1=嵌套 jar  $2=类路径
  local tmp; tmp="$(mktemp -d)"
  if ( cd "$tmp" && unzip -o -q "$J" "BOOT-INF/lib/$1" && unzip -o -q "BOOT-INF/lib/$1" "$2" ) >/dev/null 2>&1; then
    echo "    OK   $1 -> ${2##*/}"
  else
    echo "    FAIL $1 缺少 $2"; fail=1
  fi
  rm -rf "$tmp"
}
check_class nacos-consistency-2.2.3.jar com/alibaba/nacos/consistency/entity/ReadRequest.class
check_class nacos-istio-2.2.3.jar       'istio/mcp/v1alpha1/ResourceSourceGrpc$ResourceSourceImplBase.class'
check_class nacos-istio-2.2.3.jar       istio/mcp/v1alpha1/ResourceSourceGrpc.class

echo "--- [2] fat jar 内无 shade 版 nacos-client 重复类 ---"
if unzip -l "$J" | grep -qE 'BOOT-INF/lib/nacos-client-2\.2\.3\.jar$'; then
  echo "    FAIL 存在 shade 版 nacos-client-2.2.3.jar"; fail=1
else
  echo "    OK   无 shade 版"
fi
if unzip -l "$J" | grep -qE 'BOOT-INF/lib/nacos-client-2\.2\.3-pure\.jar$'; then
  echo "    OK   含 nacos-client-2.2.3-pure.jar"
else
  echo "    FAIL 缺 pure 版"; fail=1
fi

echo "--- [3] JDK 8 字节码 ---"
tmp="$(mktemp -d)"; cd "$tmp"
unzip -o -q "$J" BOOT-INF/lib/nacos-sys-2.2.3.jar
unzip -o -q BOOT-INF/lib/nacos-sys-2.2.3.jar com/alibaba/nacos/sys/utils/DiskUtils.class
MAJOR="$(javap -v com/alibaba/nacos/sys/utils/DiskUtils.class | grep 'major version' | awk '{print $3}')"
FLIP="$(javap -c -p com/alibaba/nacos/sys/utils/DiskUtils.class | grep -oE 'ByteBuffer\.flip:\(\)Ljava/nio/[A-Za-z]+;' | head -1)"
echo "    major version: $MAJOR"
echo "    $FLIP"
[ "$MAJOR" = "52" ] || { echo "    FAIL 非 JDK 8 编译"; fail=1; }
[ "$FLIP" = "ByteBuffer.flip:()Ljava/nio/Buffer;" ] || { echo "    FAIL flip 签名为 JDK 9+"; fail=1; }

echo "--- [4] 对外版本号 (nacos-version.txt) ---"
unzip -o -q "$J" BOOT-INF/lib/nacos-common-2.2.3.jar
VER="$(unzip -p BOOT-INF/lib/nacos-common-2.2.3.jar nacos-version.txt | sed 's/^version=//')"
echo "    version=$VER"
cd "$ROOT"; rm -rf "$tmp"

# ---------------------------- 4. 结果 --------------------------------------
echo
if [ $fail -eq 0 ]; then
  echo "==> ✅ 自检全部通过"
  for f in console/target/nacos-server.jar distribution/target/nacos-server-2.2.3.zip distribution/target/nacos-server-2.2.3.tar.gz; do
    printf "    %11s  %s\n" "$(stat -f%z "$ROOT/$f")" "$f"
  done
  echo "    SHA256(jar): $(shasum -a 256 "$J" | awk '{print $1}')"
else
  echo "==> ❌ 自检失败，产物不可部署"; exit 1
fi
