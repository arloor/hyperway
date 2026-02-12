# hyperway

`hyperway` 是一个面向 Kubernetes Gateway API 的轻量网关实现，包含：
- 数据面进程：`hyperway`
- 控制器进程：`hyperway_controller`

核心能力：
- 解析 `GatewayClass` / `Gateway` / `HTTPRoute`
- 根据 `Gateway.listeners` 动态增删监听端口
- 根据 `listeners[*].tls.certificateRefs` 读取 Secret 并启用 TLS
- 将解析结果落到 `RouteSnapshot` CRD，数据面按快照热更新路由

## 关键约定

- Gateway `controllerName`：`hyperway.arloor.dev/gateway-controller`
- RouteSnapshot API Group：`hyperway.arloor.dev`
- RouteSnapshot Kind：`RouteSnapshot`
- RouteSnapshot Resource：`routesnapshots`
- CRD 名称：`routesnapshots.hyperway.arloor.dev`

## 架构

推荐使用“独立 controller + snapshot”模式：
1. `hyperway_controller` 监听 Gateway API 资源，写入 `RouteSnapshot`
2. `hyperway` 仅读 `RouteSnapshot`，负责流量转发和监听端口/TLS热更新

也支持单进程直连 K8s API（不经 RouteSnapshot），用于调试或小规模场景。

## 快速开始

### 1) 编译

```bash
cargo build -p hyperway --release
```

### 2) 查看参数

```bash
cargo run -p hyperway -- --help
cargo run -p hyperway --bin hyperway_controller -- --help
```

### 3) 推荐运行方式（双进程）

控制器：

```bash
hyperway_controller \
  --gateway-api-snapshot-name default-routes \
  --gateway-api-snapshot-namespace default \
  --gateway-api-k8s-namespace default \
  --gateway-api-k8s-poll-seconds 15 \
  --gateway-api-k8s-controller-name hyperway.arloor.dev/gateway-controller
```

数据面：

```bash
hyperway \
  --gateway-api-snapshot-name default-routes \
  --gateway-api-snapshot-namespace default \
  --gateway-api-snapshot-poll-seconds 3
```

### 4) 直连 K8s API 运行方式（单进程）

```bash
hyperway \
  --gateway-api-k8s-sync \
  --gateway-api-k8s-namespace default \
  --gateway-api-k8s-poll-seconds 15 \
  --gateway-api-k8s-controller-name hyperway.arloor.dev/gateway-controller
```

## Kubernetes 部署清单

- CRD：`deploy/gateway-api-snapshot-crd.yaml`
- RBAC：`deploy/gateway-api-rbac.yaml`
- Sidecar（同 Pod 双容器）示例：`deploy/gateway-api-sidecar.yaml`
- 完整示例（含 CRD + RBAC + Deployment + Gateway + HTTPRoute）：`deploy/gateway-api-argocd-dashboard.yaml`
- 基础 Gateway API 示例：`deploy/gateway-api-demo.yaml`

建议部署顺序：

```bash
kubectl apply -f deploy/gateway-api-snapshot-crd.yaml
kubectl apply -f deploy/gateway-api-rbac.yaml
kubectl apply -f deploy/gateway-api-sidecar.yaml
kubectl apply -f deploy/gateway-api-demo.yaml
```

## TLS 与监听行为

- 仅 `HTTPS`/`TLS` listener 会启用 TLS。
- 证书来源：`Gateway.listeners[*].tls.certificateRefs` 指向的 `Secret`。
- Secret 需包含 `tls.crt` 和 `tls.key`。
- 同一端口若配置多个 listener，当前实现会按稳定顺序保留一个并记录告警。

## 运维接口

- 健康检查：`GET /healthz`
- 指标：`GET /metrics`（Prometheus 格式）

## 开发与校验

```bash
cargo fmt
cargo clippy -p hyperway --all-targets -- -D warnings
cargo test -p hyperway
```

## 常见问题

- `422 ... spec.checksum ... must be of type integer/string`：
  - 说明运行代码和集群中的 CRD schema 不一致。
  - 重新 apply 当前仓库的 `deploy/gateway-api-snapshot-crd.yaml`，并重启 `hyperway_controller`。
- `RouteSnapshot ... does not exist yet`：
  - 先确认 controller 正常运行且有 `routesnapshots` 的写权限。
  - 再确认 `--gateway-api-snapshot-name/namespace` 两边一致。
