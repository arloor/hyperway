# hyperway

`hyperway` 是一个面向 Kubernetes Gateway API 的轻量网关实现，包含：
- 数据面进程：`hyperway`
- 控制器进程：`hyperway_controller`（仅 Snapshot/CRD 模式使用）

核心能力：
- 解析 `GatewayClass` / `Gateway` / `HTTPRoute`（v1.1 Core+Extended）
- 根据 `Gateway.listeners` 动态增删监听端口
- 根据 `listeners[*].tls.certificateRefs` 读取 Secret 并启用 TLS
- 执行 `HTTPRoute` 匹配与过滤：`path/method/header/query`、加权 `backendRefs`、`Request/ResponseHeaderModifier`、`RequestRedirect`、`URLRewrite`、`RequestMirror`、`timeouts`、`retry`
- 数据面仅执行 `httpRoutesV1` 运行时模型，不再包含 legacy `locations` 回退链路
- 支持两种运行模式：
  - 模式 A：`controller + RouteSnapshot CRD + proxy`
  - 模式 B：`single-process direct K8s API`

## 关键约定

- Gateway `controllerName`：`hyperway.arloor.dev/gateway-controller`
- RouteSnapshot API Group：`hyperway.arloor.dev`
- RouteSnapshot Kind：`RouteSnapshot`
- RouteSnapshot Resource：`routesnapshots`
- CRD 名称：`routesnapshots.hyperway.arloor.dev`

## 模式总览（并列）

### 模式 A：`controller + RouteSnapshot CRD + proxy`

1. `hyperway_controller` 监听 Gateway API 资源，写入 `RouteSnapshot`
2. `hyperway` 读取 `RouteSnapshot`，热更新路由和监听端口/TLS

### 模式 B：`single-process direct K8s API`

1. 仅运行 `hyperway` 单进程
2. `hyperway` 直接从 Kubernetes API 同步 Gateway API 资源并在内存中更新路由

### 模式对比

| 维度 | 模式 A（Snapshot/CRD） | 模式 B（直连 K8s API） |
| --- | --- | --- |
| 进程拓扑 | 双进程：`hyperway_controller` + `hyperway` | 单进程：仅 `hyperway` |
| 是否需要 CRD | 需要 `RouteSnapshot` CRD | 不需要 |
| 是否需要 `hyperway_controller` | 需要 | 不需要 |
| RBAC 重点权限 | `gatewayclasses/gateways/httproutes/referencegrants`、`secrets/services/namespaces`、`routesnapshots`（含 status） | `gatewayclasses/gateways/httproutes/referencegrants`、`secrets/services/namespaces`（无 `routesnapshots` 相关权限） |
| 同步机制 | controller 侧：Gateway API watch + poll；proxy 侧：`RouteSnapshot` poll | `hyperway` 直接对 Gateway API watch + poll |
| 故障影响面 | controller 故障会停止新快照写入，但已有快照仍可被 proxy 使用 | 单进程故障会同时影响流量转发与配置同步 |
| 适用场景 | 控制面与数据面解耦、希望通过 CRD 观察中间态 | 部署更轻量、无需 CRD、调试或小规模环境 |

### 参数边界（两种模式通用约束）

- `--gateway-api-k8s-sync` 与 `--gateway-api-snapshot-name` 互斥，不能同时启用。

## 快速开始（按模式）

### 1) 编译

```bash
cargo build -p hyperway --release
```

### 2) 查看参数

```bash
cargo run -p hyperway -- --help
cargo run -p hyperway --bin hyperway_controller -- --help
```

### 3) 路径 A：Snapshot/CRD（双进程）

`hyperway_controller`：

```bash
hyperway_controller \
  --gateway-api-snapshot-name default-routes \
  --gateway-api-snapshot-namespace default \
  --gateway-api-k8s-namespace default \
  --gateway-api-k8s-poll-seconds 15 \
  --gateway-api-k8s-controller-name hyperway.arloor.dev/gateway-controller
```

`hyperway`：

```bash
hyperway \
  --gateway-api-snapshot-name default-routes \
  --gateway-api-snapshot-namespace default \
  --gateway-api-snapshot-poll-seconds 3
```

### 4) 路径 B：直连 K8s API（单进程）

```bash
hyperway \
  --gateway-api-k8s-sync \
  --gateway-api-k8s-namespace default \
  --gateway-api-k8s-poll-seconds 15 \
  --gateway-api-k8s-controller-name hyperway.arloor.dev/gateway-controller
```

## 模式 A（Snapshot/CRD）细节

### 数据流

`Gateway API resources -> hyperway_controller -> RouteSnapshot CRD -> hyperway`

### 必需资源

- CRD：`deploy/gateway-api-snapshot-crd.yaml`
- RBAC：`deploy/gateway-api-rbac.yaml`
- Sidecar（同 Pod 双容器）示例：`deploy/gateway-api-sidecar.yaml`

### 启动参数

- `hyperway_controller`：必须配置 `--gateway-api-snapshot-name`，并建议显式设置 `--gateway-api-snapshot-namespace`、`--gateway-api-k8s-namespace`、`--gateway-api-k8s-poll-seconds`、`--gateway-api-k8s-controller-name`。
- `hyperway`：通过 `--gateway-api-snapshot-name`、`--gateway-api-snapshot-namespace`、`--gateway-api-snapshot-poll-seconds` 读取快照。

### 常见风险

- CRD schema 与运行代码不一致会导致写入/更新失败（例如 `spec.checksum` 类型错误）。
- controller 未写入对应对象时，proxy 会持续提示 `RouteSnapshot ... does not exist yet`。

## 模式 B（直连 K8s API）细节

### 数据流

`Gateway API resources -> hyperway（内存路由）`

### 部署要求

- 无需 `RouteSnapshot` CRD。
- 无需独立 `hyperway_controller` 进程。
- RBAC 应聚焦于 Gateway API、ReferenceGrant、Namespace/Service/Secret 读取及状态更新；最小权限原则下可去掉 `routesnapshots` 与 `routesnapshots/status` 相关权限。

### 启动参数

- 需开启 `--gateway-api-k8s-sync`。
- 可按需设置 `--gateway-api-k8s-namespace`（为空表示全命名空间）。
- 使用 `--gateway-api-k8s-poll-seconds` 设置周期拉取间隔。
- 使用 `--gateway-api-k8s-controller-name` 过滤目标 GatewayClass。

### 配置边界

- 不可同时配置 `--gateway-api-k8s-sync` 和 `--gateway-api-snapshot-name`。
- 当前仓库现成 Deployment 示例主要针对模式 A；模式 B 需要在 Deployment 参数层面切换到 `--gateway-api-k8s-sync` 并移除 `gateway-controller` 容器。

## Kubernetes 部署清单（按模式）

### 路径 A：Snapshot/CRD

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

### 路径 B：直连 K8s API

当前仓库没有单独维护的“模式 B 一键 YAML”，可基于模式 A 清单做最小改造：

1. 以 `deploy/gateway-api-sidecar.yaml` 为基础，删除 `gateway-controller` 容器，只保留 `hyperway` 容器。
2. 把 `hyperway` 容器参数改为 `--gateway-api-k8s-sync` 路径，不再传 `--gateway-api-snapshot-*`。
3. 以 `deploy/gateway-api-rbac.yaml` 为基础，按最小权限原则去掉 `routesnapshots` 与 `routesnapshots/status` 规则。
4. 继续 apply Gateway API 对象（例如 `deploy/gateway-api-demo.yaml`）。

## TLS 与监听行为

- 仅 `HTTPS`/`TLS` listener 会启用 TLS。
- 证书来源：`Gateway.listeners[*].tls.certificateRefs` 指向的 `Secret`。
- Secret 需包含 `tls.crt` 和 `tls.key`。
- 同一端口可配置多个 listener：
  - 同端口多个 `HTTP` listener：支持（按 host/route 匹配）。
  - 同端口多个 `HTTPS` listener：支持；证书不同场景通过 SNI 选择证书（优先精确 hostname，再通配符，再默认证书）。
  - 同端口混合 `HTTP` 和 `HTTPS`：拒绝并在 listener status 标记 `PortConflict`。

## 运维接口

- 健康检查：`GET /healthz`
- 指标：`GET /metrics`（Prometheus 格式）

## 开发与校验

```bash
cargo fmt
cargo clippy -p hyperway --all-targets -- -D warnings
cargo test -p hyperway
```

## 常见问题（按模式定位）

- `422 ... spec.checksum ... must be of type integer/string`（仅模式 A）：
  - 说明运行代码和集群中的 CRD schema 不一致。
  - 重新 apply 当前仓库的 `deploy/gateway-api-snapshot-crd.yaml`，并重启 `hyperway_controller`。
- `RouteSnapshot ... does not exist yet`（仅模式 A）：
  - 先确认 controller 正常运行且有 `routesnapshots` 的写权限。
  - 再确认 `--gateway-api-snapshot-name/namespace` 两边一致。
- 直连模式下路由未生效（模式 B）：
  - 检查 ServiceAccount 是否有 `gatewayclasses/gateways/httproutes/referencegrants` 与 `services/namespaces/secrets` 的读取权限及相关 status patch 权限。
  - 检查 `--gateway-api-k8s-controller-name` 是否与目标 `GatewayClass.spec.controllerName` 一致。
  - 检查 `--gateway-api-k8s-namespace` 是否覆盖目标 Gateway/HTTPRoute 所在命名空间。
