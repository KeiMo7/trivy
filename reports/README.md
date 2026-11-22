# 复核结论 → OpenVEX 合成与回灌验证

把人工复核结论（复核表）和 Trivy 扫描结果合成为一份**标准、可机读、可被现有消费路径直接消费**的
OpenVEX 文档，并通过**未改动的 Trivy VEX 消费器**回灌，逐条断言命中集合与状态。

本方案不修改 `pkg/vex` 下任何消费侧解释规则。生成的文档刻意落在消费侧既有的匹配口径内。

## 为什么必须按消费侧口径生成（硬约束 1）

消费侧链路是 `pkg/vex/openvex.go` → `github.com/openvex/go-vex` 的 `VEX.Matches`：

1. 只采信 `not_affected` 与 `fixed` 两种状态，其余状态（`affected` / `under_investigation`）
   会被保留在文档里但**不参与过滤**。
2. 匹配三元组是 `(vulnerability_id, product PURL, subcomponent PURL)`。
   - product 用扫描结果里镜像根组件的 OCI PURL；
   - subcomponent 用扫描结果里组件自身的 PURL。
3. PURL 匹配（`PurlMatches`）只比较 type/namespace/name/version/qualifiers，
   **不比较 purl 的 subpath，也没有任何 pkg_path 维度**。
4. 消费侧在组件树上做 leaf→root 遍历：组件级语句（带 subcomponent）只命中该组件；
   产物级语句（不带 subcomponent）在遍历到根时命中该产物下所有相关组件。
5. 同一 `(vuln, product, subcomponent)` 有多条语句时，取时间最新的一条。

第 3 点是消费侧真实的表达力边界，直接决定了本工具对"同组件多路径"的处理，见下文。

## 两级结论粒度

| 粒度 | OpenVEX 形态 | 消费行为 |
|------|--------------|----------|
| 产物级 `scope=product` | product=OCI PURL，无 subcomponent | 该产物内该漏洞的所有组件发现都被命中 |
| 组件级 `scope=component` | product=OCI PURL + subcomponent=组件 PURL | 仅命中该组件（PURL 相同的所有路径一并命中） |

同一漏洞在不同组件上可以是不同结论（一条 not_affected、一条 fixed），各自独立成语句。

## 产物身份：内容指纹，不靠名字、不靠标签

- 产物身份锚定 `repo_digests[0]` 的 `sha256` 摘要；`repo_tags` 仅作信息展示，不进身份。
- OCI PURL 由摘要构造，逻辑与 `pkg/purl` 的 `parseOCI` 一致：
  `pkg:oci/<repo 末段>@sha256:<hex>?arch=..&repository_url=..`。
- 镜像重新打标签（tag 变化、摘要不变）产出**相同** product PURL，结论不会分裂。
  单测 `TestRetagDoesNotChangeIdentity` 覆盖此点。

## 同组件多路径：不静默抹掉（对应问题陈述第 2 条）

扫描里同一组件 PURL 可能在多个 `pkg_path` 各报一条，而消费侧只按 PURL 匹配、无法区分路径。
因此一条组件级语句必然作用于该 PURL 的**全部**路径。生成器据此强制：

- 多路径只复核了其中一部分 → `REVIEW_PATH_PARTIAL`，**拒绝生成**（拒绝把"没复核"写成结论）；
- 多路径的最终结论互相矛盾 → `REVIEW_PATH_DIVERGENT`，**拒绝生成**，提示改用产物级或统一结论；
- 空 `pkg_path` 的复核行视为覆盖该组件全部路径（通配）；
- 全部路径结论一致时，收敛成一条组件级语句。

## 改判收敛与冲突（对应问题陈述第 7 条）

- 同一三要素键的多条复核，按 `reviewed_at` 时间先后收敛，文档只保留**最终一条**结论。
- 同键、同时间戳但结论互相矛盾时没有"最新者"，报 `REVIEW_CONFLICT` 拒绝生成，不猜。

## 对账清单（对应问题陈述第 6 条）

复核表里对不上扫描结果的条目不进文档、也不被静默跳过，而是单独写入 reconciliation 报告，逐条给原因：

- `component_not_found`：扫描结果中不存在该组件；
- `version_changed`：同 type/namespace/name 的组件版本已变，旧结论**过期**，不得沿用；
- `finding_not_found`：组件还在，但该漏洞（或该路径上的该漏洞）已不再上报；
- `product_not_found`：没有任何扫描产物携带该摘要。

每条都带 `source_file` + `row`，可定位到原始表的具体行。

## 全有或全无的失败策略（硬约束 2、降级第 3 条）

- 任意一条非法（理由缺失/非法、状态非法、重复冲突、部分路径等）→ **整份文档不出**，
  一次性列出全部问题条目（`Issues.Error()`），不接受"少几条也能交"。
- 回灌后若零命中，显式报错为失败，绝不当成"没有需要过滤的条目"。
- 对账类条目（对不上扫描）不阻断生成，但必须全部出现在对账清单里。

## 离线与可复现（硬约束 3、4，需求第 8 条）

- 构建/运行 `GOPROXY=off`，不依赖任何外部服务；模块已在本机缓存。
- 时间戳由 `SOURCE_DATE_EPOCH`（Unix 秒或 RFC3339）注入，不读墙钟、不使用随机量。
- 语句按确定顺序输出，相同输入两次生成**字节一致**（验收脚本含比对）。
- 交付产物（`reports/output/`）不含任何本机绝对路径或临时目录；回灌报告里的 VEX 来源归一成文档基名。

## 目录结构

```
pkg/vexgen/                 合成引擎（库）
  model.go                  输入/输出数据模型、问题与对账类型
  identity.go               摘要/OCI PURL/PURL 归一化
  engine.go                 扫描索引、全量校验、改判收敛、阻断规则
  render.go                 OpenVEX 渲染、冲突检测、多路径覆盖校验
  roundtrip.go              调用真实 pkg/vex 回灌 + 命中集合精确比对
  expect.go                 从文档反推期望集（独立 roundtrip 子命令用）
  helpers.go                文件/镜像配置辅助
  *_test.go                 单元测试
cmd/vexgen/                 CLI：generate / roundtrip / all
reports/
  input/                    扫描样本与两张复核表（含 failures/ 失败夹具）
  output/                   生成的 OpenVEX、对账清单、回灌比对报告
  scripts/                  三步脚本 + 失败演示 + 一键验收，及预编译 vexgen
  logs/                     真实运行输出
```

## 输入格式

扫描结果 `scans.json`（数组，每项一个产物）：

```json
{
  "product": {"artifact_type": "container_image", "name": "...", "repo_digests": ["repo@sha256:.."],
              "repo_tags": ["..."], "architecture": "amd64"},
  "findings": [{"vulnerability_id": "CVE-...", "component_purl": "pkg:...", "component_name": "..",
                "installed_version": "..", "pkg_path": ".."}]
}
```

复核表 `reviews_*.json`（数组，可多文件、多复核人、多轮次）：

```json
{"product_digest": "sha256:..", "vulnerability_id": "CVE-..", "scope": "component",
 "component_purl": "pkg:...", "pkg_path": "..", "status": "not_affected",
 "justification": "vulnerable_code_not_in_execute_path", "reviewer": "alice",
 "reviewed_at": "2026-11-10T08:00:00Z"}
```

`status` 取值：`not_affected` / `affected` / `fixed` / `under_investigation`。
`not_affected` 必须带合法 `justification`（OpenVEX 受控词表五选一）；其余状态不允许带 justification。

## 运行

```bash
# 一键：离线构建 → 生成 → 回灌 → 精确比对 → 可复现校验 → 失败/降级演示
bash reports/scripts/run_all.sh

# 或分三步
bash reports/scripts/01_generate.sh   # 生成 openvex.json + reconciliation.json
bash reports/scripts/02_roundtrip.sh  # 用未改动的 pkg/vex 回灌，产出 roundtrip.json
bash reports/scripts/03_compare.sh    # 断言命中集合一条不多一条不少、状态全对
bash reports/scripts/04_failures.sh   # 非法理由/部分路径阻断 + 条目缺失/版本过期对账
```

环境变量：`SOURCE_DATE_EPOCH`（必填，钉时间）、`VEXGEN_AUTHOR`（可选）。

## 验收点对照

| 验收要求 | 落点 |
|----------|------|
| 三产物、每产物十条结论，回灌逐条比对 | `reports/input/scans.json` + 两张复核表；`03_compare.sh` 断言 expected==observed==33 |
| 同漏洞不同组件不同结论，最终结论唯一 | 单测 `TestSameVulnDifferentComponents`；样本 CVE-2024-0001（bash=not_affected / curl=fixed） |
| 先后改判，最终结论唯一 | 单测 `TestRejudgementConverges`、`TestConflictingSameTimestamp`；样本 CVE-2024-0003、CVE-2024-0010 |
| 理由非法 / 条目缺失 / 版本过期三类失败，可复现且定位到条目 | `04_failures.sh` + `reports/input/failures/`；报错含 source_file:row |
| 零命中显式告警为失败 | 单测 `TestZeroHitsIsFailure`；`RoundTrip` 对零期望/零命中均返回 error |
| 产物入 reports/，附生成/回灌/比对脚本与真实输出 | `reports/scripts/`、`reports/logs/`、`reports/output/` |
| 消费侧零改动 | `pkg/vex` 未改；`go test ./pkg/vex/` 保持通过 |
