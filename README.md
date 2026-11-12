# WASM 终端检测插件沙箱

面向供应商交付的 **WASI Preview 1** 终端检测插件服务：上传一个模块和一份脱敏 JSON 日志，服务在独立子进程中运行模块，把日志原样送入 stdin，并在模块正常退出后返回它写到 stdout 的 JSON。

服务不会把宿主目录、宿主环境变量、网络接口、额外文件描述符或服务器文件传给插件。插件只能看到 WASI 的 stdin/stdout/stderr；线性内存上限 64 MiB。

除原有的试跑接口外，服务还提供成对的**录制 / 重放**接口，用于把供应商插件“偶发误报”的一次具体运行原样交给供应商复现：录制时按调用顺序捕获每次 `random_get`，重放时只回放这些记录、绝不取新随机数，输出逐字节一致才判定复现成功。

## 快速启动

```bash
docker compose up --build
```

服务启动后：

* API 文档与上传界面（Swagger UI，可直接 Try it out）：<http://localhost:8000/docs>
* 健康检查：<http://localhost:8000/healthz>

## 三个接口

| 接口 | 用途 | 允许的 WASI 导入 |
| --- | --- | --- |
| `POST /api/v1/analyze` | 原始试跑接口（保持不变） | 完整 WASI preview-1（无预打开目录、空环境） |
| `POST /api/v1/record` | 运行并录制每次 `random_get`，返回 JSON 录制包 | 仅 `fd_read`、`fd_write`、`proc_exit`、`random_get` |
| `POST /api/v1/replay` | 上传原模块、原日志和录制包，确定性重放 | 同上四个 |

录制 / 重放接口在实例化之前检查模块导入：只要导入了四个允许函数之外的任何符号（例如 `path_open`、`environ_sizes_get`，或非 `wasi_snapshot_preview1` 模块的导入），直接返回 `422 import_not_allowed`，不会实例化。

## 录制包格式

`/api/v1/record` 的响应是一个 JSON 对象（`application/json`，`Cache-Control: no-store`）：

```json
{
  "format": "wasm-random-replay/1",
  "module_sha256": "…（上传模块的 SHA-256，十六进制）",
  "log_sha256": "…（上传日志的 SHA-256，十六进制）",
  "random_calls": 2,
  "random_bytes": 5,
  "random_get": [
    {"index": 0, "length": 1, "errno": 0, "bytes": "a9"},
    {"index": 1, "length": 4, "errno": 0, "bytes": "ac7632e0"}
  ],
  "output": "…（本次运行 stdout 原始字节的 base64）"
}
```

* 每条 `random_get` 记录按**调用顺序**保存请求长度 `length`、返回码 `errno` 和写入客户内存的原始字节 `bytes`（十六进制）；实例化阶段（WASI start 函数中）发生的调用同样被记录。
* 录制最多 **256 次**调用、随机字节合计 **32 KiB**。任一上限被突破都会终止运行并返回 `422 recording_limit_exceeded`，**不返回半包**。
* 包内同时保存模块与日志的 SHA-256 和本次原始输出；录制包只存在于该请求的临时目录中，响应后即删除，服务不落盘、不缓存。

## 在 /docs 中完成一次录制—重放—篡改演练

下面的命令与 Swagger UI 的 **Try it out** 完全等价（字段名相同）。演示模块 `demo/random-classify.wasm` 读取日志后调用两次 `random_get`（长度分别为 1 和 4），随机字节会影响它的分类结论；`demo/echo-random.wasm` 则把取到的 4 个随机字节原样写到 stdout，便于直观验证“回放不取新随机数”。

### 1. 录制

```bash
curl -sS \
  -F 'module=@demo/random-classify.wasm;type=application/wasm' \
  -F 'log=@demo/sample-log.json;type=application/json' \
  http://localhost:8000/api/v1/record -o package.json
```

### 2. 用同一个包反复重放，结果稳定复现

```bash
for i in 1 2 3; do
  curl -sS \
    -F 'module=@demo/random-classify.wasm;type=application/wasm' \
    -F 'log=@demo/sample-log.json;type=application/json' \
    -F 'package=@package.json;type=application/json' \
    http://localhost:8000/api/v1/replay
  echo
done
```

每次都返回 `"reproduced":true`，且 `output` 与录制包逐字节相同。用 `echo-random.wasm` 可以更直观地看到：重放 stdout 的十六进制内容永远等于录制到的随机字节，而不是新的随机值。

### 3. 篡改 / 删除记录后重放，按调用位置报错

```bash
# 长度不符：把第 0 条记录改成 9 字节
python3 - <<'EOF'
import json
p = json.load(open("package.json"))
p["random_get"][0]["length"] = 9
p["random_get"][0]["bytes"] = "00" * 9
json.dump(p, open("package-bad-length.json", "w"))
EOF

curl -sS \
  -F 'module=@demo/random-classify.wasm;type=application/wasm' \
  -F 'log=@demo/sample-log.json;type=application/json' \
  -F 'package=@package-bad-length.json;type=application/json' \
  http://localhost:8000/api/v1/replay
# 422 replay_diverged：… different buffer length … (random_get call position: 0)

# 记录耗尽：删掉最后一条记录，模块仍会发起第二次调用
python3 - <<'EOF'
import json
p = json.load(open("package.json"))
p["random_get"].pop()
json.dump(p, open("package-short.json", "w"))
EOF
# → 422 replay_diverged … called random_get more times than were recorded … position: 1

# 退出后仍有剩余：追加一条模块用不到的记录
python3 - <<'EOF'
import json
p = json.load(open("package.json"))
p["random_get"].append({"index": 2, "length": 1, "errno": 0, "bytes": "ab"})
json.dump(p, open("package-extra.json", "w"))
EOF
# → 422 replay_diverged … exited before consuming every recorded … position: 2
```

### 4. 模块或日志被替换会先被摘要拦下

```bash
curl -sS \
  -F 'module=@demo/classify.wasm;type=application/wasm' \
  -F 'log=@demo/sample-log.json;type=application/json' \
  -F 'package=@package.json;type=application/json' \
  http://localhost:8000/api/v1/replay
# 422 replay_digest_mismatch
```

只有摘要核对通过、记录被完整按序消耗、且 stdout 与录制输出逐字节一致时，才返回 `200` 与 `"reproduced":true`。

## 演示模块

| 文件 | 用途 | 预期结果 |
| --- | --- | --- |
| `demo/classify.wasm` | 读取 stdin，匹配标记后输出分类 JSON（试跑接口演示） | `200` + JSON |
| `demo/random-classify.wasm` | 两次 `random_get` 影响分类结论（录制/重放主示例） | 录制成功、重放稳定复现 |
| `demo/echo-random.wasm` | 把 4 个随机字节原样写到 stdout（验证回放不引入新随机数） | 重放输出恒等于录制字节 |
| `demo/loop.wasm` | `_start` 无限循环 | `504 plugin_timeout` |
| `demo/spam.wasm` | 持续写 stdout，永不退出 | `413 plugin_output_too_large` |
| `demo/sample-log.json` / `suspicious-log.json` / `malicious-log.json` | 脱敏日志 | `allow` / `review` / `block` |

`.wat` 源码一并保留，修改后可重新生成（需要本地安装 `requirements.txt` 中的 `wasmtime`）：

```bash
python demo/build_demo.py
```

## 错误格式

所有错误均为：

```json
{ "error": { "code": "…", "message": "…" }
}
```

录制 / 重放相关的 `code`：

| HTTP | `code` | 说明 |
| --- | --- | --- |
| `413` | `package_too_large` | 录制包超过上传上限 |
| `422` | `import_not_allowed` | 模块导入了四个允许函数之外的符号 |
| `422` | `recording_limit_exceeded` | 超过 256 次调用或 32 KiB 随机字节，未生成录制包 |
| `422` | `invalid_replay_package` | 录制包不是合法 JSON、格式/字段/摘要/预算不合法 |
| `422` | `replay_digest_mismatch` | 上传模块或日志的 SHA-256 与录制包不一致 |
| `422` | `replay_diverged` | 长度不符、记录耗尽或退出后仍有剩余，消息含 `random_get` 调用位置 |
| `422` | `replay_output_mismatch` | 记录全部按序消耗，但 stdout 与录制输出不是逐字节一致 |

试跑接口原有的 `invalid_module`、`plugin_trap`、`plugin_nonzero_exit`、`plugin_timeout`、`plugin_output_too_large`、`client_disconnected` 等代码在三个接口上含义一致。

## 安全边界

* **独立子进程**：每个请求新建 Python runner 子进程、独立临时目录和独立进程组；插件死循环不会占用 API 事件循环。三个接口共用同一套监督逻辑（超时、输出上限、断连清理）。
* **WASI 能力最小化**：不调用 `preopen_dir`（没有 `--dir`），WASI 环境变量为空，`argv` 固定且不含宿主路径；Preview 1 没有 socket 接口。录制/重放进一步把可链接导入收紧到 `fd_read`、`fd_write`、`proc_exit`、`random_get` 四个，并由 runner 自行实现，便于拦截与注入 `random_get`。
* **确定性重放**：重放路径不导入任何熵源，`random_get` 只按序返回录制字节；长度不符、记录耗尽、退出后剩余均按零基调用位置报错；完整消耗且输出逐字节一致才算复现成功。
* **文件描述符**：子进程 `close_fds=True`，stdin 为 `DEVNULL`，只有父进程持有的 stdout/stderr 管道；日志通过受限 runner 的 `fd_read` 提供，插件看不到临时目录路径。
* **内存上限**：wasmtime `StoreLimits` 将线性内存限制为 64 MiB；表元素、实例、内存和表数量也有独立上限。
* **时间与输出上限**：子进程启动后 2 秒墙钟上限；stdout+stderr 合计 64 KiB，超限即杀进程组，不返回部分输出。
* **断连与清理**：处理过程中轮询客户端断开状态；断连、取消、超时、超限和录制预算超限都走同一套进程组终止、`wait()` 回收和临时目录删除逻辑。录制包与重放材料只存在于请求临时目录，响应后同步删除。
* **容器加固**：Compose 使用只读根文件系统、`/tmp` tmpfs、`cap_drop: ALL`、`no-new-privileges`、进程数和内存限制。

## 本地测试

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

测试覆盖原有分类/陷阱/超时/输出与内存上限，以及录制包结构、反复重放稳定性、模块与日志摘要核对、长度不符/记录耗尽/剩余记录的调用位置、输出逐字节比对、非法录制包各形态、导入白名单、256 次/32 KiB 预算边界、start 函数中的 `random_get`、`proc_exit(0)` 正常录制等。

## 主要文件

```text
app/main.py        FastAPI 接口、上传/录制包校验与 OpenAPI 文档
app/middleware.py  在 multipart 解析前限制请求体（重放接口单独的更大上限）
app/sandbox.py     子进程监督、超时/输出限制/断连清理、录制与重放编排
app/runner.py      每请求独立运行的 wasmtime runner（试跑模式 + 受限录制/重放模式）
app/config.py      所有资源上限（含 256 次 / 32 KiB 录制预算）
demo/              演示模块、WAT 源码和脱敏日志
tests/             试跑接口与录制/重放接口的回归测试
```
