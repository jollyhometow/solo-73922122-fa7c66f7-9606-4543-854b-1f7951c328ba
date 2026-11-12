# WASM 终端检测插件沙箱

面向供应商交付的 **WASI Preview 1** 终端检测插件试跑服务：上传一个模块和一份脱敏 JSON 日志，服务在独立子进程中运行模块，把日志原样送入 stdin，并在模块正常退出后返回它写到 stdout 的 JSON。

服务不会把宿主目录、宿主环境变量、网络接口、额外文件描述符或服务器文件传给插件。插件只能看到 WASI 的 stdin/stdout/stderr；线性内存上限 64 MiB。

## 快速启动

```bash
docker compose up --build
```

服务启动后：

* API 文档与上传界面：<http://localhost:8000/docs>
* 健康检查：<http://localhost:8000/healthz>

在 `/docs` 中展开 `POST /api/v1/analyze`，点击 **Try it out**：

1. `module` 选择仓库中的 `demo/classify.wasm`；
2. `log` 选择 `demo/sample-log.json`；
3. Execute，应返回：

```json
{"verdict":"allow","score":0,"reasons":["no malicious marker found"]}
```

也可以直接用 curl：

```bash
curl -sS \
  -F 'module=@demo/classify.wasm;type=application/wasm' \
  -F 'log=@demo/sample-log.json;type=application/json' \
  http://localhost:8000/api/v1/analyze
```

## 演示模块

| 文件 | 用途 | 预期结果 |
| --- | --- | --- |
| `demo/classify.wasm` | 读取 stdin，在日志中匹配 `malicious` / `suspicious` 标记后输出分类 JSON | `200` + JSON |
| `demo/loop.wasm` | `_start` 无限循环 | `504 plugin_timeout` |
| `demo/spam.wasm` | 持续写 stdout，永不退出 | `413 plugin_output_too_large` |
| `demo/sample-log.json` | 脱敏正常日志 | `allow` |
| `demo/suspicious-log.json` | 脱敏可疑日志 | `review` |
| `demo/malicious-log.json` | 脱敏恶意标记日志 | `block` |

`classify.wasm` 只是无依赖的演示插件，用字节子串匹配模拟分类；真实插件可以自行解析 stdin 中的 JSON。`.wat` 源码一并保留，修改后可重新生成：

```bash
python demo/build_demo.py
```

（需要本地已安装 `requirements.txt` 中的 `wasmtime`。）

## API

### `POST /api/v1/analyze`

`multipart/form-data` 两个必填字段：

* `module`：二进制 WebAssembly 1.0 / WASI Preview 1 模块，最大 **1 MiB**
* `log`：合法 UTF-8 JSON，最大 **64 KiB**，原样写入插件 stdin

成功时返回插件 stdout 中的完整 JSON 值（状态码 `200`，`application/json`）。只有插件正常退出、stdout 是唯一一个合法 JSON 值，且总输出未超限时才会返回；否则不返回任何部分结果。

### 错误格式

```json
{
  "error": {
    "code": "plugin_timeout",
    "message": "Plugin execution exceeded the 2 second limit."
  }
}
```

| HTTP | `code` | 说明 |
| --- | --- | --- |
| `413` | `module_too_large` / `log_too_large` | 上传文件超过上限 |
| `413` | `request_too_large` | multipart 请求体超过服务上限 |
| `413` | `plugin_output_too_large` | 插件 stdout + stderr 合计超过 64 KiB |
| `422` | `invalid_module` | 不是合法 WASI Preview 1 二进制模块、缺少合法 `_start` 等 |
| `422` | `plugin_instantiation_failed` | 链接/实例化失败 |
| `422` | `plugin_trap` | 运行中触发 Wasm 陷阱 |
| `422` | `plugin_nonzero_exit` | 插件通过 `proc_exit` 返回非零状态 |
| `422` | `log_not_utf8` / `invalid_log_json` | 日志不是 UTF-8 或不是单个合法 JSON 值 |
| `422` | `invalid_plugin_json` | 插件 stdout 不是单个合法 UTF-8 JSON 值 |
| `499` | `client_disconnected` | 客户端断开，插件已终止并回收 |
| `504` | `plugin_timeout` | 子进程启动后超过 2 秒 |
| `500` / `502` | `sandbox_internal_error` / `sandbox_process_failed` | 沙箱内部故障 |

## 安全边界

* **独立子进程**：每个请求新建 Python runner 子进程、独立临时目录和独立进程组；插件死循环不会占用 API 事件循环。
* **WASI 能力最小化**：不调用 `preopen_dir`（没有 `--dir`），WASI 环境变量为空，`argv` 固定且不含宿主路径；Preview 1 没有 socket 接口。
* **文件描述符**：子进程 `close_fds=True`，stdin 为 `DEVNULL`，只有父进程持有的 stdout/stderr 管道；WASI 侧只暴露 fd 0/1/2，日志通过 runner 配置为 stdin，插件看不到临时目录路径。
* **内存上限**：wasmtime `StoreLimits` 将线性内存限制为 64 MiB；表元素、实例、内存和表数量也有独立上限。
* **时间上限**：子进程启动后 2 秒墙钟上限；超时由父进程终止整个进程组并等待回收。
* **输出上限**：父进程并发读取 stdout/stderr，共享 64 KiB 计数；任一流导致合计超限即杀进程，不解析部分输出。
* **断连清理**：处理过程中轮询客户端断开状态；断连、取消、超时和超限路径都会走同一套进程组终止、`wait()` 回收和临时目录删除逻辑。
* **容器加固**：Compose 使用只读根文件系统、`/tmp` tmpfs、`cap_drop: ALL`、`no-new-privileges`、进程数和内存限制。

说明：WASI Preview 1 本身没有网络和文件系统能力；宿主侧还通过不预打开目录和清空环境变量收缩攻击面。若需要更强的操作系统级网络隔离，可在生产编排层为整个服务增加网络策略，但这不影响 WASI 插件能力边界。

## 本地测试

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

测试覆盖正常分类、可疑/恶意分类、陷阱、非零退出、非法模块、非法日志、非法插件 JSON、输出超限、内存上限与增长、无宿主目录预打开、空环境变量、超时以及并发下死循环不阻塞正常请求。

## 主要文件

```text
app/main.py        FastAPI 接口、上传校验与 OpenAPI 文档
app/middleware.py  在 multipart 解析前限制请求体
app/sandbox.py     子进程监督、超时/输出限制/断连清理
app/runner.py      每个请求独立运行的 wasmtime/WASI runner
app/config.py      所有资源上限
demo/              演示模块、WAT 源码和脱敏日志
```
