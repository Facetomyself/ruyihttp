# 上游 `ruyihttp` 0.11.0：差异与跟进计划

核对日期：2026-11-26。本仓基线是 [`0.9.1` 对应的提交 `fae13b0`](https://github.com/Facetomyself/ruyihttp/tree/fae13b0a9eabbafbcdbf5c59438875525fcc0d0b)，共同起点是上游 PyPI `0.9.0`。这里比较发布物，区分**上游新增内容、本仓已有实现、尚待验收的移植**。以下建议尚未改变本仓的代码、默认版本或原生库。

## 比较依据

上游署名 **LoseNine**（PyPI 维护账号 `ruyi`），元数据列出的代码地址是 [charlesval/ruyiHttp](https://github.com/charlesval/ruyiHttp)。核对时该仓库网页与公开 GitHub API 均返回 HTTP 404，因此本次以 PyPI 版本元数据、wheel 及其 `RECORD` 为比对依据，不把无法公开访问解释为停止维护。下表是实际发布文件，而不是上游文档的目标平台列表。

| 上游版本 | 发行日期 | PyPI 上实际可下载的 wheel | 默认 Firefox | Windows NSS / NSPR / Neqo |
| --- | --- | --- | --- | --- |
| [0.9.0](https://pypi.org/project/ruyihttp/0.9.0/#files) | 2026-10-28 | Windows x64 | 159 | 3.131 / 4.40 / 0.32.0 |
| [0.10.0](https://pypi.org/project/ruyihttp/0.10.0/#files) | 2026-11-14 | Windows x64、`manylinux_2_31_x86_64` | 160 | 3.132 / 4.40 / 0.33.0 |
| [0.11.0](https://pypi.org/project/ruyihttp/0.11.0/#files) | 2026-11-25 | **仅 Windows x64** | 161 | **3.133 / 4.40 / 0.34.0** |

三版 Windows wheel 均核对了 PyPI SHA-256 和逐文件 `RECORD`。0.11.0 的 wheel SHA-256 为 `79eb2f08326c5f1e0a9ffddecef5136f45b50aefe952051f878e514a63939332`。本仓 Windows 仍使用上游 0.9.0 的六个 DLL；四个 POSIX 目标则使用固定 ff-ruyijs / Firefox 源码构建的 NSS 3.132 / NSPR 4.40 / Neqo 0.33.0。**包版本、可选 Firefox 配置和实际加载的原生库版本是三个不同的值。**

## 优先跟进什么

### 1. 先同步信任数据与公共后缀列表

这是可以脱离原生库升级、单独验收的变更。比较本仓与上游 0.11.0：

- **根证书：121 → 118。** 按证书 DER 的 SHA-256 比较，新增 0、移除 3：`emSign Root CA - C1`、`emSign ECC Root CA - G3`、`emSign ECC Root CA - C3`。这些变化已包含在 0.10.0；0.10.0 与 0.11.0 的根证书文件相同。移出本发行包不等于证书被吊销。根约束 JSON 的解析结果相同。比较 DER 和解析后的 JSON，可以排除 Windows 换行差异。
- **公共后缀列表（PSL）：新增 70 条、移除 5 条规则。** 口径是排除注释和空行后的规则集合（10,398 → 10,463）。在本仓原有 Cookie 逻辑中仅用测试夹具替换此表，从 `one.abyme.dev` 向 `two.abyme.dev` 准备跨租户 fetch：旧表得到 `same-site` 并附带目标的 Secure / SameSite=Strict 测试 Cookie；新表得到 `cross-site` 且不附带。实验仅构造请求，没有发包。
- **合入门禁：** 上游 0.11.0 的 PSL 与 Mozilla [`FIREFOX_161_0_RELEASE` 的 PSL](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_161_0_RELEASE/netwerk/dns/effective_tld_names.dat) 字节一致；该版 wheel 记录的 `certdata.txt` 源哈希也与 [Mozilla 文件](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_161_0_RELEASE/security/nss/lib/ckfw/builtins/certdata.txt) 一致。正式同步前应复查导出的受信任根/约束、更新本仓 manifest 的数据哈希，验证留存/移除根、CA 轮换、跨租户 Cookie 和安装后数据完整性。无需因此把默认 Firefox 从 159 改成 161。

### 2. Firefox 160/161：先做可选配置，再验证原生行为

上游 Windows wheel 的 Python 改动很小：两个版本依次扩展 `_firefox.py` 的默认值和范围、在 `_tls_profiles.py` 中把 `160`、`161` 映射到已有的 `_P7`，并在 `_nss.py` 把固定 NSS 检查提升到 3.132、3.133。**相同的 Python 表不证明不同原生版本产生相同的网络行为。**

建议先在分支上显式选择 `firefox="160"`、`firefox="161"`，保留现有按平台生成的 UA 和按清单验证 NSS 的逻辑。用上游验证样本或相应 Firefox 正式版对照 TLS、H2 SETTINGS 和 H3 协商，回归现有 159 配置。各平台的能力、遥测和差异有证据以后，再决定何时改默认值；验证前保持[当前支持矩阵](platform-support.md)。

### 3. 原生候选先验 Windows，再决定 POSIX 的升级路径

上游 0.11.0 Windows 的 **6 个 DLL 均与本仓不同**。静态 PE 检查中，Necko core 的 50 个、QUIC 桥的 4 个命名导出与本仓 Windows 旧桥一致，但上游 Windows 仍是 JSON 正文接口，没有本仓 POSIX 的可选 binary body ABI v1。相同导出名不能代替调用约定和网络行为验证。

Windows 宜用完整的 NSS 3.133 / Neqo 0.34.0 库组做候选，附新来源、哈希与第三方清单，在 Windows x64 的 CPython 3.10 / 3.14 上验证加载路径、证书拒绝、H1/H2/H3、代理和旧包升级。上游描述了 Windows `source/`、Rust 依赖与 SDK 构建流程；0.11.0 的 PyPI 文件列表没有 sdist，wheel 也未携带这套源码。拿到相应源树及其版本后才能把“导入已发布 DLL”提升为“从源码重建”。

POSIX 宜单独钉住新 Firefox / NSS / Neqo 源码，重放本仓 H3 数据 ABI 和 macOS 遥测等补丁，再跑四个原生目标的安装与协议门禁。上游 0.10.0 的 Linux x64 wheel 是降低 glibc 门槛的工程参考，不是 0.11.0 的 Linux 产物：它含 12 个 `.so`，本仓为 14 个，布局也不同（如 `libmozsqlite3.so` 与 `libsqlite3.so`）。**仅改 manylinux 标签没有兼容性意义**；如要下探 2.31，应在该基线构建并用最低系统实测。Apple Silicon、Intel Mac、Linux ARM64 继续由本仓独立验收。

## 哪些应保留

- 将换行统一为 LF 后，上游三版 Windows wheel 的 `_transport.py`、`_http2.py`、`_http3.py`、`_connect.py`、`_socks.py`、`api.py`、`adapters.py`、`sessions.py` 分别逐文件一致。`_retry.py` 在 0.9.0 → 0.10.0 只改了注释性文档字符串。本仓与这三个版本的 41 项顶层 `__all__` 导出、`Session` 构造签名以及 `Requires-Dist` 约束（含 SOCKS extra）一致，没有新增公开 API 或依赖需要追赶。**这是 Python 层结论，不含 DLL 内部实现。**
- 保留本仓已验收的非幂等 POST 防重放、IP SameSite、统一 DNS/连接时限、H2 慢流隔离、H3 停止上传与两种正文 ABI、Alt-Svc 回退、信任材料轮换及五平台门禁。用上游整个包覆盖会丢失这些改动；例如上游 0.11.0 的 `_retry.restartable` 仍把连接复用本身作为一种重发条件。

## 复核版本与下载哈希

以下命令只读取 PyPI 元数据，不会安装或运行上游代码：

```bash
python - <<'PY'
import json
from urllib.request import urlopen
for version in ('0.9.0', '0.10.0', '0.11.0'):
    with urlopen(f'https://pypi.org/pypi/ruyihttp/{version}/json', timeout=15) as response:
        release = json.load(response)
    for artifact in release['urls']:
        print(version, artifact['filename'], artifact['digests']['sha256'])
PY
```
