# 上游 `ruyihttp` 0.11.0：差异与选择性同步

核对日期：2026-11-26。本仓基线是 [`0.9.1` 对应的提交 `fae13b0`](https://github.com/Facetomyself/ruyihttp/tree/fae13b0a9eabbafbcdbf5c59438875525fcc0d0b)，共同起点是上游 PyPI `0.9.0`。这里比较发布物，区分**上游新增内容、本仓已有实现、尚待验收的移植**。下面的比较和原始计划以 0.9.1 为基线；实施结果单列于下，默认配置仍为 159。

## 比较依据

上游署名 **LoseNine**（PyPI 维护账号 `ruyi`），元数据列出的代码地址是 [charlesval/ruyiHttp](https://github.com/charlesval/ruyiHttp)。核对时该仓库网页与公开 GitHub API 均返回 HTTP 404，因此本次以 PyPI 版本元数据、wheel 及其 `RECORD` 为比对依据，不把无法公开访问解释为停止维护。下表是实际发布文件，而不是上游文档的目标平台列表。

| 上游版本 | 发行日期 | PyPI 上实际可下载的 wheel | 默认 Firefox | Windows NSS / NSPR / Neqo |
| --- | --- | --- | --- | --- |
| [0.9.0](https://pypi.org/project/ruyihttp/0.9.0/#files) | 2026-10-28 | Windows x64 | 159 | 3.131 / 4.40 / 0.32.0 |
| [0.10.0](https://pypi.org/project/ruyihttp/0.10.0/#files) | 2026-11-14 | Windows x64、`manylinux_2_31_x86_64` | 160 | 3.132 / 4.40 / 0.33.0 |
| [0.11.0](https://pypi.org/project/ruyihttp/0.11.0/#files) | 2026-11-25 | **仅 Windows x64** | 161 | **3.133 / 4.40 / 0.34.0** |

三版 Windows wheel 均核对了 PyPI SHA-256 和逐文件 `RECORD`。0.11.0 的 wheel SHA-256 为 `79eb2f08326c5f1e0a9ffddecef5136f45b50aefe952051f878e514a63939332`。比较基线 0.9.1 的 Windows 使用上游 0.9.0 的六个 DLL；四个 POSIX 目标则使用固定 ff-ruyijs / Firefox 源码构建的 NSS 3.132 / NSPR 4.40 / Neqo 0.33.0。**包版本、可选 Firefox 配置和实际加载的原生库版本是三个不同的值。**

## 0.9.4：独立于上游的代理与 Linux 运行基线

本分支新增[端到端 H3 经 CONNECT-UDP](masque.md)及[Linux glibc 2.31 原生验收](linux-glibc231-qualification.md)。没有以旧 Linux wheel 或仅修改平台标签取得兼容性；Windows 上游 DLL 和 Firefox 159 默认配置沿用。两条版本线继续独立。

## 0.9.3：区分上游、平台移植与真实浏览器

上游 0.11.0 的 Python 桌面 UA 固定为 Windows；0.10.0 的 Linux x86_64 wheel 也沿用该模板。本仓支持按宿主选择官方平台配置，因此 Linux/macOS 的验收依据应是该平台的官方 Firefox，而不是 Windows 模板。Linux ARM64 对应的公开 CPU 字段与实际加载库的 CPU 分离：[Firefox 122 源码](https://github.com/mozilla-firefox/firefox/blob/f16f94e4ec9404ae1cec1377a32c4812bbdbf0d3/netwerk/protocol/http/nsHttpHandler.cpp)仍使用 `uname`；[Firefox 123 发布默认值](https://github.com/mozilla-firefox/firefox/blob/83a2fe4a63390103d1ea7cacb15be96451e923f5/modules/libpref/init/StaticPrefList.yaml#L11540-L11555)开始在 Linux ARM64 冻结 OSCPU，故对外是 `X11; Linux x86_64`。Windows 六个 DLL 沿用上游原件，POSIX 桥则按[固定 Gecko 源码与目标机观测](../native/patches/GECKO_H3_POLICY.md)单独维护。

对 Windows 的结论有直接对照：[同一 Windows x64 runner](https://github.com/Facetomyself/ruyihttp/actions/runs/45768951928)分别运行签名的官方 Firefox 161、原样安装的 PyPI 0.11.0、已发布的 fork 0.9.2 和修复候选。在显式 `firefox="161"`、相同导航/Fetch 场景下，三份 wheel 的受检稳定字段均与官方相符，且多次新 H3 连接均呈现允许的扩展排列变化。这不是五个系统的上游结论，也不是对 100–158 或完整浏览器行为的总保证。最终 Windows wheel 在自己的发布格式门禁里重复该同机对照。

## 0.9.2 实施记录

- **先同步信任数据。** [输入来源与 SHA-256](upstream-0.11.0-data.json)给出精确 wheel 和 Mozilla 源文件。维护者用 `python tools/sync_trust_data.py --wheel WHEEL --certdata CERTDATA --psl PSL` 离线复查；默认只读，`--apply` 仅写入三份受限数据和对应哈希。118 张证书逐一匹配 Mozilla TLS server trusted delegator；仅一条签发截止约束，未变。测试中三张移出的自签根在原包受信、新包不受信；ISRG Root X1 在两包均受信。保留的 `firefox-profile.json` 是 Firefox 159 历史参考，不是当前根列表或运行时清单。
- **随后适配配置与平台运行时。** `firefox="160"` 和 `firefox="161"` 均为显式选择，保留 `159` 默认。本仓未接纳上游 Python 传输实现。[配置参考及真实观察](firefox-profile-wire.md)列出与官方浏览器的匹配字段和已知差异；Windows 整组 DLL 的输入哈希、POSIX 的锁定源码及补丁、各平台门禁分别见[构建说明](build-native.md)和[平台验收](platform-support.md)。
- **保留 fork 身份。** 采用独立版本 `0.9.2`；按 wheel 校验 46 个原生文件（五目标合计）、四份数据与来源记录，并在目标平台验证从公开 0.9.0 / 旧 fork 和直接前序 fork 0.9.1 的普通 pip 升级。PyPI 发布与本仓交付是两件事。

## 基于 0.9.1 的原始差异和跟进顺序

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
