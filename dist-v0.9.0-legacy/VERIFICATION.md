# 归档 wheel 与重建 wheel 的对照验证

## 归档的原因

`dist/` 里的两个 wheel 是私有树改造前的产物，与 `native/` 已脱钩：

| 旧 wheel | 问题 |
| --- | --- |
| `ruyihttp-0.9.0-py3-none-win_amd64.whl` | `runtime-manifest.json` 是旧结构 `{version, platform, sha256}`，无 `platforms` 段；DLL 直放包根，不在 `native/` 布局 |
| `ruyihttp-0.9.0-py3-none-macosx_26_0_arm64.whl` | dylib 哈希与 `native/darwin_arm64/provenance.json` 全部不符；**缺 `libnecko_quic.dylib`** |
| linux | 从未产出 |

## 重建验证（2026-11-19 实测）

用 `RUYIHTTP_PLATFORM` 覆盖逐平台重建：

```
平台              wheel tag                              原生文件  结果
--------------------------------------------------------------------------------
win_amd64         py3-none-win_amd64                     6        OK
darwin_arm64      py3-none-macosx_26_0_arm64             6        OK
linux_x86_64      py3-none-manylinux_2_39_x86_64        14        OK
darwin_x86_64     —                                       0        FAIL
linux_aarch64     —                                       0        FAIL
```

两个 `build-required` 平台的失败是**预期的**：`setup.py` 明确抛
`native runtime missing` 而不是打包别的平台的二进制：

```
native runtime missing: .../native/linux_aarch64
Windows DLLs are in native/win_amd64.
macOS needs libnecko_core.dylib and libnecko_quic.dylib in native/darwin_arm64 or ...
```

## 重建产物与 manifest 的一致性

| wheel | 原生库 | 新 manifest | hash 匹配 |
| --- | ---: | --- | ---: |
| `ruyihttp-0.9.0-py3-none-win_amd64.whl` | 6 | 有 `platforms` 段 | **6/6** |
| `ruyihttp-0.9.0-py3-none-macosx_26_0_arm64.whl` | 6 | 有 `platforms` 段 | **6/6** |
| `ruyihttp-0.9.0-py3-none-manylinux_2_39_x86_64.whl` | 14 | 有 `platforms` 段 | **14/14** |

**26 个原生文件全部 hash 匹配**，且三个 wheel 都是新 manifest 结构。

## 重建命令

```bash
cd submodules/ruyihttp

# 本机平台
python -m pip wheel --no-build-isolation --no-deps -w dist .

# 交叉构建
RUYIHTTP_PLATFORM=win_amd64   python -m pip wheel --no-build-isolation --no-deps -w dist .
RUYIHTTP_PLATFORM=darwin_arm64 python -m pip wheel --no-build-isolation --no-deps -w dist .
RUYIHTTP_PLATFORM=linux_x86_64 RUYIHTTP_GLIBC=2.39 \
  python -m pip wheel --no-build-isolation --no-deps -w dist .
```

## 已知限制

- 重建出的 wheel **未做 live 验证**：本机 glibc 2.35 < 2.38，`libnecko_core.so` 无法 `dlopen`。
  hash 匹配只证明「wheel 里的文件与 manifest 记录一致」，不证明「能跑」。
- `linux_aarch64` / `darwin_x86_64` 仍无二进制，需要对应平台构建。
