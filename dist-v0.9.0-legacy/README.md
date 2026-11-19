# 归档：0.9.0 旧 wheel

这两个 wheel 是私有树**改造前**的产物，与当前 `native/` 目录已脱钩：

- `ruyihttp-0.9.0-py3-none-win_amd64.whl` 的 `runtime-manifest.json` 是旧结构
  （`{version, platform, sha256}`），文件直接放在包根 `ruyihttp/*.dll`，
  没有 `platforms` 段。
- `ruyihttp-0.9.0-py3-none-macosx_26_0_arm64.whl` 的 dylib 哈希与
  `native/darwin_arm64/provenance.json` **全部不符**，且**缺 `libnecko_quic.dylib`**。
- 从未有 `linux` wheel。

**不要把它们当作可发布的产物。** 当前三平台 wheel 应从 `native/` 重新构建：

```bash
python -m pip wheel --no-build-isolation --no-deps -w dist .
```

Windows 得到 `py3-none-win_amd64`，macOS arm64 得到
`py3-none-macosx_26_0_arm64`，glibc ≥ 2.38 的 Linux 得到
`py3-none-manylinux_2_39_x86_64`。

保留这两个文件的原因：它们是 0.9.0 原始发布物的唯一副本，用于对照
「改造前的 wheel 长什么样」。
