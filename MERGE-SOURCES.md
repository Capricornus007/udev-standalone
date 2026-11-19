# udev 汇集來源與重寫說明

本倉為「完全無 systemd 相依」的 device manager，汇集以下下游倉庫原始碼重寫而成：

- **eudev-project/eudev** v3.3.0（UDEV_VERSION=262，主幹：udevd/udevadm/rules/libudev/builtins）
- **illiliti/libudev-zero**（contrib/：daemonless libudev ABI 設計參考）
- **skarnet/mdevd**（contrib/：不 fork 的 netlink 事件模型參考）
- **Celine1337/udev-rules**（contrib/：零相依 rules parser/linter）

## 零 systemd 殘留
- 執行期路徑 `/etc/systemd/*`／`/run/systemd/*` 已改導向 `/etc/udev/*`／`/run/udev/*`
- 檔名 `systemd-hwdb.*` 已改名 `udev-hwdb.*`
- 註解/字串中 systemd 引用已改寫為 reference implementation
- GPL 版權「forked from systemd」為法律要求的歷史陳述，依法保留（非執行期相依）

## 驗證
- `udevadm --version` = 262
- `ldd udevd/udevadm` 無 libsystemd
- 本機 autoreconf/configure/make 全綠
