# udev-standalone

A **clean-room** device manager that merges two worlds. Licensed under
[TBWTFPL](https://github.com/Capricornus007/tbwtfpl/blob/main/LICENSE)
(The Better WTFPL, v114514) — the only license used across this account.

- **mdevd side** — listens on the kernel netlink uevent socket
  (`NETLINK_KOBJECT_UEVENT`, multicast group 1), the same primitive
  skarnet's mdevd uses. No systemd, no init coupling.
- **udevd side** — parses the real `/etc/udev/rules.d/*.rules` grammar
  (the rich rule language: `SUBSYSTEM`/`KERNEL`/`ACTION`/`ENV{}` matching,
  `==`/`!=`/`=`/`+=`/`:=` operators, `MODE`/`OWNER`/`GROUP` actions).

## Status (milestone 10)

- [x] netlink uevent listener (kernel → userspace)
- [x] rules.d parser + matcher (`SUBSYSTEM`/`KERNEL`/`ACTION`/`ENV{}`)
- [x] device node creation with `MODE`/`OWNER`/`GROUP`
- [x] netlink monitor rebroadcast (multicast group 4, for libudev clients)
- [x] persistent device DB (`/run/udev/data/cMAJ:MIN`, udev-compatible layout)
- [ ] `udev_queue_*` seqnum state machine
- [x] rules.d directory loading (lexical merge of `*.rules`)
- [x] `ATTR{}` match, `SYMLINK` create, `TAG` record (udev_enumerate ready)
- [x] **unified `udev` binary** — daemon + admin tool (`trigger`/`settle`/`info`/`control`) in one
- [x] live reload on `SIGHUP` (+ standard `/run/udev.pid`)
- [x] **`udev monitor`** subcommand — netlink listener for kernel uevents (grp1) and daemon replay (grp4), mirrors `udevadm monitor`
- [x] standard udev runtime paths (`/run/udev/data`, `/run/udev.pid`) for drop-in universality
- [x] pending-event counter (seed of the `udev_queue_*` state machine)
- [x] rule actions: `PROGRAM` (capture stdout → `RESULT`), `IMPORT{program|file}` (parse KEY=VALUE into env), `RUN` (execute on event)
- [x] rule control flow: `GOTO`/`LABEL` (shared `process_uevent()` used by daemon + `--test`)
- [x] hwdb text-database query (`udev hwdb --query=MODALIAS [--value]`) + `IMPORT{hwdb}` rule action
- [x] builtin dispatch (`IMPORT{builtin}="name"`) + `net_id` (ID_NET_NAME_PATH / ID_NET_NAME_MAC)
- [x] builtin `path_id` (ID_PATH / ID_PATH_TAG from PCI+USB topology)
- [x] builtin `blkid` (ID_FS_TYPE via magic sniff; ext4 UUID/label) — no libblkid dependency
- [x] `udev_queue_*` seed in the daemon — monotonic udev seqnum + `/run/udev/queue` (SEQNUM / QUEUE_LENGTH); kernel seqnum read from `/sys/kernel/uevent_seqnum`
- [x] **full libudev ABI (the 17 missing symbols) in the companion repo `libudev-standalone`** (route Y): `udev_queue_*` + `udev_device_*` + `udev_enumerate_*` + `udev_monitor_*` + `udev_list_entry_*`, drop-in linkable for Y-libudev. No libsystemd/libblkid dependency.

## Status (milestone 12 — daemon→libudev end-to-end)

- [x] `UDEV_RUNDIR` env override for all runtime state (device DB + queue), mirroring the
      same variable `libudev-standalone` reads — one shared fake/test root surface
- [x] `udev apply <uevent-file>` subcommand — process a synthetic uevent and **write the real
      device DB + queue** (not just print), so a libudev client can read it without root/netlink
- [x] rules directory resolved relative to the executable (and `/etc/udev/rules.d`), so the
      daemon no longer depends on the caller's CWD
- [x] device-node creation skipped in `apply`/`--test` mode (no `/dev` mutation), builtins still run
- [x] **`udev apply` builds a self-contained fake `/dev` tree under `UDEV_RUNDIR`** (node
      + symlink + parent dirs), so a fake root is fully inspectable without root
- [x] **`udev queue` subcommand** — print the daemon's queue state (SEQNUM / QUEUE_LENGTH)
      from the rundir, drop-in for `udevadm settle` status reads; honors `UDEV_RUNDIR`
- [x] **`udev verify <rules-file|dir>...` subcommand** — syntax-check rules (unbalanced
      quotes / missing operator / unknown key), non-zero exit on error; mirrors `udevadm verify`
- [x] **`udev test <syspath|uevent-file>` subcommand** — dry-run the rule engine against a
      real `/sys` device (synthesises the uevent from sysfs) or a synthetic uevent file,
      printing matched rules and builtin results without writing anything; mirrors `udevadm test`
- [x] **`udev test-builtin <builtin> <syspath|uevent-file>` subcommand** — run a single
      builtin (`net_id`/`path_id`/`blkid`) against a device and print the environment
      it produces, dry-run only; mirrors `udevadm test-builtin`
- [x] **real udev database layout** — keys `b/c MAJOR:MINOR`, `nIFINDEX` (network),
      `+subsystem:sysname` (everything else); writes `S:` devlinks, `I:` init time,
      `E:` properties, `G:`/`Q:` tags, so network and non-devnum devices persist too
- [x] **argv[0] personalities** — the same ELF dispatches as `udevd` / `systemd-udevd`
      (daemon), `udevadm <command>` (admin), and `udev-hwdb <update|query <alias>>`
      (hwdb), matching systemd's single-binary layout so symlinks are drop-in
- [x] **proven end-to-end**: `udev-standalone/test/` + `libudev-standalone/test/integration.sh`
      runs the daemon `apply` then reads the produced DB with a libudev-only `udevinfo`
      (by name and by devnum), asserting `ID_PATH`, `ID_FS_TYPE`, queue state, the
      fake `/dev` node, `udev verify`, `udev test`, `udev test-builtin`, and argv[0]
      personalities — 30/30 checks pass

## Build & test

    make
    ./udev --test test/uevent-sample.txt    # parse + rules, no root needed
    sudo ./udev                             # real daemon (needs CAP_NET_ADMIN)
