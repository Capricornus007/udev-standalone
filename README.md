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

## Status (milestone 6)

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
- [ ] hwdb lookups, builtins (net_id / path_id / blkid)
- [ ] full `udev_queue_*` seqnum state machine (the 17 symbols Y-libudev needs)

## Build & test

    make
    ./udev --test test/uevent-sample.txt    # parse + rules, no root needed
    sudo ./udev                             # real daemon (needs CAP_NET_ADMIN)
