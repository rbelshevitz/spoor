# spoor

[![Go](https://img.shields.io/badge/go-1.23-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![CI](https://github.com/rbelshevitz/spoor/actions/workflows/ci.yml/badge.svg)](https://github.com/rbelshevitz/spoor/actions/workflows/ci.yml)

> **See what runs. Trace why.**

A focused Linux TUI for answering one question: _why is this running?_

`spoor` is a Go process and incident explorer with no third-party runtime dependencies. It reads Linux `/proc` directly, builds a process hierarchy, maps TCP sockets to PIDs, shows cgroup boundaries, and keeps a short history of changes.

The name `spoor` is Dutch for **“track”** or **“trail.”** Every process leaves a spoor: who started it, which supervisor or container keeps it alive, which sockets belong to it, and what changed over time. `spoor` follows that trail instead of showing an isolated PID list.

## Why spoor?

`htop` is excellent at showing what is running. `spoor` is aimed at the next incident question: **what is holding this process here, what does it own, and is it changing?**

The detail view connects:

- the selected process and its ancestry;
- its cgroup boundary, including systemd or container context when visible;
- visible TCP sockets owned by the PID;
- resident-memory growth or shrink rate;
- process identity changes and restart events.

The **PID identity radar** compares Linux process `starttime` rather than relying only on the numeric PID. It reports a confirmed identity change when the same numeric PID belongs to a different process between snapshots. This is a PID-reuse signal; it does not claim to know why a service restarted.

## Interface

The main screen follows the familiar `htop` model: a live process list, visible meters, keyboard actions, tree mode, tags, sorting, and direct process actions.

The top panel shows:

- CPU usage, calculated from process CPU deltas;
- RAM and swap meters;
- load average and uptime;
- Linux PSI pressure for CPU, memory, and I/O;
- access mode: `ROOT`, `ROOT via sudo`, or `USER (uid N)`.

The Containers view appears only when Docker or Podman containers are detected.

## Keyboard controls

| Key | Action |
| --- | --- |
| `1` / `2` / `3` | Switch Processes / Ports / Containers |
| `Tab` | Next available view |
| `↑` `↓`, `j` `k` | Move selection |
| `PgUp` `PgDn`, `Ctrl-U` `Ctrl-D` | Move one page |
| `g` / `G` | First / last row |
| `F1` / `?` | Help |
| `F3` / `/` | Live search |
| `F4` | Start search/filter mode |
| `F5` / `t` | Toggle process tree |
| `F6` / `s` | Cycle sort order |
| `m` | Sort by resident memory |
| `c` | Sort by CPU |
| `Space` | Tag/untag a process |
| `p` | Pin/unpin the selected process at the top |
| `Enter` | Open process details and ancestry |
| `F9` / `x` | Prepare `TERM`; `y` confirms, `n` cancels |
| `L` | Open the incident timeline |
| `d` | Toggle incident diff from the startup baseline |
| `r` | Request an immediate refresh |
| `e` | Export `spoor-snapshot.json` |
| `h` | Export `spoor-report.html` |
| `q` | Quit and restore the terminal |

Search is case-insensitive substring matching. It updates after every character and searches the fields of the current view. Examples: `/nginx`, `/8080`, `/listen`.

`SLEEP` means that a process is alive and waiting for an event; it is not an error state. The CPU column is calculated from the change in `utime + stime` between snapshots. Each CPU bar block represents roughly 12.5% of one core.

## Timeline and incident evidence

`L` opens a short flight recorder containing:

- process and socket counts for each refresh;
- new and exited process identities;
- PID reuse/restart events;
- CPU, memory, and I/O PSI;
- the point at which pressure or process churn started.

PSI is stall time caused by contention, not ordinary CPU utilization. A spike can indicate that runnable work, memory reclaim, or I/O was waiting for a resource.

## JSON and HTML reports

JSON is the machine-readable snapshot for `jq`, shell scripts, CI, and agents:

```bash
./spoor --pid 1234 --json | jq '.ancestry'
./spoor --port 8080 --json > incident.json
jq '.processes[] | select(.rss | endswith("M"))' incident.json
```

The HTML export is for humans and incident sharing:

```bash
./spoor --html incident.html
```

It contains a static summary, access mode, PSI, the 30 largest processes by RSS, TCP sockets, and containers when present. Open it in any browser or attach it to an incident.

## Usage

```bash
go run .
go build -buildvcs=false -o spoor .
./spoor
./spoor --pid 1234
./spoor --port 8080
./spoor --pid 1234 --json
./spoor --html incident.html
```

If your Go toolchain reports `error obtaining VCS status`, use `-buildvcs=false` as shown above. This disables build-time VCS stamping; it does not affect runtime process inspection.

## What makes spoor different

The goal is not to become another general-purpose resource monitor. The distinctive direction is causal incident analysis.

Implemented today:

- **Causal path:** process → parent → supervisor/cgroup/container → socket.
- **Process context:** show the selected process's cgroup boundary, memory trend, ancestry, and visible TCP sockets.
- **PID identity radar:** detect process identity changes and PID reuse.
- **Pressure-aware view:** put PSI beside process changes to explain why a machine feels stuck.

Planned extensions:

- **Blast radius:** show the sockets and descendants affected by a selected process.
- **Evidence ledger:** distinguish confirmed `/proc` facts from inferred relationships.
- **Counterfactual actions:** before stopping a process, show what may disappear and which supervisor may restart it.
- **Repro bundle:** export JSON plus a redacted Markdown incident summary.

## Architecture

- Standard-library Go and one binary.
- Background snapshot collection so `/proc`, file-descriptor, socket, and container scans do not block input or rendering.
- Linux `/proc` as the primary data source.
- Best-effort Docker and Podman discovery.
- JSON as a stable integration surface.

The current implementation is Linux-first. Visibility of other users' processes, file descriptors, and sockets depends on kernel permissions. Run as root when full visibility is required.

## Русская версия

`spoor` — быстрый Linux TUI, который помогает понять, почему запущен процесс, кто его породил, какой cgroup или контейнер удерживает его живым и какие TCP-сокеты ему принадлежат. Название `spoor` по-нидерландски означает «след» или «трасса».

Главный экран сделан в парадигме `htop`: список процессов, индикаторы ресурсов, дерево, поиск, сортировка, метки, закрепление и действия через функциональные клавиши. `t` включает дерево, `L` открывает timeline, `F9` подготавливает завершение процесса, `e` экспортирует JSON, `h` — HTML-отчёт.
