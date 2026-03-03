# serverstats_grab

**Linux Server Telemetry & Analysis Tool (Disk/CPU/Memory)**  
_By Laurence Oberman · GPL v3 · Rust · Graphs & HTML Dashboard_

---

## Overview
Version 3.0.0

**serverstats_grab** is a modern, open-source telemetry tool for Linux servers, capturing key I/O, CPU,NET and memory stats to a single capture file, with rich playback and browser-based analysis.


- **Capture Mode:** Samples `/proc/diskstats`, `/proc/stat`, `/proc/meminfo` at your interval.
- **Playback Mode:** Prints per-interval deltas for disk, CPU, or memory with readable columns.
- **Analysis Mode:** Generates SVG/PNG graphs and a dynamic HTML dashboard (just open `index.html`).
- **Zero dependencies:** Just Rust and Plotters. Output is portable, readable anywhere.

> **Authored by:** Laurence Oberman (`loberman@redhat.com`)  
> **AI Copilot:** Documentation and code generation support by ChatGPT (OpenAI)

---

## Usage examples

```sh
serverstats_grab -g <interval_seconds>
    # Gather mode (writes serverstats_grab-YYYY-MM-DD_HH-MM-SS.dat)

serverstats_grab -pD <capturefile>
    # Playback DISK stats (showing deltas, queue depth, IOPS, etc.)

serverstats_grab -pC <capturefile>
    # Playback CPU stats (user/sys/idle/iowait %)

serverstats_grab -pM <capturefile>
    # Playback MEMORY stats (% used/available/cached)

serverstats_grab -pN <capturefile>
    # Playback NETWORK stats 

serverstats_grab -a <capturefile>
    # Analyze mode: writes SVG/PNG graphs and index.html dashboard

serverstats_grab -pMpath <multipath-ll.txt> <capturefile.dat>     # Multipath IO/KB/sec summary
    # Create a multipath path usage balance report
