# serverstats_grab

**Linux Server Telemetry & Analysis Tool (Disk/CPU/Memory)**  
_By Laurence Oberman · GPL v3 · Rust · Graphs & HTML Dashboard_

---

## Overview

**serverstats_grab** is a modern, open-source telemetry tool for Linux servers, capturing key I/O, CPU,NET and memory stats to a single capture file, with rich playback and browser-based analysis.


- **Capture Mode:** Samples `/proc/diskstats`, `/proc/stat`, `/proc/meminfo` at your interval.
- **Playback Mode:** Prints per-interval deltas for disk, CPU, or memory with readable columns.
- **Analysis Mode:** Generates SVG/PNG graphs and a dynamic HTML dashboard (just open `index.html`).
- **Zero dependencies:** Just Rust and Plotters. Output is portable, readable anywhere.

> **Authored by:** Laurence Oberman (`loberman@redhat.com`)  
> **AI Copilot:** Documentation and code generation support by ChatGPT (OpenAI)

---


   serverstats_grab: Linux Server I/O/CPU/Memory Telemetry Capture & Analysis Tool
   --------------------------------------------------------------------------------
   Copyright (C) 2025 Laurence Oberman <loberman@redhat.com>
  
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
  
   ChatGPT (OpenAI) assisted with the design, implementation, and documentation of this tool,
   including code, algorithms, documentation, and reporting logic.
  
   --------------------------------------------------------------------------------
   DESCRIPTION:
  
   `serverstats_grab` is an open-source, Rust-based telemetry tool for Linux servers,
   providing capture, playback, and graphical analysis of disk, CPU, and memory metrics.
 *
 * FEATURES:
 *  - Collects `/proc/diskstats`, `/proc/stat`, and `/proc/meminfo` at user-defined intervals,
 *    writing a unified `.dat` capture file.
 *  - Playback modes for each metric with clear, human-readable output (disk IOPS, CPU%, Mem%).
 *  - Analysis mode generates per-device and system-level SVG/PNG graphs and a dynamic HTML dashboard
 *    for instant, browser-based review.
 *  - Handles sparse data, missing metrics, and idle periods gracefully.
 *  - Output directory is self-contained—just copy and open `index.html` in any browser.
  
    After running the -a analyze option you can cd to the directory
    Then run this python lightweight web server and browse the analysis data:
    python3 -m http.server 8080

    Please note! playback | more or less will see a thread main stack panic on quit
    This can be safely ignored, it is how stdout works with Rust.

   AUTHOR:
      Laurence Oberman <loberman@redhat.com>
      With code, ideas, and documentation support from ChatGPT (OpenAI)

## Usage examples

```sh
 * Usage:
    serverstats_grab -g <interval_seconds>                            # Gather mode (all metrics)
    serverstats_grab -g <interval_seconds> -o <output path>           # Gather mode (all metrics)
    serverstats_grab -pD <capturefile>                                # Playback DISK
    serverstats_grab -pD --from HH:MM:SS --to HH:MM:SS <capturefile>  # Playback DISK time window
    serverstats_grab -pC <capturefile>                                # Playback CPU
    serverstats_grab -pperCpu <capturefile>                           # Per CPU metrics
    serverstats_grab -ptperCpu <capturefile>                          # Per CPU metrics grouped by time (collectl like)
    serverstats_grab -pperCpu --cpu 3 <capturefile>                   # filter for CPU 3
    serverstats_grab -pperCpu --top 10 <capturefile>                  # top 10 busy CPUS
    serverstats_grab -pM <capturefile>                                # Playback MEM
    serverstats_grab -pN <capturefile>                                # Playback NET
    serverstats_grab -a <capturefile>                                 # Analysis mode (graphs + dashboard)
    serverstats_grab -pMpath <multipath-ll.txt> <capturefile.dat>     # Multipath IO/KB/sec summary

