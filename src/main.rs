/*!
 * serverstats_grab: Linux Server I/O/CPU/Memory Telemetry Capture & Analysis Tool
 * --------------------------------------------------------------------------------
 * Copyright (C) 2025 Laurence Oberman <loberman@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * ChatGPT (OpenAI) assisted with the design, implementation, and documentation of this tool,
 * including code, algorithms, documentation, and reporting logic.
 *
 * --------------------------------------------------------------------------------
 * DESCRIPTION:
 *
 * `serverstats_grab` is an open-source, Rust-based telemetry tool for Linux servers,
 * providing capture, playback, and graphical analysis of disk, CPU, and memory metrics.
 *
 * FEATURES:
 *  - Collects `/proc/diskstats`, `/proc/stat`, and `/proc/meminfo` at user-defined intervals,
 *    writing a unified `.dat` capture file.
 *  - Playback modes for each metric with clear, human-readable output (disk IOPS, CPU%, Mem%).
 *  - Analysis mode generates per-device and system-level SVG/PNG graphs and a dynamic HTML dashboard
 *    for instant, browser-based review.
 *  - Handles sparse data, missing metrics, and idle periods gracefully.
 *  - Output directory is self-contained—just copy and open `index.html` in any browser.
 *
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


    After running the -a analyze option you can cd to the directory
    Then run this python lightweight web server and browse the analysis data:
    python3 -m http.server 8080

    Please note! playback | more or less will see a thread main stack panic on quit
    This can be safely ignored, it is how stdout works with Rust.

 * AUTHOR:
 *    Laurence Oberman <loberman@redhat.com>
 *    With code, ideas, and documentation support from ChatGPT (OpenAI)
 */

mod analyze;
mod mpath;

// Increment as tool evolves
const VERSION_NUMBER: &str = "4.0.1";

use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write, Read},
    collections::HashMap,
    env,
    thread::sleep,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use chrono::{Local, TimeZone, Timelike};
use hostname::get;

/// Represents a single sample from /proc/diskstats for one block device.
#[derive(Debug, Clone)]
pub struct DiskStat {
    /// Device major number (kernel driver family)
    pub major: u32,
    /// Device minor number (unique per device)
    pub minor: u32,
    /// Device name (e.g., sda, nvme0n1, dm-0)
    pub name: String,
    /// Reads completed successfully
    pub reads: u64,
    /// Reads merged
    pub reads_merged: u64,
    /// Sectors read
    pub sectors_read: u64,
    /// Time spent reading (ms)
    pub read_time_ms: u64,
    /// Writes completed
    pub writes: u64,
    /// Writes merged
    pub writes_merged: u64,
    /// Sectors written
    pub sectors_written: u64,
    /// Time spent writing (ms)
    pub write_time_ms: u64,
    /// I/Os currently in progress
    pub io_in_progress: u64,
    /// Time spent doing I/Os (ms)
    pub io_time_ms: u64,
    /// Weighted time spent doing I/Os (ms)
    pub weighted_io_time_ms: u64,
    pub discards: u64,
    pub discards_merged: u64,
    pub sectors_discarded: u64,
    pub discard_time_ms: u64,
}

impl DiskStat {
    /// Parses a line from `/proc/diskstats` into a `DiskStat`.
    fn from_line(line: &str) -> Option<Self> {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 18 { return None; }
        Some(Self {
            major: cols[0].parse().ok()?,
            minor: cols[1].parse().ok()?,
            name: cols[2].to_string(),
            reads: cols[3].parse().ok()?,
            reads_merged: cols[4].parse().ok()?,
            sectors_read: cols[5].parse().ok()?,
            read_time_ms: cols[6].parse().ok()?,
            writes: cols[7].parse().ok()?,
            writes_merged: cols[8].parse().ok()?,
            sectors_written: cols[9].parse().ok()?,
            write_time_ms: cols[10].parse().ok()?,
            io_in_progress: cols[11].parse().ok()?,
            io_time_ms: cols[12].parse().ok()?,
            weighted_io_time_ms: cols[13].parse().ok()?,
            discards: cols[14].parse().ok()?,
            discards_merged: cols[15].parse().ok()?,
            sectors_discarded: cols[16].parse().ok()?,
            discard_time_ms: cols[17].parse().ok()?,
        })
    }
    /// Parses a CSV field slice (from capture file) into a `DiskStat`.
    fn from_csv_fields(fields: &[&str]) -> Option<Self> {
        if fields.len() < 18 { return None; }
        Some(Self {
            major: fields[0].parse().ok()?,
            minor: fields[1].parse().ok()?,
            name: fields[2].to_string(),
            reads: fields[3].parse().ok()?,
            reads_merged: fields[4].parse().ok()?,
            sectors_read: fields[5].parse().ok()?,
            read_time_ms: fields[6].parse().ok()?,
            writes: fields[7].parse().ok()?,
            writes_merged: fields[8].parse().ok()?,
            sectors_written: fields[9].parse().ok()?,
            write_time_ms: fields[10].parse().ok()?,
            io_in_progress: fields[11].parse().ok()?,
            io_time_ms: fields[12].parse().ok()?,
            weighted_io_time_ms: fields[13].parse().ok()?,
            discards: fields[14].parse().ok()?,
            discards_merged: fields[15].parse().ok()?,
            sectors_discarded: fields[16].parse().ok()?,
            discard_time_ms: fields[17].parse().ok()?,
        })
    }
}

fn sanitize_latency(v: f64) -> f64 {
    if !v.is_finite() || v > 60000.0 {
        0.0
    } else {
        v
    }
}

/// Gathers disk, CPU, and memory stats at the requested interval and appends to output file.
fn gather(interval: u64, out_path: &str) -> std::io::Result<()> {
    let mut out = OpenOptions::new()
        .create(true)
        .append(true)
        .open(out_path)?;

    // Print header only if file is empty
    if out.metadata()?.len() == 0 {
        writeln!(out, "#TYPE,ts_epoch,<fields...>")?;
    }

    loop {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // --- DISK ---
        let file = File::open("/proc/diskstats")?;
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            if let Some(stat) = DiskStat::from_line(&line) {
                if stat.name.starts_with("sd") || stat.name.starts_with("nvme") || stat.name.starts_with("dm-") || stat.name.starts_with("loop")
                    || stat.name.starts_with("emcpower") || stat.name.starts_with("vd") || stat.name.starts_with("rbd") || stat.name.starts_with("md") || stat.name.starts_with("scini")
                {
                    writeln!(
                        out,
                        "DISK,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                        now,
                        stat.major,
                        stat.minor,
                        stat.name,
                        stat.reads,
                        stat.reads_merged,
                        stat.sectors_read,
                        stat.read_time_ms,
                        stat.writes,
                        stat.writes_merged,
                        stat.sectors_written,
                        stat.write_time_ms,
                        stat.io_in_progress,
                        stat.io_time_ms,
                        stat.weighted_io_time_ms,
                        stat.discards,
                        stat.discards_merged,
                        stat.sectors_discarded,
                        stat.discard_time_ms
                    )?;
                }

            }
        }
/* 
Field	Name	Description
1	user	Time spent on normal processes executing in user mode.
2	nice	Time spent on low-priority (niced) processes executing in user mode.
3	system	Time spent on processes executing in kernel mode (system calls, etc.).
4	idle	Time spent in the idle task (CPU has nothing to do).
5	iowait	Time spent waiting for I/O to complete.
6	irq	Time spent servicing hardware interrupts.
7	softirq	Time spent servicing software interrupts (e.g., network processing).
8	steal	Stolen time. Time spent on other guests by the hypervisor (only relevant in virtualized environments like Xen/KVM).
9	guest	Time spent running a virtual CPU for a guest OS (non-niced). Note: This time is already included in the user field.
10	guest_nice	Time spent running a niced virtual CPU for a guest OS (low-priority). Note: This time is already included in 
the nice field.
 */
        // --- CPU ---
        if let Ok(mut stat_file) = File::open("/proc/stat") {
            let mut buf = String::new();
            stat_file.read_to_string(&mut buf)?;
            let mut procs_running: Option<u64> = None;
            let mut procs_blocked: Option<u64> = None;
            let mut cpu_vals: Vec<&str> = Vec::new();
            let mut intr_total: Option<u64> = None;
            let mut ctxt_total: Option<u64> = None;
            let mut processes_total: Option<u64> = None;

            for line in buf.lines() {
                if line.starts_with("cpu ") {
                    cpu_vals = line.split_whitespace().collect();
                } else if line.starts_with("procs_running") {
                    procs_running = line.split_whitespace().nth(1).and_then(|v| v.parse().ok());
                } else if line.starts_with("procs_blocked") {
                    procs_blocked = line.split_whitespace().nth(1).and_then(|v| v.parse().ok());
                }
                else if line.starts_with("intr ") {
                intr_total = line.split_whitespace().nth(1).and_then(|v| v.parse().ok());
                 } else if line.starts_with("ctxt ") {
                     ctxt_total = line.split_whitespace().nth(1).and_then(|v| v.parse().ok());
                 } else if line.starts_with("processes ") {
                     processes_total = line.split_whitespace().nth(1).and_then(|v| v.parse().ok());
                }
            }
            if cpu_vals.len() >= 10 {
                writeln!(out, "CPU,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                    now,
                    cpu_vals[1], cpu_vals[2], cpu_vals[3], cpu_vals[4], cpu_vals[5],
                    cpu_vals[6], cpu_vals[7], cpu_vals[8], cpu_vals[9],
                    procs_running.unwrap_or(0), procs_blocked.unwrap_or(0),
                    intr_total.unwrap_or(0),
                    ctxt_total.unwrap_or(0),
                    processes_total.unwrap_or(0)
                )?;
            }

            // --- Per CPU gather (SAFE V4.1 extension) ---
        if let Ok(mut stat_file) = File::open("/proc/stat") {
            let mut buf = String::new();
            stat_file.read_to_string(&mut buf)?;

            for line in buf.lines() {

                // skip system aggregate "cpu "
                if line.starts_with("cpu") && !line.starts_with("cpu ") {

                    let cpu_vals: Vec<&str> = line.split_whitespace().collect();

                    if cpu_vals.len() >= 10 {

                        let cpu_id = cpu_vals[0].trim_start_matches("cpu");

                        writeln!(out,
                            "PCPU,{},{},{},{},{},{},{},{},{},{},{}",
                            now,
                            cpu_id,
                            cpu_vals[1], // user
                            cpu_vals[2], // nice
                            cpu_vals[3], // system
                            cpu_vals[4], // idle
                            cpu_vals[5], // iowait
                            cpu_vals[6], // irq
                            cpu_vals[7], // softirq
                            cpu_vals[8], // steal
                            cpu_vals[9]  // guest
                        )?;
                    }
                }
            }
        }

        }

        // --- MEM ---
        if let Ok(mem_file) = File::open("/proc/meminfo") {
            let reader = BufReader::new(mem_file);
            let mut values = HashMap::new();
            for line in reader.lines().flatten() {
                let mut parts = line.split_whitespace();
                if let (Some(key), Some(val)) = (parts.next(), parts.next()) {
                    values.insert(key.trim_end_matches(':').to_string(), val.to_string());
                }
            }
            writeln!(out, "MEM,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                now,
                values.get("MemTotal").unwrap_or(&"0".to_string()),
                values.get("MemFree").unwrap_or(&"0".to_string()),
                values.get("MemAvailable").unwrap_or(&"0".to_string()),
                values.get("Buffers").unwrap_or(&"0".to_string()),
                values.get("Cached").unwrap_or(&"0".to_string()),
                values.get("SwapTotal").unwrap_or(&"0".to_string()),
                values.get("SwapFree").unwrap_or(&"0".to_string()),
                values.get("Dirty").unwrap_or(&"0".to_string()),
                values.get("Writeback").unwrap_or(&"0".to_string()),
                values.get("Active(file)").unwrap_or(&"0".to_string()),
                values.get("Inactive(file)").unwrap_or(&"0".to_string()),
                values.get("Slab").unwrap_or(&"0".to_string()),
                values.get("KReclaimable").unwrap_or(&"0".to_string()),
                values.get("SReclaimable").unwrap_or(&"0".to_string()),
            )?;
        }

                // --- NET ---
        if let Ok(file) = File::open("/proc/net/dev") {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten().skip(2) { // skip header lines
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 17 {
                    // Format: iface: rx_bytes ... tx_bytes ... etc
                    // E.g. ["eth0:", "123", "0", ... "456", ...]
                    let iface = parts[0].trim_end_matches(':');
                    let rx_bytes   = parts[1];
                    let rx_packets = parts[2];
                    let rx_errors  = parts[3];
                    let rx_dropped = parts[4];
                    let tx_bytes   = parts[9];
                    let tx_packets = parts[10];
                    let tx_errors  = parts[11];
                    let tx_dropped = parts[12];

                    writeln!(
                        out,
                        "NET,{},{},{},{},{},{},{},{},{},{}",
                        now, iface,
                        rx_bytes, tx_bytes,
                        rx_packets, tx_packets,
                        rx_errors, tx_errors,
                        rx_dropped, tx_dropped
                    )?;
                }
            }
        }

        out.flush()?;
        sleep(Duration::from_secs(interval));
    }
}

/// Playback disk stats from a previously captured file, printing interval-by-interval deltas.


/// Playback disk stats from a previously captured file, printing interval-by-interval deltas.
/// Now supports filtering output to a given time window (seconds since midnight).
fn playback_disk(
    file_path: &str,
    from_sec: Option<u32>,
    to_sec: Option<u32>,
    show_discards: bool
) -> std::io::Result<()> {

    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    let mut prev: HashMap<String, (u64, DiskStat)> = HashMap::new();
    let mut printed_header = false;

    for line in reader.lines().flatten() {

        if line.starts_with("#TYPE") || line.starts_with('#') {
            continue;
        }

        let mut cols = line.split(',');
        let typ = cols.next().unwrap_or("");

        if typ != "DISK" {
            continue;
        }

        let ts = cols.next().unwrap_or("0").parse::<u64>().unwrap_or(0);
        let fields: Vec<&str> = cols.collect();

        if let Some(stat) = DiskStat::from_csv_fields(&fields) {

            let key = format!("{}-{}-{}", stat.major, stat.minor, stat.name);

            if let Some((last_ts, last_stat)) = prev.get(&key) {

                let dt = ts.saturating_sub(*last_ts);
                if dt == 0 {
                    continue;
                }

                let d_reads = stat.reads.saturating_sub(last_stat.reads);
                let d_reads_merged = stat.reads_merged.saturating_sub(last_stat.reads_merged);
                let d_writes = stat.writes.saturating_sub(last_stat.writes);
                let d_writes_merged = stat.writes_merged.saturating_sub(last_stat.writes_merged);

                let d_sectors_written =
                    stat.sectors_written.saturating_sub(last_stat.sectors_written);

                let d_sectors_read =
                    stat.sectors_read.saturating_sub(last_stat.sectors_read);

                let delta_weighted_io_time_ms =
                    stat.weighted_io_time_ms.saturating_sub(last_stat.weighted_io_time_ms);

                let avg_queue_depth =
                    delta_weighted_io_time_ms as f64 / (dt as f64 * 1000.0);

                let delta_io_time_ms =
                    stat.io_time_ms.saturating_sub(last_stat.io_time_ms);

                let qlen = if delta_io_time_ms > 0 {
                    delta_weighted_io_time_ms as f64 / delta_io_time_ms as f64
                } else {
                    0.0
                };

                let r_s = d_reads as f64 / dt as f64;
                let w_s = d_writes as f64 / dt as f64;

                // Skip idle disks (no IO activity)
                if d_reads == 0 && d_writes == 0 {
                    prev.insert(key, (ts, stat));
                    continue;
                }
                let rd_sec_s = d_sectors_read as f64 / dt as f64;
                let wr_sec_s = d_sectors_written as f64 / dt as f64;

                let rd_kbs = rd_sec_s * 512.0 / 1024.0;
                let wr_kbs = wr_sec_s * 512.0 / 1024.0;

                let await_read_ms = sanitize_latency(
                    if d_reads > 0 {
                        (stat.read_time_ms.saturating_sub(last_stat.read_time_ms)) as f64 / d_reads as f64
                    } else { 0.0 }
                );

                let await_write_ms = sanitize_latency(
                    if d_writes > 0 {
                        (stat.write_time_ms.saturating_sub(last_stat.write_time_ms)) as f64 / d_writes as f64
                    } else { 0.0 }
                );

                let total_ios = d_reads + d_writes;

                let svctim = if total_ios > 0 {
                    delta_io_time_ms as f64 / total_ios as f64
                } else {
                    0.0
                };

                let d_discards = stat.discards.saturating_sub(last_stat.discards);
                let d_discards_merged =
                    stat.discards_merged.saturating_sub(last_stat.discards_merged);

                let d_sectors_discarded =
                    stat.sectors_discarded.saturating_sub(last_stat.sectors_discarded);

                let d_discard_ms =
                    stat.discard_time_ms.saturating_sub(last_stat.discard_time_ms);

                let sectors_discarded_s =
                    d_sectors_discarded as f64 / dt as f64;

                let discard_kbs = sectors_discarded_s * 512.0 / 1024.0;

                let await_discard_ms = sanitize_latency(
                   if d_discards > 0 {
                       d_discard_ms as f64 / d_discards as f64
                    } else {
                        0.0
                    }
                );

                let avg_rd_kb = if d_reads > 0 {
                    (d_sectors_read as f64 * 512.0 / 1024.0) / d_reads as f64
                } else { 0.0 };

                let avg_wr_kb = if d_writes > 0 {
                    (d_sectors_written as f64 * 512.0 / 1024.0) / d_writes as f64
                } else { 0.0 };

                let dt_obj = Local.timestamp_opt(ts as i64, 0).single().unwrap();

                let t_hms = dt_obj.format("%H:%M:%S").to_string();

                let secs_since_midnight =
                    dt_obj.hour() * 3600 +
                    dt_obj.minute() * 60 +
                    dt_obj.second();

                if let Some(start) = from_sec {
                    if secs_since_midnight < start {
                        continue;
                    }
                }

                if let Some(end) = to_sec {
                    if secs_since_midnight > end {
                        continue;
                    }
                }

                if !printed_header {

                    if show_discards {

                        println!(
"{:<10} {:<8} {:<10} {:<5} {:>10} {:>12} {:>10} {:>14} {:>12} {:>12} {:>10} {:>10} {:>12} {:>12} {:>10} {:>12} {:>12} {:>10} {:>14} {:>14} {:>14} {:>14}",
"Device","Time","Epoch","Δt","ΔReads","ΔReadsMerg","ΔWrites","ΔWritesMerg","AvgQDepth","Qlen","r/s","w/s","rd_kB/s","wr_kB/s","svctim","await_rd(ms)","await_wr(ms)","Discards","DiscardsM","Discardssecs","DiscardsKBS","await_dis(ms)"
                        );

                    } else {

                        println!(
"{:<10} {:<8} {:<5} {:>10} {:>10} {:>12} {:>10} {:>10} {:>10} {:>10} {:>12} {:>12} {:>12} {:>12}",
"Device","Time","Δt","ΔReads","ΔWrites","Qlen","r/s","w/s","rd_kB/s","wr_kB/s","await_rd(ms)","await_wr(ms)","avg_rd_kB","avg_wr_kB"
                        );
                    }

                    printed_header = true;
                }

                if show_discards {

                    println!(
"{:<10} {:<8} {:<10} {:<5} {:>10} {:>12} {:>10} {:>14} {:>12.2} {:>12.2} {:>10.2} {:>10.2} {:>12.2} {:>12.2} {:>10.2} {:>12.2} {:>12.2} {:>10} {:>14} {:>14} {:>14.2} {:>14.2}",
stat.name,t_hms,ts,dt,
d_reads,d_reads_merged,d_writes,d_writes_merged,
avg_queue_depth,qlen,
r_s,w_s,rd_kbs,wr_kbs,svctim,
await_read_ms,await_write_ms,
d_discards,d_discards_merged,d_sectors_discarded,
discard_kbs,await_discard_ms
                    );

                } else {

                    println!(
"{:<10} {:<8} {:<5} {:>10} {:>10} {:>12.2} {:>10.2} {:>10.2} {:>10.2} {:>10.2} {:>12.2} {:>12.2} {:>12.2} {:>12.2}",
stat.name,
t_hms,
dt,
d_reads,
d_writes,
qlen,
r_s,
w_s,
rd_kbs,
wr_kbs,
await_read_ms,
await_write_ms,
avg_rd_kb,
avg_wr_kb
                    );
                }
            }

            prev.insert(key, (ts, stat));
        }
    }

    if !printed_header {
        println!("No disk data found.");
    }

    Ok(())
}

/*
V4 CPU Capture Format:

CPU,ts,
user,nice,system,idle,iowait,irq,softirq,steal,guest,
running,
blocked,
intr,
ctxt,
processes

Notes:
- guest time is already included in user (kernel accounting)
- guest_nice already included in nice
- intr/ctxt/processes are cumulative since boot and must be delta’d per interval
*/

fn playback_cpu(file_path: &str) -> std::io::Result<()> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    // prev = ts, cpu_vals[0..8], guest, intr, ctxt, processes
    let mut prev: Option<(u64, Vec<u64>, u64, u64, u64, u64)> = None;
    let mut printed_header = false;

    for line in reader.lines().flatten() {
        if line.starts_with("#TYPE") || line.starts_with('#') { continue; }

        let fields: Vec<&str> = line.split(',').collect();
        if fields.get(0) != Some(&"CPU") { continue; }

        // V4 requires 16 fields
        if fields.len() < 16 { continue; }

        let ts = fields[1].parse::<u64>().unwrap_or(0);

        // user..steal
        let vals: Vec<u64> =
            fields[2..10].iter().filter_map(|v| v.parse::<u64>().ok()).collect();

        if vals.len() < 8 { continue; }

        let current_guest = fields[10].parse::<u64>().unwrap_or(0);
        let running       = fields[11].parse::<u64>().unwrap_or(0);
        let blocked       = fields[12].parse::<u64>().unwrap_or(0);
        let intr          = fields[13].parse::<u64>().unwrap_or(0);
        let ctxt          = fields[14].parse::<u64>().unwrap_or(0);
        let processes     = fields[15].parse::<u64>().unwrap_or(0);

        if let Some((last_ts, last_vals, last_guest, last_intr, last_ctxt, last_proc)) = &prev {

            let dt = ts.saturating_sub(*last_ts);
            if dt == 0 {
                prev = Some((ts, vals, current_guest, intr, ctxt, processes));
                continue;
            }

            // V3-correct total (guest included)
            let total_vals_diff: u64 =
                vals.iter().zip(last_vals.iter()).map(|(v, lv)| v - lv).sum();

            let total = (total_vals_diff +
                current_guest.saturating_sub(*last_guest)) as f64;

            if total == 0.0 {
                prev = Some((ts, vals, current_guest, intr, ctxt, processes));
                continue;
            }

            let inv = 100.0 / total;

            let user   = (vals[0] - last_vals[0]) as f64 * inv;
            let nice   = (vals[1] - last_vals[1]) as f64 * inv;
            let sys    = (vals[2] - last_vals[2]) as f64 * inv;
            let iowait = (vals[4] - last_vals[4]) as f64 * inv;
            let irq    = (vals[5] - last_vals[5]) as f64 * inv;
            let soft   = (vals[6] - last_vals[6]) as f64 * inv;
            let steal  = (vals[7] - last_vals[7]) as f64 * inv;
            let guest  = (current_guest.saturating_sub(*last_guest)) as f64 * inv;

            let idle = 100.0 -
                (user + nice + sys + iowait +
                 irq + soft + steal + guest);

            // NEW V4 RATES
            let intr_s = intr.saturating_sub(*last_intr) as f64 / dt as f64;
            let ctxt_s = ctxt.saturating_sub(*last_ctxt) as f64 / dt as f64;
            let proc_s = processes.saturating_sub(*last_proc) as f64 / dt as f64;

            if !printed_header {
                println!(
"{:<8} {:<10} {:<5} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>10} {:>10} {:>10} {:>6} {:>6}",
"Time","Epoch","Δt",
"User%","Nice%","Sys%","Wait%","IRQ%","Soft%","Steal%","Guest%","Idle%",
"Intr/s","Ctx/s","Proc/s","Run","Blk"
                );
                printed_header = true;
            }

            let dt_obj =
                chrono::Local.timestamp_opt(ts as i64, 0).single().unwrap();
            let t_hms = dt_obj.format("%H:%M:%S").to_string();

            println!(
"{:<8} {:<10} {:<5} {:>8.2} {:>8.2} {:>8.2} {:>8.2} {:>8.2} {:>8.2} {:>8.2} {:>8.2} {:>8.2} {:>10.2} {:>10.2} {:>10.2} {:>6} {:>6}",
t_hms, ts, dt,
user, nice, sys, iowait,
irq, soft, steal, guest, idle,
intr_s, ctxt_s, proc_s,
running, blocked
            );
        }

        prev = Some((ts, vals, current_guest, intr, ctxt, processes));
    }

    if !printed_header {
        println!("No CPU data found.");
    }

    Ok(())
}

fn playback_percpu(
    file_path: &str,
    cpu_filter: Option<u32>,
    top_n: Option<usize>
) -> std::io::Result<()> {

    use std::collections::HashMap;
    use chrono::TimeZone;

    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    // cpu_id -> Vec<(ts, vals)>
    let mut per_cpu: HashMap<u32, Vec<(u64, Vec<u64>)>> = HashMap::new();

    for line in reader.lines().flatten() {
        if line.starts_with('#') { continue; }

        let fields: Vec<&str> = line.split(',').collect();
        if fields.get(0) != Some(&"PCPU") { continue; }
        if fields.len() < 12 { continue; }

        let ts = fields[1].parse::<u64>().unwrap_or(0);
        let cpu_id = fields[2].parse::<u32>().unwrap_or(0);

        let vals: Vec<u64> = fields[3..12]
            .iter()
            .filter_map(|v| v.parse::<u64>().ok())
            .collect();

        if vals.len() < 9 { continue; }

        per_cpu.entry(cpu_id).or_default().push((ts, vals));
    }

    // --- TOP MODE ---
    if let Some(top) = top_n {

        let mut avg_busy: Vec<(u32, f64)> = Vec::new();

        for (cpu, samples) in &per_cpu {
            if samples.len() < 2 { continue; }

            let mut busy_sum = 0.0;
            let mut count = 0;

            for w in samples.windows(2) {
                let (_, last) = &w[0];
                let (_, curr) = &w[1];

                let total: u64 = curr.iter().zip(last.iter())
                    .map(|(c,l)| c.saturating_sub(*l))
                    .sum();

                if total == 0 { continue; }

                let busy =
                    curr[0].saturating_sub(last[0]) +
                    curr[1].saturating_sub(last[1]) +
                    curr[2].saturating_sub(last[2]) +
                    curr[4].saturating_sub(last[4]) +
                    curr[5].saturating_sub(last[5]) +
                    curr[6].saturating_sub(last[6]) +
                    curr[7].saturating_sub(last[7]) +
                    curr[8].saturating_sub(last[8]);

                busy_sum += (busy as f64 / total as f64) * 100.0;
                count += 1;
            }

            if count > 0 {
                avg_busy.push((*cpu, busy_sum / count as f64));
            }
        }

        avg_busy.sort_by(|a,b| b.1.partial_cmp(&a.1).unwrap());

        println!("Top {} CPUs by Avg Busy:", top);
        for (cpu, val) in avg_busy.iter().take(top) {
            println!("CPU{:>3}  {:>6.2}%", cpu, val);
        }
        return Ok(());
    }

    // --- NORMAL MODE ---
    println!(
        "{:<8} {:<10} {:<4} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7}",
        "Time","Epoch","CPU","User%","Sys%","Idle%","Wait%","IRQ%","Soft%","Steal%","Guest%"
    );

    for (cpu, samples) in per_cpu {

        if let Some(filter) = cpu_filter {
            if cpu != filter { continue; }
        }

        if samples.len() < 2 { continue; }

        for w in samples.windows(2) {

            let (last_ts, last_vals) = &w[0];
            let (ts, vals) = &w[1];

            let dt = ts.saturating_sub(*last_ts);
            if dt == 0 { continue; }

            let total: u64 = vals.iter().zip(last_vals.iter())
                .map(|(c,l)| c.saturating_sub(*l))
                .sum();

            if total == 0 { continue; }

            let inv = 100.0 / total as f64;

            let user   = (vals[0]-last_vals[0]) as f64 * inv;
            let sys    = (vals[2]-last_vals[2]) as f64 * inv;
            let idle   = (vals[3]-last_vals[3]) as f64 * inv;
            let wait   = (vals[4]-last_vals[4]) as f64 * inv;
            let irq    = (vals[5]-last_vals[5]) as f64 * inv;
            let soft   = (vals[6]-last_vals[6]) as f64 * inv;
            let steal  = (vals[7]-last_vals[7]) as f64 * inv;
            let guest  = (vals[8]-last_vals[8]) as f64 * inv;

            let dt_obj = chrono::Local.timestamp_opt(*ts as i64,0).single().unwrap();
            let t = dt_obj.format("%H:%M:%S");

            println!(
                "{:<8} {:<10} {:<4} {:>7.2} {:>7.2} {:>7.2} {:>7.2} {:>7.2} {:>7.2} {:>7.2} {:>7.2}",
                t, ts, cpu, user, sys, idle, wait, irq, soft, steal, guest
            );
        }
    }
    Ok(())
}

fn playback_percpu_by_time(
    file_path: &str,
    cpu_filter: Option<u32>
) -> std::io::Result<()> {

    use std::collections::{BTreeMap, HashMap};
    use chrono::{Local, TimeZone};
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    // ts -> cpu -> vals
    let mut by_time: BTreeMap<u64, HashMap<u32, Vec<u64>>> = BTreeMap::new();

    for line in reader.lines().flatten() {
        if line.starts_with('#') { continue; }

        let fields: Vec<&str> = line.split(',').collect();
        if fields.get(0) != Some(&"PCPU") { continue; }
        if fields.len() < 12 { continue; }

        let ts = fields[1].parse::<u64>().unwrap_or(0);
        let cpu_id = fields[2].parse::<u32>().unwrap_or(0);

        if let Some(filter) = cpu_filter {
            if cpu_id != filter { continue; }
        }

        let vals: Vec<u64> = fields[3..12]
            .iter()
            .filter_map(|v| v.parse::<u64>().ok())
            .collect();

        if vals.len() < 9 { continue; }

        by_time
            .entry(ts)
            .or_default()
            .insert(cpu_id, vals);
    }

    println!(
"{:<8} {:>10} {:>4} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7}",
"Time","Epoch","CPU","User%","Sys%","Idle%","Wait%","IRQ%","Soft%","Steal%","Guest%"
    );

    let mut prev: HashMap<u32, Vec<u64>> = HashMap::new();

    for (ts, cpu_map) in &by_time {

        // --- SORT CPU IDs ---
        let mut cpu_keys: Vec<u32> = cpu_map.keys().cloned().collect();
        cpu_keys.sort_unstable();

        for cpu in cpu_keys {

            let curr = cpu_map.get(&cpu).unwrap();

            if let Some(last) = prev.get(&cpu) {

                let total: u64 = curr.iter().zip(last.iter())
                    .map(|(c,l)| c.saturating_sub(*l))
                    .sum();

                if total == 0 { continue; }

                let delta = |i: usize| curr[i].saturating_sub(last[i]) as f64;
                let pct   = |i: usize| (delta(i) / total as f64) * 100.0;

                let time_str = Local.timestamp_opt(*ts as i64,0)
                    .unwrap()
                    .format("%H:%M:%S")
                    .to_string();

                println!(
"{:<8} {:>10} {:>4} {:>7.2} {:>7.2} {:>7.2} {:>7.2} {:>7.2} {:>7.2} {:>7.2} {:>7.2}",
time_str, ts, cpu,
pct(0), pct(1), pct(3), pct(2),
pct(5), pct(6), pct(7), pct(8)
                );
            }

            prev.insert(cpu, curr.clone());
        }
    }

    Ok(())
}

/// Playback memory stats from a previously captured file.
/// Enhanced V4-style output (percent + human-friendly GiB/MB columns)
fn playback_mem(file_path: &str) -> std::io::Result<()> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut printed_header = false;

    // Convert helpers
    let kb_to_gib = |kb: f64| kb / 1024.0 / 1024.0;
    let kb_to_mb  = |kb: f64| kb / 1024.0;

    for line in reader.lines().flatten() {
        if line.starts_with("#TYPE") || line.starts_with('#') { continue; }

        let mut cols = line.split(',');
        let typ = cols.next().unwrap_or("");
        if typ != "MEM" { continue; }

        let ts = cols.next().unwrap_or("0").parse::<u64>().unwrap_or(0);

        // These match your gather() MEM writeln ordering
        let keys = [
            "MemTotal","MemFree","MemAvailable","Buffers","Cached",
            "SwapTotal","SwapFree","Dirty","Writeback",
            "Active(file)","Inactive(file)","Slab","KReclaimable","SReclaimable"
        ];

        let mut vals: HashMap<String, u64> = HashMap::new();
        for (k, v) in keys.iter().zip(cols) {
            vals.insert((*k).to_string(), v.parse::<u64>().unwrap_or(0));
        }

        // Raw kB
        let mem_total_kb = *vals.get("MemTotal").unwrap_or(&0) as f64;
        let mem_free_kb  = *vals.get("MemFree").unwrap_or(&0) as f64;
        let mem_avail_kb = *vals.get("MemAvailable").unwrap_or(&0) as f64;
        let buff_kb      = *vals.get("Buffers").unwrap_or(&0) as f64;
        let cache_kb     = *vals.get("Cached").unwrap_or(&0) as f64;
        let slab_kb      = *vals.get("Slab").unwrap_or(&0) as f64;
        let inact_kb     = *vals.get("Inactive(file)").unwrap_or(&0) as f64;
        let krecl_kb     = *vals.get("KReclaimable").unwrap_or(&0) as f64;

        let swap_total_kb = *vals.get("SwapTotal").unwrap_or(&0) as f64;
        let swap_free_kb  = *vals.get("SwapFree").unwrap_or(&0) as f64;
        let dirty_kb      = *vals.get("Dirty").unwrap_or(&0) as f64;
        let wback_kb      = *vals.get("Writeback").unwrap_or(&0) as f64;

        // Percents
        let used_kb = (mem_total_kb - mem_free_kb).max(0.0);

        let used_percent   = if mem_total_kb > 0.0 { used_kb     / mem_total_kb * 100.0 } else { 0.0 };
        let avail_percent  = if mem_total_kb > 0.0 { mem_avail_kb/ mem_total_kb * 100.0 } else { 0.0 };
        let cached_percent = if mem_total_kb > 0.0 { cache_kb    / mem_total_kb * 100.0 } else { 0.0 };
        let free_percent   = if mem_total_kb > 0.0 { mem_free_kb / mem_total_kb * 100.0 } else { 0.0 };

        // GiB columns
        let mem_gib   = kb_to_gib(mem_total_kb);
        let used_gib  = kb_to_gib(used_kb);
        let avail_gib = kb_to_gib(mem_avail_kb);
        let buff_gib  = kb_to_gib(buff_kb);
        let cache_gib = kb_to_gib(cache_kb);
        let slab_gib  = kb_to_gib(slab_kb);
        let inact_gib = kb_to_gib(inact_kb);
        let krecl_gib = kb_to_gib(krecl_kb);

        let swap_gib  = kb_to_gib(swap_total_kb);
        let swap_used = kb_to_gib((swap_total_kb - swap_free_kb).max(0.0));

        // MB columns
        let dirty_mb = kb_to_mb(dirty_kb);
        let wb_mb    = kb_to_mb(wback_kb);

        if !printed_header {
            println!(
                "{:<8} {:<10} {:>7} {:>7} {:>7} {:>7} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>8} {:>8}",
                "Time","Epoch","Used%","Avail%","Cached%","Free%","MemGiB","UsedGiB","AvailGiB","BuffGiB","CacheGiB",
                "SlabGiB","InactGiB","KReclGiB","SwapGiB","SwapUsed","DirtyMB","WBackMB"
            );
            printed_header = true;
        }

        let dt_obj = Local.timestamp_opt(ts as i64, 0).single().unwrap();
        let t_hms = dt_obj.format("%H:%M:%S").to_string();

        println!(
            "{:<8} {:<10} {:>7.2} {:>7.2} {:>7.2} {:>7.2} {:>9.2} {:>9.2} {:>9.2} {:>9.2} {:>9.2} {:>9.2} {:>9.2} {:>9.2} {:>9.2} {:>9.2} {:>8.2} {:>8.2}",
            t_hms, ts,
            used_percent, avail_percent, cached_percent, free_percent,
            mem_gib, used_gib, avail_gib, buff_gib, cache_gib,
            slab_gib, inact_gib, krecl_gib,
            swap_gib, swap_used,
            dirty_mb, wb_mb
        );
    }

    if !printed_header {
        println!("No MEM data found.");
    }
    Ok(())
}


/// Playback network stats from a previously captured file.
/// Shows per-interface deltas for each interval.
fn playback_net(file_path: &str) -> std::io::Result<()> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    use std::collections::HashMap;
    let mut prev: HashMap<String, (u64, [u64; 8])> = HashMap::new(); // iface -> (ts, [fields])
    let mut printed_header = false;

    for line in reader.lines().flatten() {
        if line.starts_with("#TYPE") || line.starts_with('#') { continue; }
        let mut cols = line.split(',');
        let typ = cols.next().unwrap_or("");
        if typ != "NET" { continue; }
        let ts = cols.next().unwrap_or("0").parse::<u64>().unwrap_or(0);
        let iface = cols.next().unwrap_or("unknown").to_string();
        let fields: Vec<u64> = cols.take(8).map(|v| v.parse::<u64>().unwrap_or(0)).collect();
        if fields.len() < 8 { continue; }
        let [rx_bytes, tx_bytes, rx_packets, tx_packets, rx_errs, tx_errs, rx_drop, tx_drop] = match fields.as_slice() {
            [a,b,c,d,e,f,g,h] => [*a,*b,*c,*d,*e,*f,*g,*h],
            _ => continue,
        };
        if let Some((last_ts, last_vals)) = prev.get(&iface) {
            let dt = ts.saturating_sub(*last_ts);
            if dt == 0 { continue; }
            let drx_bytes = rx_bytes.saturating_sub(last_vals[0]);
            let dtx_bytes = tx_bytes.saturating_sub(last_vals[1]);
            let drx_packets = rx_packets.saturating_sub(last_vals[2]);
            let dtx_packets = tx_packets.saturating_sub(last_vals[3]);
            let drx_errs = rx_errs.saturating_sub(last_vals[4]);
            let dtx_errs = tx_errs.saturating_sub(last_vals[5]);
            let drx_drop = rx_drop.saturating_sub(last_vals[6]);
            let dtx_drop = tx_drop.saturating_sub(last_vals[7]);

            // Print header on first output row
            if !printed_header {
                println!(
                    "{:<10} {:<8} {:<10} {:<10} {:<10} {:<10} {:<10} {:<10} {:<10} {:<10}",
                    "Iface", "Time", "Epoch", "rx_kB/s", "tx_kB/s", "rx_pkts", "tx_pkts", "rx_err", "tx_err", "drop"
                );
                printed_header = true;
            }
            let t_hms = chrono::Local.timestamp_opt(ts as i64, 0).single().unwrap().format("%H:%M:%S").to_string();
            println!(
                "{:<10} {:<8} {:<10} {:<10.2} {:<10.2} {:<10} {:<10} {:<10} {:<10} {:<10}",
                iface, t_hms, ts,
                drx_bytes as f64 / dt as f64 / 1024.0,
                dtx_bytes as f64 / dt as f64 / 1024.0,
                drx_packets, dtx_packets, drx_errs, dtx_errs, drx_drop + dtx_drop
            );
        }
        prev.insert(iface, (ts, [rx_bytes, tx_bytes, rx_packets, tx_packets, rx_errs, tx_errs, rx_drop, tx_drop]));
    }
    if !printed_header {
        println!("No NET data found.");
    }
    Ok(())
}


/// Prints command-line usage and exits with code 1.
fn usage() {
    println!("serverstats_grab {}", VERSION_NUMBER);
    eprintln! (
"Usage:
    serverstats_grab -g <interval_seconds>                            # Gather mode (all metrics)
    serverstats_grab -g <interval_seconds> -o <output path>           # Gather mode (all metrics)
    serverstats_grab -pD <capturefile>                                # Playback DISK
    serverstats_grab -pD --from HH:MM:SS --to HH:MM:SS <capturefile>  # Playback DISK time window
    serverstats_grab -pD --discards <capturefile>                     # Playback DISK full width
    serverstats_grab -pC <capturefile>                                # Playback CPU
    serverstats_grab -pperCpu <capturefile>                           # Per CPU metrics
    serverstats_grab -ptperCpu <capturefile>                          # Per CPU metrics grouped by time (collectl like)
    serverstats_grab -pperCpu --cpu 3 <capturefile>                   # filter for CPU 3
    serverstats_grab -pperCpu --top 10 <capturefile>                  # top 10 busy CPUS
    serverstats_grab -pM <capturefile>                                # Playback MEM
    serverstats_grab -pN <capturefile>                                # Playback NET
    serverstats_grab -a <capturefile>                                 # Analysis mode (graphs + dashboard)
    serverstats_grab -pMpath <multipath-ll.txt> <capturefile.dat>     # Multipath IO/KB/sec summary

    After running the -a analyze option you can cd to the directory
    Then run this python lightweight web server and browse the analysis data:
    python3 -m http.server 8080

    Please note! playback | more or less will see a thread main stack panic on quit
    This can be safely ignored, it is how stdout works with Rust.
"
    );
}

/// Main program entrypoint and argument parser.

fn parse_time_hms(s: &str) -> Option<u32> {
    // Require exactly two colons (HH:MM:SS)
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 {
        eprintln!("ERROR: Time must be in HH:MM:SS format (e.g. 13:15:01)");
        usage();
        std::process::exit(1);
    }
    let h = parts[0].parse::<u32>().ok()?;
    let m = parts[1].parse::<u32>().ok()?;
    let s = parts[2].parse::<u32>().ok()?;
    if h > 23 || m > 59 || s > 59 {
        eprintln!("ERROR: Time must be in valid HH:MM:SS range");
        usage();
        std::process::exit(1);
    }
    Some(h * 3600 + m * 60 + s)
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
        std::process::exit(1);
   }

    match args[1].as_str() {
       "-g" => {
            let interval = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);

            // [OUTPUT DIR PATCH START]
            // Find optional -o <output_dir>
            let mut output_dir = ".".to_string(); // default is current directory
            let mut i = 3; // Start after "-g <interval>"
            while i < args.len() {
                if args[i] == "-o" && i+1 < args.len() {
                    output_dir = args[i+1].clone();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            let ts = Local::now().format("%Y-%m-%d_%H-%M-%S");
            let hostname = get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown".to_string());
            let fname = format!("serverstats_grab-{}-{}.dat", hostname, ts);

            // [OUTPUT DIR PATCH] Prepend output_dir if not "."
            let fullpath = if output_dir == "." {
                fname.clone()
            } else {
                format!("{}/{}", output_dir.trim_end_matches('/'), fname)
            };

            println!("Writing to file: {}", fullpath);
            gather(interval, &fullpath)
        }
        "-pD" => {
            // Argument parsing for optional --from and --to
            let mut from_sec = None;
            let mut to_sec = None;
            let mut file_arg: Option<String> = None;
            let mut i = 2; // Start at 2 because 0 is prog, 1 is -pD
            let mut show_discards = false; 
            while i < args.len() {
                match args[i].as_str() {
                    "--discards" => {
                        show_discards = true;
                        i += 1;
                    }
                    "--from" if i+1 < args.len() => {
                        from_sec = parse_time_hms(&args[i+1]);
                        i += 2;
                    }
                    "--to" if i+1 < args.len() => {
                        to_sec = parse_time_hms(&args[i+1]);
                        i += 2;
                    }
                    s if !s.starts_with("--") => {
                        file_arg = Some(s.to_string());
                        i += 1;
                    }
                    _ => { i += 1; }
                }
            }
            let file_path = file_arg.as_deref().unwrap_or("serverstats_grab.dat");
            playback_disk(file_path, from_sec, to_sec, show_discards)
        }

        "-pC" => {
            let fname = args.get(2).map(|s| s.as_str()).unwrap_or("serverstats_grab.dat");
            playback_cpu(fname)
        }
        "-pperCpu" => {

    let mut cpu_filter: Option<u32> = None;
    let mut top_n: Option<usize> = None;
    let mut file_arg: Option<String> = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--cpu" if i+1 < args.len() => {
                cpu_filter = args[i+1].parse().ok();
                i += 2;
            }
            "--top" if i+1 < args.len() => {
                top_n = args[i+1].parse().ok();
                i += 2;
            }
            s => {
                file_arg = Some(s.to_string());
                i += 1;
            }
        }
    }

    let fname = file_arg.as_deref().unwrap_or("serverstats_grab.dat");
    playback_percpu(fname, cpu_filter, top_n)
}
        "-ptperCpu" => {
            if args.len() < 3 {
                eprintln!("Usage: {} -ptperCpu <file>", args[0]);
                std::process::exit(1);
            }
            return playback_percpu_by_time(&args[2], None);
        }

        "-pM" => {
            let fname = args.get(2).map(|s| s.as_str()).unwrap_or("serverstats_grab.dat");
            playback_mem(fname)
        }
        "-pN" => {
            let fname = args.get(2).map(|s| s.as_str()).unwrap_or("serverstats_grab.dat");
            playback_net(fname)
        }

        "-a" => {
            let fname = args.get(2).map(|s| s.as_str()).unwrap_or("serverstats_grab.dat");
            analyze::analyze(fname)
        }
            "-pMpath" => {
        let mp_ll = args.get(2).expect("multipath-ll.txt required");
        let dat = args.get(3).expect("capturefile.dat required");
        mpath::report_mpath_stats(mp_ll, dat)
        }

        _ => {
            usage();
            std::process::exit(1);
        }
    }
}

