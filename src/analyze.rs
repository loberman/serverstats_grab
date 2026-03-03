/*!
 * serverstats_grab: Analysis Module
 * ---------------------------------
 * Copyright (C) 2024 Laurence Oberman <loberman@redhat.com>
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
 * ----------------------------------------------------------------------
 *  This module implements analysis and visualization for
 *  serverstats_grab telemetry capture files. It processes
 *  captured data (DISK, CPU, MEM sections), generates per-device
 *  and per-metric graphs, and writes a rich HTML dashboard for
 *  interactive exploration in any browser.
 *
 *  All output is self-contained in a new output directory.
 *  - Disk graphs: per device & metric (SVG + PNG)
 *  - CPU and Memory: single chart each (SVG + PNG)
 *  - "Top 50" tables for disk metrics (avg/peak)
 *  - Dynamic index.html for browsing
 */

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::collections::HashMap;
use plotters::prelude::*;
use crate::DiskStat;
use chrono::TimeZone;

// ==================== Structs ====================

/// Per-interval computed disk metrics for plotting/stats
#[derive(Debug, Clone)]
pub struct IntervalDiskMetrics {
    ts: u64,
    pub(crate) rps: f64,       // Read IOPS/sec
    pub(crate) wps: f64,       // Write IOPS/sec
    pub(crate) io_sec: f64,    // Total IO/sec
    pub(crate) rd_kbs: f64,    // Read KB/sec
    pub(crate) wr_kbs: f64,    // Write KB/sec
    pub(crate) kb_sec: f64,    // Total KB/sec
    avg_queue_depth: f64, // <-- Rename this from qlen: for your interval-based calculation
    qlen: f64,      // <-- New: collectl/iostat-style (delta_weighted_io_time / delta_io_time)
    svctim: f64,    // calclated service time
    await_rd: f64,  // Average read await (ms)
    await_wr: f64,  // Average write await (ms)
    discards_s: f64,         // New: Discard IOs/sec
    discards_merged_s: f64,  // New: Discard merges/sec
    sectors_discarded_s: f64,// New: Discard sectors/sec (or KB/sec if you like)
    discard_kbs: f64,
    await_discard_ms: f64,   // New: Discard await time (ms)
}

/// Per-interval CPU utilization summary
#[derive(Debug, Clone)]
struct CpuMetrics {
    ts: u64,
    user: f64,
    sys: f64,
    idle: f64,
    iowait: f64,
    guest: f64,
    running: Option<u64>, 
    blocked: Option<u64>,
}

/// Per-interval Memory usage summary (percentages)
#[derive(Debug, Clone)]
struct MemMetrics {
    ts: u64,
    used_percent: f64,
    avail_percent: f64,
    cached_percent: f64,
    free_percent: f64,
}

/// Per-interval computed NET metrics for plotting/stats
#[derive(Debug, Clone)]
struct IntervalNetMetrics {
    ts: u64,
    rx_bytes: f64,
    tx_bytes: f64,
    rx_pkts: f64,
    tx_pkts: f64,
    rx_errs: f64,
    tx_errs: f64,
    rx_drop: f64,
    tx_drop: f64,
}
#[derive(Debug, Clone)]
struct NetStat {
    rx_bytes: u64,
    rx_pkts: u64,
    rx_errs: u64,
    rx_drop: u64,
    tx_bytes: u64,
    tx_pkts: u64,
    tx_errs: u64,
    tx_drop: u64,
}

// ==================== Main Analyze Entrypoint ====================

/// Analyze a serverstats_grab telemetry file and write all graphs + dashboard.
/// All output goes into a new directory (named after your capture file stem).
pub fn analyze(file_path: &str) -> std::io::Result<()> {
    let output_dir = output_dir_for_datafile(file_path);
    println!("Analyzing serverstats: {}\nOutput dir: {output_dir}", file_path);
    fs::create_dir_all(&output_dir)?;
    
    // ========== Step 1: Parse all rows into Vecs ==========

    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    let mut per_device: HashMap<String, Vec<(u64, DiskStat)>> = HashMap::new();
    let mut cpu_vec: Vec<(u64, Vec<u64>, Option<u64>, Option<u64>)> = Vec::new();
    let mut mem_vec: Vec<(u64, HashMap<String, u64>)> = Vec::new();
    let mut per_net: HashMap<String, Vec<(u64, NetStat)>> = HashMap::new();
    for line in reader.lines().flatten() {
        if line.starts_with('#') { continue; }
        let mut cols = line.split(',');
        let typ = cols.next().unwrap_or("");
        if typ == "DISK" {
            let ts = cols.next().unwrap().parse::<u64>().unwrap_or(0);
            let fields: Vec<&str> = cols.collect();
            if let Some(stat) = parse_disk_from_fields(&fields) {
                per_device.entry(stat.name.clone()).or_default().push((ts, stat));
            }
        } else if typ == "CPU" {
            let ts = cols.next().unwrap().parse::<u64>().unwrap_or(0);
            // Get ALL remaining numeric fields, so we can reliably pick running/blocked from the end
            let values: Vec<u64> = cols.filter_map(|v| v.parse::<u64>().ok()).collect();
            // Defensive: expect at least 12 values (in your format there are 8 cpu fields + 2 zeros + running + blocked)
            if values.len() >= 10 {
                let vals = values.clone();   // Keep ALL CPU counters
                let running = values.get(values.len() - 2).copied();
                let blocked = values.get(values.len() - 1).copied();
                cpu_vec.push((ts, vals, running, blocked));
            }
        }
        else if typ == "MEM" {
            let ts = cols.next().unwrap().parse::<u64>().unwrap_or(0);
            let keys = [
                "MemTotal","MemFree","MemAvailable","Buffers","Cached",
                "SwapTotal","SwapFree","Dirty","Writeback","Active(file)","Inactive(file)","Slab","KReclaimable","SReclaimable"
            ];
            let mut vals = HashMap::new();
            for (k, v) in keys.iter().zip(cols) {
                vals.insert((*k).to_string(), v.parse::<u64>().unwrap_or(0));
            }
            mem_vec.push((ts, vals));
        }


else if typ == "NET" {
    let ts = cols.next().unwrap().parse::<u64>().unwrap_or(0);
    let iface = cols.next().unwrap_or("").to_string();
    // Now next 8 fields in order: rx_bytes, tx_bytes, rx_pkts, tx_pkts, rx_errs, tx_errs, rx_drop, tx_drop
    let rx_bytes = cols.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let tx_bytes = cols.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let rx_pkts  = cols.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let tx_pkts  = cols.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let rx_errs  = cols.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let tx_errs  = cols.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let rx_drop  = cols.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let tx_drop  = cols.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);

    per_net.entry(iface.clone()).or_default().push((ts, NetStat {
        rx_bytes,
        tx_bytes,
        rx_pkts,
        tx_pkts,
        rx_errs,
        tx_errs,
        rx_drop,
        tx_drop,
    }));
}

    }


    // ========== Step 2: Process raw Vecs into per-interval metric Vecs ==========

    // --- Disk Metrics ---
    let mut disk_metrics: HashMap<String, Vec<IntervalDiskMetrics>> = HashMap::new();
    for (dev, rows) in &per_device {
        let mut prev: Option<(u64, &DiskStat)> = None;
        let mut out = Vec::new();
        for (ts, stat) in rows {
            if let Some((last_ts, last_stat)) = prev {
                let dt = (*ts).saturating_sub(last_ts);
                if dt == 0 { prev = Some((*ts, stat)); continue; }
                let d_reads = stat.reads.saturating_sub(last_stat.reads);
                let d_writes = stat.writes.saturating_sub(last_stat.writes);
                let d_sectors_read = stat.sectors_read.saturating_sub(last_stat.sectors_read);
                let d_sectors_written = stat.sectors_written.saturating_sub(last_stat.sectors_written);
                let delta_weighted_io_time_ms = stat.weighted_io_time_ms.saturating_sub(last_stat.weighted_io_time_ms);
                let avg_queue_depth = delta_weighted_io_time_ms as f64 / (dt as f64 * 1000.0);
                let delta_io_time_ms = stat.io_time_ms.saturating_sub(last_stat.io_time_ms);
                let qlen = if delta_io_time_ms > 0 {
                    delta_weighted_io_time_ms as f64 / delta_io_time_ms as f64
                } else {
                    0.0
                };
                let delta_io_time_ms = stat.io_time_ms.saturating_sub(last_stat.io_time_ms);
                let total_ios = d_reads + d_writes;
                let svctim = if total_ios > 0 {
                    delta_io_time_ms as f64 / total_ios as f64
                } else {
                    0.0
                };
                let rps = d_reads as f64 / dt as f64;
                let wps = d_writes as f64 / dt as f64;
                let io_sec = rps + wps;
                let rd_kbs = d_sectors_read as f64 * 512.0 / 1024.0 / dt as f64;
                let wr_kbs = d_sectors_written as f64 * 512.0 / 1024.0 / dt as f64;
                let kb_sec = rd_kbs + wr_kbs;
                let await_read_ms = if d_reads > 0 {
                    (stat.read_time_ms.saturating_sub(last_stat.read_time_ms)) as f64 / d_reads as f64
                } else { 0.0 };
                let await_write_ms = if d_writes > 0 {
                    (stat.write_time_ms.saturating_sub(last_stat.write_time_ms)) as f64 / d_writes as f64
                } else { 0.0 };
                    let d_discards = stat.discards.saturating_sub(last_stat.discards);
                    let d_discards_merged = stat.discards_merged.saturating_sub(last_stat.discards_merged);
                    let d_sectors_discarded = stat.sectors_discarded.saturating_sub(last_stat.sectors_discarded);
                    let d_discard_time_ms = stat.discard_time_ms.saturating_sub(last_stat.discard_time_ms);
                    let sectors_discarded_s = d_sectors_discarded as f64 / dt as f64;
                    let discards_s = d_discards as f64 / dt as f64;
                    let discards_merged_s = d_discards_merged as f64 / dt as f64;
                    // If you want KB/sec for discards, multiply by 0.5 (just like you do for reads/writes if 512B sectors)
                    let discard_kbs = d_sectors_discarded as f64 * 0.5 / dt as f64;
                    let await_discard_ms = if d_discards > 0 {
                        d_discard_time_ms as f64 / d_discards as f64
                    } else { 0.0 };

                    out.push(IntervalDiskMetrics {
                        ts: *ts,
                        rps,
                        wps,
                        io_sec,
                        rd_kbs,
                        wr_kbs,
                        kb_sec,
                        avg_queue_depth,
                        qlen,
                        svctim,
                        await_rd: await_read_ms,
                        await_wr: await_write_ms,
                        discards_s,
                        discards_merged_s,
                        sectors_discarded_s,
                        await_discard_ms,
                        discard_kbs,
                    });
            }
            prev = Some((*ts, stat));
        }
        if !out.is_empty() {
            disk_metrics.insert(dev.clone(), out);
        }
    }
        // CPU Metrics
        let mut cpu_metrics: Vec<CpuMetrics> = Vec::new();
        let mut prev: Option<(u64, Vec<u64>, Option<u64>, Option<u64>)> = None;
        for (ts, vals, running, blocked) in cpu_vec {
            if let Some((_last_ts, last_vals, _, _)) = &prev {
                let total = vals.iter().zip(last_vals.iter()).map(|(v, lv)| v - lv).sum::<u64>() as f64;
                if total == 0.0 { prev = Some((ts, vals, running, blocked)); continue; }
                let user   = (vals[0] - last_vals[0]) as f64 / total * 100.0;
                let nice   = (vals[1] - last_vals[1]) as f64 / total * 100.0;
                let sys    = (vals[2] - last_vals[2]) as f64 / total * 100.0;
                let idle   = (vals[3] - last_vals[3]) as f64 / total * 100.0;
                let iowait = (vals[4] - last_vals[4]) as f64 / total * 100.0;
                let guest  = (vals[8] - last_vals[8]) as f64 / total * 100.0;
                cpu_metrics.push(CpuMetrics {
                    ts,
                    user: user + nice,
                    sys,
                    idle,
                    iowait,
                    guest,
                    running,
                    blocked,
                });
            }
            prev = Some((ts, vals, running, blocked));
        }
    // --- Memory Metrics ---
    let mut mem_metrics: Vec<MemMetrics> = Vec::new();
    for (ts, vals) in &mem_vec {
        let mem_total = *vals.get("MemTotal").unwrap_or(&1) as f64;
        let mem_free  = *vals.get("MemFree").unwrap_or(&0) as f64;
        let mem_avail = *vals.get("MemAvailable").unwrap_or(&0) as f64;
        let cached    = *vals.get("Cached").unwrap_or(&0) as f64;
        let used = mem_total - mem_free;
        let used_percent = if mem_total > 0.0 { used / mem_total * 100.0 } else { 0.0 };
        let avail_percent = if mem_total > 0.0 { mem_avail / mem_total * 100.0 } else { 0.0 };
        let cached_percent = if mem_total > 0.0 { cached / mem_total * 100.0 } else { 0.0 };
        let free_percent = if mem_total > 0.0 { mem_free / mem_total * 100.0 } else { 0.0 };
        mem_metrics.push(MemMetrics {
            ts: *ts,
            used_percent,
            avail_percent,
            cached_percent,
            free_percent,
        });
    }

    // --- NET Metrics ---
        let mut net_metrics: HashMap<String, Vec<IntervalNetMetrics>> = HashMap::new();
        for (iface, rows) in &per_net {
            let mut prev: Option<(u64, &NetStat)> = None;
            let mut out = Vec::new();
            for (ts, stat) in rows {
            if let Some((last_ts, last_stat)) = prev {
                let dt = (*ts).saturating_sub(last_ts);
                if dt == 0 { prev = Some((*ts, stat)); continue; }
                let rx_bytes = (stat.rx_bytes.saturating_sub(last_stat.rx_bytes)) as f64 / dt as f64;
                let tx_bytes = (stat.tx_bytes.saturating_sub(last_stat.tx_bytes)) as f64 / dt as f64;
                let rx_pkts  = (stat.rx_pkts.saturating_sub(last_stat.rx_pkts)) as f64 / dt as f64;
                let tx_pkts  = (stat.tx_pkts.saturating_sub(last_stat.tx_pkts)) as f64 / dt as f64;
                let rx_errs  = (stat.rx_errs.saturating_sub(last_stat.rx_errs)) as f64 / dt as f64;
                let tx_errs  = (stat.tx_errs.saturating_sub(last_stat.tx_errs)) as f64 / dt as f64;
                let rx_drop  = (stat.rx_drop.saturating_sub(last_stat.rx_drop)) as f64 / dt as f64;
                let tx_drop  = (stat.tx_drop.saturating_sub(last_stat.tx_drop)) as f64 / dt as f64;
                out.push(IntervalNetMetrics {
                    ts: *ts, rx_bytes, tx_bytes, rx_pkts, tx_pkts, rx_errs, tx_errs, rx_drop, tx_drop,
                });
            }
        prev = Some((*ts, stat));
        }
    if !out.is_empty() {
        net_metrics.insert(iface.clone(), out);
    }
}


    // ========== Step 3: Generate all graphs ==========

    // --- Disk: per device, per metric ---
    let disk_metric_defs: &[(&str, &str, Box<dyn Fn(&IntervalDiskMetrics) -> f64>)] = &[
    ("rps", "Read IOPS/sec", Box::new(|m: &IntervalDiskMetrics| m.rps)),
    ("wps", "Write IOPS/sec", Box::new(|m: &IntervalDiskMetrics| m.wps)),
    ("io_sec", "IO/sec (Total)", Box::new(|m: &IntervalDiskMetrics| m.io_sec)),
    ("rd_kbs", "Read KB/sec", Box::new(|m: &IntervalDiskMetrics| m.rd_kbs)),
    ("wr_kbs", "Write KB/sec", Box::new(|m: &IntervalDiskMetrics| m.wr_kbs)),
    ("kb_sec", "KB/sec (Total)", Box::new(|m: &IntervalDiskMetrics| m.kb_sec)),
    ("avg_queue_depth", "AvgQDepth (interval-avg)", Box::new(|m: &IntervalDiskMetrics| m.avg_queue_depth)),
    ("qlen", "QueueLen (collectl/iostat style)", Box::new(|m: &IntervalDiskMetrics| m.qlen)),
    ("svctim", "Service Time (ms)", Box::new(|m: &IntervalDiskMetrics| m.svctim)),   // <--- HERE!
    ("await_rd", "Read Await (ms)", Box::new(|m: &IntervalDiskMetrics| m.await_rd)),
    ("await_wr", "Write Await (ms)", Box::new(|m: &IntervalDiskMetrics| m.await_wr)),
    ("discards_s", "Discards/sec", Box::new(|m: &IntervalDiskMetrics| m.discards_s)),
    ("discards_merged_s", "Discard Merges/sec", Box::new(|m: &IntervalDiskMetrics| m.discards_merged_s)),
    ("sectors_discarded_s", "Discard Sectors/sec", Box::new(|m: &IntervalDiskMetrics| m.sectors_discarded_s)),
    ("await_discard_ms", "Discard Await (ms)", Box::new(|m: &IntervalDiskMetrics| m.await_discard_ms)),
    ("discard_kbs", "Discard KB/sec", Box::new(|m: &IntervalDiskMetrics| m.discard_kbs)),
];

    println!("Writing disk graphs...");
    for (dev, series) in &disk_metrics {
        for (key, label, func) in disk_metric_defs.iter() {
            plot_disk_metric(&output_dir, dev, series, &**func, label, key)?;
        }
    }

    // --- CPU (all lines on one chart) ---
    if !cpu_metrics.is_empty() {
        plot_cpu(&output_dir, &cpu_metrics)?;
        plot_running_blocked(&output_dir, &cpu_metrics)?;
    }
    // --- MEM (all lines on one chart) ---
    if !mem_metrics.is_empty() {
        plot_mem(&output_dir, &mem_metrics)?;
    }
// ===> INSERT NET GRAPHS HERE <===
let net_metric_defs: &[(&str, &str, Box<dyn Fn(&IntervalNetMetrics) -> f64>)] = &[
    ("rx_bytes", "RX Bytes/sec", Box::new(|m: &IntervalNetMetrics| m.rx_bytes)),
    ("tx_bytes", "TX Bytes/sec", Box::new(|m: &IntervalNetMetrics| m.tx_bytes)),
    ("rx_pkts", "RX Packets/sec", Box::new(|m: &IntervalNetMetrics| m.rx_pkts)),
    ("tx_pkts", "TX Packets/sec", Box::new(|m: &IntervalNetMetrics| m.tx_pkts)),
    ("rx_errs", "RX Errors/sec", Box::new(|m: &IntervalNetMetrics| m.rx_errs)),
    ("tx_errs", "TX Errors/sec", Box::new(|m: &IntervalNetMetrics| m.tx_errs)),
    ("rx_drop", "RX Drops/sec", Box::new(|m: &IntervalNetMetrics| m.rx_drop)),
    ("tx_drop", "TX Drops/sec", Box::new(|m: &IntervalNetMetrics| m.tx_drop)),
];
    println!("Writing net graphs...");
    for (iface, series) in &net_metrics {
        for (key, label, func) in net_metric_defs.iter() {
            // Debug print of actual values being plotted
            //let vals: Vec<f64> = series.iter().map(|m| func(m)).collect();
            //println!("Net graph: iface={} metric={} first5={:?}", iface, key, &vals[..std::cmp::min(5, vals.len())]);
            plot_net_metric(&output_dir, iface, series, &**func, label, key)?;
        }
    }

    // ========== Step 3.5: Write Top 50 Device Tables ==========

    // Compute summary for each device/metric
    let mut metrics_summary: HashMap<&str, Vec<(String, f64, f64)>> = HashMap::new();
    for (dev, series) in &disk_metrics {
        for (key, _label, func) in disk_metric_defs.iter() {
            let avg = mean(series, &**func);
            let max = max(series, &**func);
            metrics_summary.entry(key).or_default().push((dev.clone(), avg, max));
        }
    }

    // Write top50 txt tables
    let mut tables: Vec<String> = Vec::new();
    for (metric, entries) in &metrics_summary {
        let mut by_avg = entries.clone();
        by_avg.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        let mut by_max = entries.clone();
        by_max.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());

        let avg_fname = format!("top50_{}_avg.txt", metric);
        let max_fname = format!("top50_{}_peak.txt", metric);

        let avg_out = format!("{}/{}", output_dir, avg_fname);
        let max_out = format!("{}/{}", output_dir, max_fname);
        let mut f_avg = File::create(&avg_out)?;
        let mut f_max = File::create(&max_out)?;

        // Table headings
        writeln!(f_avg, "{fname}\nMetric: {metric} (average)\n", fname=avg_fname, metric=metric)?;
        writeln!(f_avg, "{:<5} {:<16} {:>12} {:>12}", "Rank", "Device", "Average", "Peak")?;
        writeln!(f_avg, "{}", "-".repeat(5 + 1 + 16 + 1 + 12 + 1 + 12))?;
        for (idx, (dev, avg, peak)) in by_avg.iter().take(50).enumerate() {
            writeln!(f_avg, "{:<5} {:<16} {:>12.2} {:>12.2}", idx+1, dev, avg, peak)?;
        }

        writeln!(f_max, "{fname}\nMetric: {metric} (peak)\n", fname=max_fname, metric=metric)?;
        writeln!(f_max, "{:<5} {:<16} {:>12} {:>12}", "Rank", "Device", "Average", "Peak")?;
        writeln!(f_max, "{}", "-".repeat(5 + 1 + 16 + 1 + 12 + 1 + 12))?;
        for (idx, (dev, avg, peak)) in by_max.iter().take(50).enumerate() {
            writeln!(f_max, "{:<5} {:<16} {:>12.2} {:>12.2}", idx+1, dev, avg, peak)?;
        }

        tables.push(avg_fname);
        tables.push(max_fname);
    }

    // ========== Step 4: HTML dashboard ==========

    let devices: Vec<String> = disk_metrics.keys().cloned().collect();
    let net_ifaces: Vec<String> = net_metrics.keys().cloned().collect();
    write_index_html(&output_dir, &devices, &net_ifaces, &tables, "cpu", "mem")?;
    println!("Analysis complete. See {}/ for results.", output_dir);
    Ok(())
}

// ==================== Helpers: Parsing ====================

/// Parse DiskStat from split CSV field slice (see DISK lines)
fn parse_disk_from_fields(fields: &[&str]) -> Option<DiskStat> {
    if fields.len() < 18 { return None; }
    Some(DiskStat {
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

/// Compute output directory (stem of .dat file)
fn output_dir_for_datafile(datafile: &str) -> String {
    let path = std::path::Path::new(datafile);
    let stem = path.file_stem().unwrap().to_string_lossy();
    stem.to_string()
}

// ==================== Plotters (Graphing) ====================

/// Plot one disk metric for a device (SVG + PNG)
fn plot_disk_metric<F>(
    output_dir: &str,
    dev: &str,
    series: &[IntervalDiskMetrics],
    metric: F,
    ylabel: &str,
    fname: &str,
) -> std::io::Result<()>
where
    F: Fn(&IntervalDiskMetrics) -> f64,
{
    let times: Vec<u64> = series.iter().map(|m| m.ts).collect();
    let time_labels: Vec<String> = times.iter().map(|epoch| {
        chrono::Local.timestamp_opt(*epoch as i64, 0)
            .single()
            .unwrap_or_else(|| chrono::Local.timestamp_opt(0, 0).single().unwrap())
            .format("%H:%M:%S").to_string()
    }).collect();
    let values: Vec<f64> = series.iter().map(|m| metric(m)).collect();
    if values.iter().all(|&v| v == 0.0) { return Ok(()); }
    let y_min = values.iter().cloned().fold(f64::INFINITY, f64::min).min(0.0);
    let y_max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max).max(1.0);

    // SVG
    let svg_path = format!("{}/{}_{}.svg", output_dir, dev, fname);
    {
        let backend = SVGBackend::new(&svg_path, (900, 300));
        let root = backend.into_drawing_area();
        root.fill(&WHITE).unwrap();
        let mut chart = ChartBuilder::on(&root)
            .caption(format!("{} - {}", dev, ylabel), ("sans-serif", 22))
            .margin(12)
            .x_label_area_size(30)
            .y_label_area_size(60)
            .build_cartesian_2d(0..(time_labels.len() - 1), y_min..y_max)
            .unwrap();
        chart
            .configure_mesh()
            .x_labels(8)
            .x_label_formatter(&|idx| time_labels.get(*idx).cloned().unwrap_or_default())
            .x_desc("Time (HH:MM:SS)")
            .y_desc(ylabel)
            .draw()
            .unwrap();
        chart
            .draw_series(LineSeries::new(
                (0..values.len()).map(|i| (i, values[i])),
                &BLUE,
            ))
            .unwrap();
        root.present().unwrap();
    }
    // PNG
    let png_path = format!("{}/{}_{}.png", output_dir, dev, fname);
    {
        let backend = BitMapBackend::new(&png_path, (900, 300));
        let root = backend.into_drawing_area();
        root.fill(&WHITE).unwrap();
        let mut chart = ChartBuilder::on(&root)
            .caption(format!("{} - {}", dev, ylabel), ("sans-serif", 22))
            .margin(12)
            .x_label_area_size(30)
            .y_label_area_size(60)
            .build_cartesian_2d(0..(time_labels.len() - 1), y_min..y_max)
            .unwrap();
        chart
            .configure_mesh()
            .x_labels(8)
            .x_label_formatter(&|idx| time_labels.get(*idx).cloned().unwrap_or_default())
            .x_desc("Time (HH:MM:SS)")
            .y_desc(ylabel)
            .draw()
            .unwrap();
        chart
            .draw_series(LineSeries::new(
                (0..values.len()).map(|i| (i, values[i])),
                &BLUE,
            ))
            .unwrap();
        root.present().unwrap();
    }
    Ok(())
}
fn plot_net_metric<F>(
    output_dir: &str,
    iface: &str,
    series: &[IntervalNetMetrics],
    metric: F,
    ylabel: &str,
    fname: &str,
) -> std::io::Result<()>
where
    F: Fn(&IntervalNetMetrics) -> f64,
{
    let times: Vec<u64> = series.iter().map(|m| m.ts).collect();
    let time_labels: Vec<String> = times.iter().map(|epoch| {
        chrono::Local.timestamp_opt(*epoch as i64, 0)
            .single()
            .unwrap_or_else(|| chrono::Local.timestamp_opt(0, 0).single().unwrap())
            .format("%H:%M:%S").to_string()
    }).collect();
    let values: Vec<f64> = series.iter().map(|m| metric(m)).collect();
    if values.iter().all(|&v| v == 0.0) { return Ok(()); }
    let y_min = values.iter().cloned().fold(f64::INFINITY, f64::min).min(0.0);
    let y_max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max).max(1.0);

    // SVG
    let svg_path = format!("{}/{}_{}.svg", output_dir, iface, fname);
    {
        let backend = SVGBackend::new(&svg_path, (900, 300));
        let root = backend.into_drawing_area();
        root.fill(&WHITE).unwrap();
        let mut chart = ChartBuilder::on(&root)
            .caption(format!("{} - {}", iface, ylabel), ("sans-serif", 22))
            .margin(12)
            .x_label_area_size(30)
            .y_label_area_size(60)
            .build_cartesian_2d(0..(time_labels.len() - 1), y_min..y_max)
            .unwrap();
        chart
            .configure_mesh()
            .x_labels(8)
            .x_label_formatter(&|idx| time_labels.get(*idx).cloned().unwrap_or_default())
            .x_desc("Time (HH:MM:SS)")
            .y_desc(ylabel)
            .draw()
            .unwrap();
        chart
            .draw_series(LineSeries::new(
                (0..values.len()).map(|i| (i, values[i])),
                &BLUE,
            ))
            .unwrap();
        root.present().unwrap();
    }
    // PNG
    let png_path = format!("{}/{}_{}.png", output_dir, iface, fname);
    {
        let backend = BitMapBackend::new(&png_path, (900, 300));
        let root = backend.into_drawing_area();
        root.fill(&WHITE).unwrap();
        let mut chart = ChartBuilder::on(&root)
            .caption(format!("{} - {}", iface, ylabel), ("sans-serif", 22))
            .margin(12)
            .x_label_area_size(30)
            .y_label_area_size(60)
            .build_cartesian_2d(0..(time_labels.len() - 1), y_min..y_max)
            .unwrap();
        chart
            .configure_mesh()
            .x_labels(8)
            .x_label_formatter(&|idx| time_labels.get(*idx).cloned().unwrap_or_default())
            .x_desc("Time (HH:MM:SS)")
            .y_desc(ylabel)
            .draw()
            .unwrap();
        chart
            .draw_series(LineSeries::new(
                (0..values.len()).map(|i| (i, values[i])),
                &BLUE,
            ))
            .unwrap();
        root.present().unwrap();
    }
    Ok(())
}


/// Plot all CPU metrics (user/sys/idle/iowait) in one chart, SVG + PNG

/// Plot all CPU metrics (user/sys/idle/iowait/guest) in one chart, SVG + PNG
fn plot_cpu(output_dir: &str, series: &[CpuMetrics]) -> std::io::Result<()> {
    let times: Vec<u64> = series.iter().map(|m| m.ts).collect();
    let time_labels: Vec<String> = times.iter().map(|epoch| {
        chrono::Local.timestamp_opt(*epoch as i64, 0)
            .single()
            .unwrap_or_else(|| chrono::Local.timestamp_opt(0, 0).single().unwrap())
            .format("%H:%M:%S").to_string()
    }).collect();

    let user:   Vec<f64> = series.iter().map(|m| m.user).collect();
    let sys:    Vec<f64> = series.iter().map(|m| m.sys).collect();
    let idle:   Vec<f64> = series.iter().map(|m| m.idle).collect();
    let iowait: Vec<f64> = series.iter().map(|m| m.iowait).collect();
    let guest:  Vec<f64> = series.iter().map(|m| m.guest).collect();   // <-- NEW

    let y_max = 100.0;

    for ext in &["svg", "png"] {
        let fname = format!("{}/cpu.{}", output_dir, ext);

        if *ext == "svg" {
            let backend = SVGBackend::new(&fname, (900, 300));
            let root = backend.into_drawing_area();
            root.fill(&WHITE).unwrap();

            let mut chart = ChartBuilder::on(&root)
                .caption("CPU Utilization (%)", ("sans-serif", 22))
                .margin(12)
                .x_label_area_size(30)
                .y_label_area_size(60)
                .build_cartesian_2d(0..(time_labels.len() - 1), 0.0..y_max)
                .unwrap();

            chart.configure_mesh()
                .x_labels(8)
                .x_label_formatter(&|idx| time_labels.get(*idx).cloned().unwrap_or_default())
                .x_desc("Time (HH:MM:SS)")
                .y_desc("CPU %")
                .draw()
                .unwrap();

            chart.draw_series(LineSeries::new((0..user.len()).map(|i| (i, user[i])), &RED)).unwrap()
                .label("User").legend(|(x, y)| PathElement::new(vec![(x, y), (x+25, y)], &RED));

            chart.draw_series(LineSeries::new((0..sys.len()).map(|i| (i, sys[i])), &BLUE)).unwrap()
                .label("System").legend(|(x, y)| PathElement::new(vec![(x, y), (x+25, y)], &BLUE));

            chart.draw_series(LineSeries::new((0..idle.len()).map(|i| (i, idle[i])), &GREEN)).unwrap()
                .label("Idle").legend(|(x, y)| PathElement::new(vec![(x, y), (x+25, y)], &GREEN));

            chart.draw_series(LineSeries::new((0..iowait.len()).map(|i| (i, iowait[i])), &MAGENTA)).unwrap()
                .label("IOWait").legend(|(x, y)| PathElement::new(vec![(x, y), (x+25, y)], &MAGENTA));

            // -------------------------
            // NEW: Guest CPU line
            // -------------------------
            chart.draw_series(LineSeries::new((0..guest.len()).map(|i| (i, guest[i])), &CYAN)).unwrap()
                .label("Guest").legend(|(x, y)| PathElement::new(vec![(x, y), (x+25, y)], &CYAN));

            chart.configure_series_labels()
                .background_style(&WHITE.mix(0.8))
                .border_style(&BLACK)
                .draw().unwrap();

            root.present().unwrap();

        } else {
            // ===================== PNG BACKEND =====================
            let backend = BitMapBackend::new(&fname, (900, 300));
            let root = backend.into_drawing_area();
            root.fill(&WHITE).unwrap();

            let mut chart = ChartBuilder::on(&root)
                .caption("CPU Utilization (%)", ("sans-serif", 22))
                .margin(12)
                .x_label_area_size(30)
                .y_label_area_size(60)
                .build_cartesian_2d(0..(time_labels.len() - 1), 0.0..y_max)
                .unwrap();

            chart.configure_mesh()
                .x_labels(8)
                .x_label_formatter(&|idx| time_labels.get(*idx).cloned().unwrap_or_default())
                .x_desc("Time (HH:MM:SS)")
                .y_desc("CPU %")
                .draw()
                .unwrap();

            chart.draw_series(LineSeries::new((0..user.len()).map(|i| (i, user[i])), &RED)).unwrap()
                .label("User").legend(|(x, y)| PathElement::new(vec![(x, y), (x+25, y)], &RED));

            chart.draw_series(LineSeries::new((0..sys.len()).map(|i| (i, sys[i])), &BLUE)).unwrap()
                .label("System").legend(|(x, y)| PathElement::new(vec![(x, y), (x+25, y)], &BLUE));

            chart.draw_series(LineSeries::new((0..idle.len()).map(|i| (i, idle[i])), &GREEN)).unwrap()
                .label("Idle").legend(|(x, y)| PathElement::new(vec![(x, y), (x+25, y)], &GREEN));

            chart.draw_series(LineSeries::new((0..iowait.len()).map(|i| (i, iowait[i])), &MAGENTA)).unwrap()
                .label("IOWait").legend(|(x, y)| PathElement::new(vec![(x, y), (x+25, y)], &MAGENTA));

            // -------------------------
            // NEW: Guest CPU line
            // -------------------------
            chart.draw_series(LineSeries::new((0..guest.len()).map(|i| (i, guest[i])), &CYAN)).unwrap()
                .label("Guest").legend(|(x, y)| PathElement::new(vec![(x, y), (x+25, y)], &CYAN));

            chart.configure_series_labels()
                .background_style(&WHITE.mix(0.8))
                .border_style(&BLACK)
                .draw().unwrap();

            root.present().unwrap();
        }
    }

    Ok(())
}


fn plot_running_blocked(output_dir: &str, series: &[CpuMetrics]) -> std::io::Result<()> {
    let times: Vec<u64> = series.iter().map(|m| m.ts).collect();
    let time_labels: Vec<String> = times.iter().map(|epoch| {
        chrono::Local.timestamp_opt(*epoch as i64, 0)
            .single()
            .unwrap_or_else(|| chrono::Local.timestamp_opt(0, 0).single().unwrap())
            .format("%H:%M:%S").to_string()
    }).collect();
    let running: Vec<f64> = series.iter().map(|m| m.running.unwrap_or(0) as f64).collect();
    let blocked: Vec<f64> = series.iter().map(|m| m.blocked.unwrap_or(0) as f64).collect();

    for (label, data, fname, color) in [
    ("Running Processes", &running, "running", &BLUE),
    ("Blocked Processes", &blocked, "blocked", &RED),
] {
    // SVG
    {
        let path = format!("{}/{}.svg", output_dir, fname);
        let backend = SVGBackend::new(&path, (900, 300));
        let root = backend.into_drawing_area();
        root.fill(&WHITE).unwrap();
        let mut chart = ChartBuilder::on(&root)
            .caption(label, ("sans-serif", 22))
            .margin(12)
            .x_label_area_size(30)
            .y_label_area_size(60)
            .build_cartesian_2d(0..(time_labels.len()-1), 0.0..(data.iter().cloned().fold(0./0., f64::max)+1.0))
            .unwrap();
        chart
            .configure_mesh()
            .x_labels(8)
            .x_label_formatter(&|idx| time_labels.get(*idx).cloned().unwrap_or_default())
            .x_desc("Time (HH:MM:SS)")
            .y_desc(label)
            .draw()
            .unwrap();
        chart.draw_series(LineSeries::new(
            (0..data.len()).map(|i| (i, data[i])),
            color,
        )).unwrap();
        root.present().unwrap();
    }
    // PNG
    {
        let path = format!("{}/{}.png", output_dir, fname);
        let backend = BitMapBackend::new(&path, (900, 300));
        let root = backend.into_drawing_area();
        root.fill(&WHITE).unwrap();
        let mut chart = ChartBuilder::on(&root)
            .caption(label, ("sans-serif", 22))
            .margin(12)
            .x_label_area_size(30)
            .y_label_area_size(60)
            .build_cartesian_2d(0..(time_labels.len()-1), 0.0..(data.iter().cloned().fold(0./0., f64::max)+1.0))
            .unwrap();
        chart
            .configure_mesh()
            .x_labels(8)
            .x_label_formatter(&|idx| time_labels.get(*idx).cloned().unwrap_or_default())
            .x_desc("Time (HH:MM:SS)")
            .y_desc(label)
            .draw()
            .unwrap();
        chart.draw_series(LineSeries::new(
            (0..data.len()).map(|i| (i, data[i])),
            color,
        )).unwrap();
        root.present().unwrap();
    }
}

    Ok(())
}

/// Plot all Memory metrics (% used/avail/cached) in one chart, SVG + PNG
fn plot_mem(output_dir: &str, series: &[MemMetrics]) -> std::io::Result<()> {
    let times: Vec<u64> = series.iter().map(|m| m.ts).collect();
    let time_labels: Vec<String> = times.iter().map(|epoch| {
        chrono::Local.timestamp_opt(*epoch as i64, 0)
            .single()
            .unwrap_or_else(|| chrono::Local.timestamp_opt(0, 0).single().unwrap())
            .format("%H:%M:%S").to_string()
    }).collect();
    let used: Vec<f64> = series.iter().map(|m| m.used_percent).collect();
    let avail: Vec<f64> = series.iter().map(|m| m.avail_percent).collect();
    let cached: Vec<f64> = series.iter().map(|m| m.cached_percent).collect();
    let free: Vec<f64> = series.iter().map(|m| m.free_percent).collect();

    let y_max = 100.0;

    for ext in &["svg", "png"] {
        let fname = format!("{}/mem.{}", output_dir, ext);
        if *ext == "svg" {
            let backend = SVGBackend::new(&fname, (900, 300));
            let root = backend.into_drawing_area();
            root.fill(&WHITE).unwrap();
            let mut chart = ChartBuilder::on(&root)
                .caption("Memory Utilization (%)", ("sans-serif", 22))
                .margin(12)
                .x_label_area_size(30)
                .y_label_area_size(60)
                .build_cartesian_2d(0..(time_labels.len() - 1), 0.0..y_max)
                .unwrap();
            chart
                .configure_mesh()
                .x_labels(8)
                .x_label_formatter(&|idx| time_labels.get(*idx).cloned().unwrap_or_default())
                .x_desc("Time (HH:MM:SS)")
                .y_desc("Memory %")
                .draw()
                .unwrap();

            chart.draw_series(LineSeries::new((0..used.len()).map(|i| (i, used[i])), &RED)).unwrap()
                .label("% Used").legend(|(x, y)| PathElement::new(vec![(x, y), (x+25, y)], &RED));
            chart.draw_series(LineSeries::new((0..avail.len()).map(|i| (i, avail[i])), &GREEN)).unwrap()
                .label("% Avail").legend(|(x, y)| PathElement::new(vec![(x, y), (x+25, y)], &GREEN));
            chart.draw_series(LineSeries::new((0..cached.len()).map(|i| (i, cached[i])), &BLUE)).unwrap()
                .label("% Cached").legend(|(x, y)| PathElement::new(vec![(x, y), (x+25, y)], &BLUE));
            chart.draw_series(LineSeries::new((0..free.len()).map(|i| (i, free[i])), &MAGENTA)).unwrap()
                .label("% Free").legend(|(x, y)| PathElement::new(vec![(x, y), (x+25, y)], &MAGENTA));
            chart.configure_series_labels()
                .background_style(&WHITE.mix(0.8))
                .border_style(&BLACK)
                .draw().unwrap();
            root.present().unwrap();
        } else {
            let backend = BitMapBackend::new(&fname, (900, 300));
            let root = backend.into_drawing_area();
            root.fill(&WHITE).unwrap();
            let mut chart = ChartBuilder::on(&root)
                .caption("Memory Utilization (%)", ("sans-serif", 22))
                .margin(12)
                .x_label_area_size(30)
                .y_label_area_size(60)
                .build_cartesian_2d(0..(time_labels.len() - 1), 0.0..y_max)
                .unwrap();
            chart
                .configure_mesh()
                .x_labels(8)
                .x_label_formatter(&|idx| time_labels.get(*idx).cloned().unwrap_or_default())
                .x_desc("Time (HH:MM:SS)")
                .y_desc("Memory %")
                .draw()
                .unwrap();

            chart.draw_series(LineSeries::new((0..used.len()).map(|i| (i, used[i])), &RED)).unwrap()
                .label("% Used").legend(|(x, y)| PathElement::new(vec![(x, y), (x+25, y)], &RED));
            chart.draw_series(LineSeries::new((0..avail.len()).map(|i| (i, avail[i])), &GREEN)).unwrap()
                .label("% Avail").legend(|(x, y)| PathElement::new(vec![(x, y), (x+25, y)], &GREEN));
            chart.draw_series(LineSeries::new((0..cached.len()).map(|i| (i, cached[i])), &BLUE)).unwrap()
                .label("% Cached").legend(|(x, y)| PathElement::new(vec![(x, y), (x+25, y)], &BLUE));
            chart.configure_series_labels()
                .background_style(&WHITE.mix(0.8))
                .border_style(&BLACK)
                .draw().unwrap();
            root.present().unwrap();
        }
    }
    Ok(())
}


// ==================== HTML Dashboard ====================
fn write_index_html(
    output_dir: &str,
    devices: &[String],
    netifaces: &[String],
    tables: &[String],
    _cpu: &str,
    _mem: &str,
) -> std::io::Result<()> {
    let index_path = format!("{}/index.html", output_dir);
    let mut file = File::create(index_path)?;
    let devices_js = format!(
        "window.DEVICES = [{}];",
        devices.iter().map(|d| format!("\"{}\"", d)).collect::<Vec<_>>().join(", ")
    );
    let tables_js = format!(
        "window.TABLES = [{}];",
        tables.iter().map(|t| format!("\"{}\"", t)).collect::<Vec<_>>().join(", ")
    );
    let netifaces_js = format!(
        "window.NETIFACES = [{}];",
        netifaces.iter().map(|n| format!("\"{}\"", n)).collect::<Vec<_>>().join(", ")
    );

    write!(file, r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{}</title>
  <style>
    body {{ font-family: sans-serif; margin: 2em; }}
    #controls, #net-controls {{ margin-bottom: 1em; }}
    label.metric {{ margin-right: 1em; }}
    img.graph {{ display: block; margin: 1em 0; max-width: 98vw; border: 1px solid #ccc; }}
    .section-tab {{
      cursor:pointer; 
      display:inline-block; 
      margin-right:1em; 
      padding:0.5em 1em; 
      border-radius:1em; 
      background:#ddd;
    }}
    .section-tab.active {{ background:#333; color:#fff; }}
    .section-content {{ display:none; }}
    .section-content.active {{ display:block; }}
    .table-link {{ font-size: 0.95em; margin: 0.5em 0; display: block; }}
    h2 {{ margin-top: 2em; }}
    #deviceSearch {{ width: 180px; margin-right: 1em; }}
  </style>
</head>

<body>
  <h1>{}</h1>
  <!-- TAB BAR -->
  <div id="tabs">
    <span class="section-tab active" onclick="showSection('disk')">Disk</span>
    <span class="section-tab" onclick="showSection('cpu')">CPU</span>
    <span class="section-tab" onclick="showSection('mem')">Memory</span>
    <span class="section-tab" onclick="showSection('net')">Network</span>
  </div>

  <!-- DISK SECTION -->
  <div id="disk" class="section-content active">
    <div id="controls">
      <label for="deviceSearch"><b>Device:</b></label>
      <input type="text" id="deviceSearch" placeholder="Type to filter disks...">
      <select id="deviceSelect"></select>
      <span style="margin-left:2em"><b>Metrics:</b>
        <label class="metric"><input type="checkbox" class="metric-cb" value="io_sec" checked>IO/sec</label>
        <label class="metric"><input type="checkbox" class="metric-cb" value="kb_sec" checked>KB/sec</label>
        <label class="metric"><input type="checkbox" class="metric-cb" value="rps">Read IOPS</label>
        <label class="metric"><input type="checkbox" class="metric-cb" value="wps">Write IOPS</label>
        <label class="metric"><input type="checkbox" class="metric-cb" value="rd_kbs">Read KB/s</label>
        <label class="metric"><input type="checkbox" class="metric-cb" value="wr_kbs">Write KB/s</label>
        <label class="metric"><input type="checkbox" class="metric-cb" value="avg_queue_depth">AvgQDepth</label>
        <label class="metric"><input type="checkbox" class="metric-cb" value="qlen">QueueLen</label>
        <label class="metric"><input type="checkbox" class="metric-cb" value="svctim">SvcTim (ms)</label>
        <label class="metric"><input type="checkbox" class="metric-cb" value="await_rd">Read Await (ms)</label>
        <label class="metric"><input type="checkbox" class="metric-cb" value="await_wr">Write Await (ms)</label>
        <label class="metric"><input type="checkbox" class="metric-cb" value="discards_s">Discards/sec</label>
        <label class="metric"><input type="checkbox" class="metric-cb" value="discards_merged_s">Discard Merges/sec</label>
        <label class="metric"><input type="checkbox" class="metric-cb" value="sectors_discarded_s">Discard Sectors/sec</label>
        <label class="metric"><input type="checkbox" class="metric-cb" value="discard_kbs">Discard KB/sec</label>
        <label class="metric"><input type="checkbox" class="metric-cb" value="await_discard_ms">Discard Await (ms)</label>
      </span>
    </div>
    <div id="graphs"></div>
    <hr>
    <h2>Stats Tables</h2>
    <div id="tableLinks"></div>
  </div>

  <!-- CPU SECTION -->
  <div id="cpu" class="section-content">
    <h2>CPU Utilization</h2>
    <img class="graph" src="cpu.svg" onerror="this.src='cpu.png';">
    <h2>Running Processes</h2>
    <img class="graph" src="running.svg" onerror="this.src='running.png';">
    <h2>Blocked Processes</h2>
    <img class="graph" src="blocked.svg" onerror="this.src='blocked.png';">
  </div>

  <!-- MEMORY SECTION -->
  <div id="mem" class="section-content">
    <h2>Memory Utilization</h2>
    <img class="graph" src="mem.svg" onerror="this.src='mem.png';">
  </div>

  <!-- NETWORK SECTION -->
  <div id="net" class="section-content">
    <div id="net-controls">
      <label for="ifaceSelect"><b>Interface:</b></label>
      <select id="ifaceSelect"></select>
      <span style="margin-left:2em"><b>Metrics:</b>
        <label class="metric"><input type="checkbox" class="net-metric-cb" value="rx_bytes" checked>RX Bytes/sec</label>
        <label class="metric"><input type="checkbox" class="net-metric-cb" value="tx_bytes" checked>TX Bytes/sec</label>
        <label class="metric"><input type="checkbox" class="net-metric-cb" value="rx_pkts">RX Packets/sec</label>
        <label class="metric"><input type="checkbox" class="net-metric-cb" value="tx_pkts">TX Packets/sec</label>
        <label class="metric"><input type="checkbox" class="net-metric-cb" value="rx_errs">RX Errors/sec</label>
        <label class="metric"><input type="checkbox" class="net-metric-cb" value="tx_errs">TX Errors/sec</label>
        <label class="metric"><input type="checkbox" class="net-metric-cb" value="rx_drop">RX Drops/sec</label>
        <label class="metric"><input type="checkbox" class="net-metric-cb" value="tx_drop">TX Drops/sec</label>
      </span>
    </div>
    <div id="net-graphs"></div>
  </div>

<script>
{devices_js}
{tables_js}
{netifaces_js}

function showSection(sec) {{
  document.querySelectorAll('.section-tab').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.section-content').forEach(el => el.classList.remove('active'));
  document.querySelector('.section-tab[onclick*="' + sec + '"]').classList.add('active');
  document.getElementById(sec).classList.add('active');
}}

// Populates the device dropdown, sorting alphabetically and filtering by search
function populateDeviceDropdown() {{
  const select = document.getElementById('deviceSelect');
  const search = document.getElementById('deviceSearch');
  select.innerHTML = "";
  // Get sorted device list
  let devs = (window.DEVICES || []).slice().sort((a, b) => a.localeCompare(b));
  // If searching, filter devices
  const filter = search ? search.value.toLowerCase() : "";
  if (filter) {{
    devs = devs.filter(d => d.toLowerCase().includes(filter));
  }}
  devs.forEach(dev => {{
    const opt = document.createElement('option');
    opt.value = dev;
    opt.textContent = dev;
    select.appendChild(opt);
  }});
  // Always show graphs for the first visible disk
  if (devs.length > 0) {{
    select.value = devs[0];
    showGraphs();
  }}
}}

function populateTableLinks() {{
  const div = document.getElementById('tableLinks');
  div.innerHTML = "";
  (window.TABLES || []).forEach(file => {{
    const a = document.createElement('a');
    a.href = file;
    a.textContent = file;
    a.className = "table-link";
    div.appendChild(a);
  }});
}}

function showGraphs() {{
  const device = document.getElementById('deviceSelect').value;
  const checked = Array.from(document.querySelectorAll('.metric-cb:checked')).map(cb => cb.value);
  const graphsDiv = document.getElementById('graphs');
  graphsDiv.innerHTML = "";
  checked.forEach(metric => {{
    const img = document.createElement('img');
    img.className = "graph";
    img.src = `${{device}}_${{metric}}.svg`;
    img.onerror = function() {{ this.onerror=null; this.src = `${{device}}_${{metric}}.png`; }};
    img.alt = `${{device}} ${{metric}}`;
    graphsDiv.appendChild(img);
  }});
}}

function populateIfaceDropdown() {{
  const select = document.getElementById('ifaceSelect');
  select.innerHTML = "";
  (window.NETIFACES || []).forEach(iface => {{
    const opt = document.createElement('option');
    opt.value = iface;
    opt.textContent = iface;
    select.appendChild(opt);
  }});
}}

function showNetGraphs() {{
  const iface = document.getElementById('ifaceSelect').value;
  const checked = Array.from(document.querySelectorAll('.net-metric-cb:checked')).map(cb => cb.value);
  const graphsDiv = document.getElementById('net-graphs');
  graphsDiv.innerHTML = "";
  checked.forEach(metric => {{
    const img = document.createElement('img');
    img.className = "graph";
    img.src = `${{iface}}_${{metric}}.svg`;
    img.onerror = function() {{ this.onerror=null; this.src = `${{iface}}_${{metric}}.png`; }};
    img.alt = `${{iface}} ${{metric}}`;
    graphsDiv.appendChild(img);
  }});
}}

window.addEventListener('DOMContentLoaded', () => {{
  populateDeviceDropdown();
  populateTableLinks();
  showGraphs();
  document.getElementById('deviceSelect').addEventListener('change', showGraphs);
  document.querySelectorAll('.metric-cb').forEach(cb => cb.addEventListener('change', showGraphs));
  // --- NET ---
  populateIfaceDropdown();
  showNetGraphs();
  document.getElementById('ifaceSelect').addEventListener('change', showNetGraphs);
  document.querySelectorAll('.net-metric-cb').forEach(cb => cb.addEventListener('change', showNetGraphs));
  // New: live search for disk device
  document.getElementById('deviceSearch').addEventListener('input', populateDeviceDropdown);
}});
</script>
</body>
</html>
"#, output_dir, output_dir)?;
    Ok(())
}

// ========== Stats helpers ==========

/// Mean of a Vec<IntervalDiskMetrics> by accessor
fn mean<F>(data: &[IntervalDiskMetrics], f: F) -> f64
where
    F: Fn(&IntervalDiskMetrics) -> f64,
{
    let sum: f64 = data.iter().map(|x| f(x)).sum();
    let count = data.len() as f64;
    if count == 0.0 { 0.0 } else { sum / count }
}

/// Max of a Vec<IntervalDiskMetrics> by accessor
fn max<F>(data: &[IntervalDiskMetrics], f: F) -> f64
where
    F: Fn(&IntervalDiskMetrics) -> f64,
{
    data.iter().map(|x| f(x)).fold(0.0, |acc, v| acc.max(v))
}


/// Helper to load disk metrics (for use by multipath module)
pub fn get_disk_metrics_map(file_path: &str) -> std::io::Result<std::collections::HashMap<String, Vec<IntervalDiskMetrics>>> {
    // Essentially copy your parsing up to the per-device metrics map in analyze.rs
    // (Same as in analyze())
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut per_device: HashMap<String, Vec<(u64, crate::DiskStat)>> = HashMap::new();

    for line in reader.lines().flatten() {
        if line.starts_with('#') { continue; }
        let mut cols = line.split(',');
        let typ = cols.next().unwrap_or("");
        if typ == "DISK" {
            let ts = cols.next().unwrap().parse::<u64>().unwrap_or(0);
            let fields: Vec<&str> = cols.collect();
            if let Some(stat) = crate::analyze::parse_disk_from_fields(&fields) {
                per_device.entry(stat.name.clone()).or_default().push((ts, stat));
            }
        }
    }
    // Convert to per-device Vec<IntervalDiskMetrics>
    let mut out: HashMap<String, Vec<IntervalDiskMetrics>> = HashMap::new();
    for (dev, rows) in per_device {
        let mut prev: Option<(u64, crate::DiskStat)> = None;
        let mut metrics = Vec::new();
        for (ts, stat) in rows {
            if let Some((last_ts, last_stat)) = &prev {
                let dt = ts.saturating_sub(*last_ts);
                if dt == 0 { prev = Some((ts, stat.clone())); continue; }
                let d_reads = stat.reads.saturating_sub(last_stat.reads);
                let d_writes = stat.writes.saturating_sub(last_stat.writes);
                let d_sectors_read = stat.sectors_read.saturating_sub(last_stat.sectors_read);
                let d_sectors_written = stat.sectors_written.saturating_sub(last_stat.sectors_written);
                let delta_weighted_io_time_ms = stat.weighted_io_time_ms.saturating_sub(last_stat.weighted_io_time_ms);
                let avg_queue_depth = delta_weighted_io_time_ms as f64 / (dt as f64 * 1000.0);
                let delta_io_time_ms = stat.io_time_ms.saturating_sub(last_stat.io_time_ms);
                let qlen = if delta_io_time_ms > 0 {
                    delta_weighted_io_time_ms as f64 / delta_io_time_ms as f64
                } else { 0.0 };
                let rps = d_reads as f64 / dt as f64;
                let wps = d_writes as f64 / dt as f64;
                let rd_kbs = d_sectors_read as f64 * 512.0 / 1024.0 / dt as f64;
                let wr_kbs = d_sectors_written as f64 * 512.0 / 1024.0 / dt as f64;

                metrics.push(IntervalDiskMetrics {
                    ts,
                    rps,
                    wps,
                    io_sec: rps + wps,
                    rd_kbs,
                    wr_kbs,
                    kb_sec: rd_kbs + wr_kbs,
                    avg_queue_depth,
                    qlen,
                    svctim: 0.0, // Not used in summary
                    await_rd: 0.0, await_wr: 0.0, discards_s: 0.0, discards_merged_s: 0.0, sectors_discarded_s: 0.0, await_discard_ms: 0.0, discard_kbs: 0.0,
                });
            }
            prev = Some((ts, stat));
        }
        if !metrics.is_empty() {
            out.insert(dev, metrics);
        }
    }
    Ok(out)
}

