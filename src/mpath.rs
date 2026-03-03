/*!
 * Multipath Analyzer Module
 * ------------------------
 * Copyright (C) 2025 Laurence Oberman <loberman@redhat.com>
 * Developed with assistance from ChatGPT (OpenAI).
 *
 * This module parses the output of `multipath -ll` and, together with the telemetry
 * .dat file, produces a report of IOPS/sec and KB/sec per multipath device and per-path.
 */

use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::analyze::get_disk_metrics_map;

#[derive(Debug)]
#[allow(dead_code, unused)]
pub struct MpathPath {
    pub bus: String,
    pub dev_name: String,
    pub major_minor: String,
    pub status: String,
}

#[derive(Debug)]
#[allow(dead_code, unused)]
pub struct MultipathDevice {
    pub name: String,         // e.g. mpathw
    pub wwid: String,         // 3600c0ff...
    pub dm_name: String,      // e.g. dm-37
    pub vendor_model: String, // e.g. HPE,MSA 2050 SAN
    pub size: String,         // e.g. size=9.3G
    pub paths: Vec<MpathPath>,
}

pub fn parse_multipath_ll(path: &str) -> Vec<MultipathDevice> {
    use regex::Regex;

    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);

    let dev_regex = Regex::new(r"^(sd[a-zA-Z0-9]+|nvme\d+n\d+)$").unwrap();
    let mut devices = Vec::new();
    let mut curdev: Option<MultipathDevice> = None;

    for line in reader.lines().flatten() {
        let l = line.trim_end();
        if l.is_empty() { continue; }

        if l.starts_with("mpath") {
            if let Some(dev) = curdev.take() {
                devices.push(dev);
            }
            let fields: Vec<&str> = l.split_whitespace().collect();
            let name = fields.get(0).unwrap_or(&"").to_string();
            let wwid = fields.get(1).unwrap_or(&"").trim_matches(|c| c == '(' || c == ')').to_string();
            let dm_name = fields.get(2).unwrap_or(&"").to_string();
            let vendor_model = fields.get(3..).unwrap_or(&[]).join(" ");
            curdev = Some(MultipathDevice {
                name, wwid, dm_name, vendor_model,
                size: String::new(),
                paths: Vec::new(),
            });
        } else if l.trim_start().starts_with("size=") {
            if let Some(dev) = curdev.as_mut() {
                dev.size = l.trim().to_string();
            }
        } else {
            // Tree-style path line (starts with |, `, space, etc)
            // Look for a field that looks like sdX or nvmeXnY
            let parts: Vec<&str> = l.split_whitespace().collect();
            // skip policy/prio lines, must be enough fields and have a dev
            let idx = parts.iter().position(|x| dev_regex.is_match(x));
            if let Some(i) = idx {
                // bus = previous field, dev = matched field, major_minor = next, status = rest
                if i >= 1 && parts.len() > i + 2 {
                    let bus = parts[i - 1].to_string();
                    let dev_name = parts[i].to_string();
                    let major_minor = parts[i + 1].to_string();
                    let status = parts[i + 2..].join(" ");
                    if let Some(dev) = curdev.as_mut() {
                        dev.paths.push(MpathPath {
                            bus, dev_name, major_minor, status,
                        });
                    }
                }
            }
        }
    }
    if let Some(dev) = curdev {
        devices.push(dev);
    }
    devices
}


pub fn report_mpath_stats(multipath_path: &str, dat_path: &str) -> std::io::Result<()> {
    let devices = parse_multipath_ll(multipath_path);
    let disk_metrics = get_disk_metrics_map(dat_path)?;

    for mdev in &devices {
        let mut mpath_total_iops = 0.0;
        let mut mpath_total_kbs = 0.0;
        let mut per_path: Vec<(String, f64, f64)> = Vec::new();

        for path in &mdev.paths {
            let (iops_avg, kbs_avg) = if let Some(series) = disk_metrics.get(&path.dev_name) {
                (
                    series.iter()
                        .map(|m| m.rps + m.wps)
                        .sum::<f64>() / series.len().max(1) as f64,
                    series.iter()
                        .map(|m| m.rd_kbs + m.wr_kbs)
                        .sum::<f64>() / series.len().max(1) as f64,
                )
            } else {
                (0.0, 0.0)
            };

            if iops_avg > 0.0 || kbs_avg > 0.0 {
                per_path.push((path.dev_name.clone(), iops_avg, kbs_avg));
                mpath_total_iops += iops_avg;
                mpath_total_kbs += kbs_avg;
            }
        }

        // Skip mpaths with no activity
        if per_path.is_empty() {
            continue;
        }

        // Split vendor/attrs cleanly
        let (dev_field, attr_field): (String, String) =
            if mdev.vendor_model.contains("size=") {
                let mut parts = mdev.vendor_model.splitn(2, "size=");
                (
                    parts.next().unwrap_or("").trim().to_string(),
                    format!("size={}", parts.nth(1).unwrap_or("").trim()),
                )
            } else {
                (
                    mdev.vendor_model.clone(),
                    mdev.size.clone(),
                )
            };

        // Header BEFORE EACH MPATH GROUP
        println!(
            "{:<8} {:<9} {:<24} {:<52} {:>9} {:>10}",
            "MPATH", "DM", "DEV", "ATTRS", "IOPS", "KB/sec"
        );
        println!("{}", "-".repeat(112));

        // Group summary row
        println!(
            "{:<8} {:<9} {:<24} {:<52} {:>9.1} {:>10.1}",
            mdev.name,
            mdev.dm_name,
            dev_field,
            attr_field,
            mpath_total_iops,
            mpath_total_kbs
        );

        // Path rows
        for (dev, iops, kbs) in &per_path {
            let io_pct = if mpath_total_iops > 0.0 {
                100.0 * iops / mpath_total_iops
            } else {
                0.0
            };
            let kb_pct = if mpath_total_kbs > 0.0 {
                100.0 * kbs / mpath_total_kbs
            } else {
                0.0
            };

            println!(
                "    {:<10} IOPS:{:>8.1} KB/sec:{:>10.1} (IO%:{:>5.1} KB%:{:>5.1})",
                dev, iops, kbs, io_pct, kb_pct
            );
        }

        println!(); // spacing between groups
    }

    Ok(())
}

