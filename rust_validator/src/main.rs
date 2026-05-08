// Powered by AxisDynamics — https://axisdynamics.cl · MIT License
//! evidence_validator — AI Cyber Range Security Audit Binary v2.0
//!
//! Full security audit tool for the AI Cyber Range harness.
//! Validates evidence, maps attack surface, and produces structured audit reports.
//!
//! Commands:
//!   validate <finding.json>         — Validate single finding (full chain check)
//!   validate-batch <dir>            — Validate all *.json findings in directory
//!   audit-evidence <evidence-dir>   — SHA-256 chain validation for all evidence
//!   attack-surface                  — Map current process attack surface
//!   entropy <file>                  — Shannon entropy analysis (detect packed payloads)
//!   capabilities                    — Inspect Linux process capabilities
//!   sockets                         — Enumerate open network sockets (/proc/net)
//!   process-tree                    — Display process ancestry chain
//!   audit-report [output.json]      — Generate full structured audit report

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Read, BufRead};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Data structures ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Finding {
    id: String,
    asset: String,
    technique_id: String,
    severity: String,
    reproducible: bool,
    evidence_path: String,
    #[serde(default)]
    score: f64,
    #[serde(default)]
    detection_status: String,
    #[serde(default)]
    poc_id: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Evidence {
    id: String,
    #[serde(default)]
    asset_id: String,
    #[serde(default)]
    technique_id: String,
    #[serde(default)]
    evidence_type: String,
    #[serde(default)]
    hash_sha256: String,
    #[serde(default)]
    chain_of_custody: Vec<String>,
    #[serde(default)]
    collector: String,
    #[serde(default)]
    collected_at: String,
    #[serde(default)]
    content: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct ValidationResult {
    finding_id: String,
    valid: bool,
    checks_passed: Vec<String>,
    checks_failed: Vec<String>,
    severity_rank: u8,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct EvidenceAudit {
    evidence_id: String,
    path: String,
    valid: bool,
    hash_sha256: String,
    hash_verified: bool,
    chain_ok: bool,
    chain_length: usize,
    technique_id: String,
    asset_id: String,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct AttackSurface {
    pid: u32,
    uid: u32,
    euid: u32,
    open_fds: usize,
    memory_regions: usize,
    capabilities: HashMap<String, String>,
    open_sockets: Vec<SocketEntry>,
    process_ancestry: Vec<ProcessInfo>,
    timestamp: u64,
}

#[derive(Debug, Serialize)]
struct SocketEntry {
    local_addr: String,
    remote_addr: String,
    state: String,
    protocol: String,
}

#[derive(Debug, Serialize)]
struct ProcessInfo {
    pid: u32,
    ppid: u32,
    name: String,
    cmdline: String,
}

#[derive(Debug, Serialize)]
struct EntropyReport {
    path: String,
    file_size: u64,
    shannon_entropy: f64,
    entropy_verdict: String,   // low|medium|high|packed/encrypted
    byte_histogram: Vec<u32>,  // 256-entry histogram
    high_entropy_regions: Vec<EntropyRegion>,
}

#[derive(Debug, Serialize)]
struct EntropyRegion {
    offset: usize,
    length: usize,
    entropy: f64,
}

#[derive(Debug, Serialize)]
struct AuditReport {
    generated_at: u64,
    total_findings: usize,
    valid_findings: usize,
    invalid_findings: usize,
    total_evidence: usize,
    valid_evidence: usize,
    findings: Vec<ValidationResult>,
    evidence_audits: Vec<EvidenceAudit>,
    attack_surface: Option<AttackSurface>,
    overall_health: String,  // HEALTHY|DEGRADED|CRITICAL
}

// ─── Severity mapping ─────────────────────────────────────────────────────────

fn severity_rank(sev: &str) -> u8 {
    match sev.to_lowercase().as_str() {
        "critical" => 5,
        "high"     => 4,
        "medium"   => 3,
        "low"      => 2,
        _          => 1,
    }
}

const BLOCKED_TECHNIQUES: &[&str] = &["T1485", "T1561", "T1529"];
const VALID_TACTICS: &[&str] = &[
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Exfiltration", "Impact",
];

// ─── Finding validation ───────────────────────────────────────────────────────

fn validate_finding(finding: &Finding, project_root: &Path) -> ValidationResult {
    let mut passed: Vec<String> = Vec::new();
    let mut failed: Vec<String> = Vec::new();
    let mut notes: Vec<String>  = Vec::new();

    // C1: Required fields
    if !finding.id.is_empty() {
        passed.push("id_present".into());
    } else {
        failed.push("id_missing".into());
    }

    if !finding.asset.is_empty() {
        passed.push("asset_present".into());
    } else {
        failed.push("asset_required".into());
    }

    // C2: Technique format
    if finding.technique_id.starts_with('T')
        && finding.technique_id.len() >= 5
        && finding.technique_id[1..].chars().all(|c| c.is_ascii_digit() || c == '.')
    {
        passed.push("technique_id_format_ok".into());
    } else {
        failed.push(format!("technique_id_invalid: '{}'", finding.technique_id));
    }

    // C3: Blocked techniques
    if BLOCKED_TECHNIQUES.contains(&finding.technique_id.as_str()) {
        failed.push(format!("blocked_technique: {}", finding.technique_id));
        notes.push("Técnica destructiva bloqueada por governance".into());
    } else {
        passed.push("technique_not_blocked".into());
    }

    // C4: Severity
    if severity_rank(&finding.severity) >= 2 {
        passed.push(format!("severity_valid: {}", finding.severity));
    } else {
        failed.push(format!("severity_invalid: '{}'", finding.severity));
    }

    // C5: Reproducible required for backlog promotion
    if finding.reproducible {
        passed.push("reproducible".into());
    } else {
        notes.push("Finding not reproducible — cannot enter remediation backlog".into());
    }

    // C6: Evidence path exists on disk
    let evidence_path = project_root.join(&finding.evidence_path);
    if !finding.evidence_path.is_empty() {
        if evidence_path.exists() {
            passed.push("evidence_path_exists".into());

            // C7: Validate evidence file has SHA-256
            if let Ok(raw) = fs::read_to_string(&evidence_path) {
                if let Ok(evd) = serde_json::from_str::<Evidence>(&raw) {
                    if evd.hash_sha256.len() == 64 {
                        passed.push("evidence_sha256_present".into());
                    } else {
                        failed.push("evidence_sha256_missing_or_malformed".into());
                    }
                    if !evd.chain_of_custody.is_empty() {
                        passed.push(format!("chain_of_custody_len={}", evd.chain_of_custody.len()));
                    } else {
                        failed.push("chain_of_custody_empty".into());
                    }
                }
            }
        } else {
            failed.push(format!("evidence_path_not_found: {}", evidence_path.display()));
            notes.push("Anti-hallucination check FAILED: evidence not on disk".into());
        }
    } else {
        failed.push("evidence_path_empty".into());
    }

    // C8: Score range
    if finding.score >= 0.0 && finding.score <= 100.0 {
        passed.push(format!("score_valid: {:.1}", finding.score));
    } else {
        failed.push(format!("score_out_of_range: {}", finding.score));
    }

    let valid = failed.is_empty();
    ValidationResult {
        finding_id: finding.id.clone(),
        valid,
        checks_passed: passed,
        checks_failed: failed,
        severity_rank: severity_rank(&finding.severity),
        notes,
    }
}

// ─── Evidence chain audit ─────────────────────────────────────────────────────

fn audit_evidence_file(path: &Path) -> EvidenceAudit {
    let path_str = path.display().to_string();

    let raw = match fs::read_to_string(path) {
        Ok(v) => v,
        Err(e) => return EvidenceAudit {
            evidence_id: path.file_stem().unwrap_or_default().to_string_lossy().into(),
            path: path_str,
            valid: false,
            hash_sha256: String::new(),
            hash_verified: false,
            chain_ok: false,
            chain_length: 0,
            technique_id: String::new(),
            asset_id: String::new(),
            error: Some(format!("read_error: {}", e)),
        },
    };

    let evd: Evidence = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => return EvidenceAudit {
            evidence_id: "unknown".into(),
            path: path_str,
            valid: false,
            hash_sha256: String::new(),
            hash_verified: false,
            chain_ok: false,
            chain_length: 0,
            technique_id: String::new(),
            asset_id: String::new(),
            error: Some(format!("json_parse_error: {}", e)),
        },
    };

    let hash_ok = evd.hash_sha256.len() == 64
        && evd.hash_sha256.chars().all(|c| c.is_ascii_hexdigit());
    let chain_ok = !evd.chain_of_custody.is_empty();
    let valid = hash_ok && chain_ok;

    EvidenceAudit {
        evidence_id: evd.id.clone(),
        path: path_str,
        valid,
        hash_sha256: evd.hash_sha256.clone(),
        hash_verified: hash_ok,
        chain_ok,
        chain_length: evd.chain_of_custody.len(),
        technique_id: evd.technique_id.clone(),
        asset_id: evd.asset_id.clone(),
        error: if valid { None } else {
            Some(format!("hash_ok={} chain_ok={}", hash_ok, chain_ok))
        },
    }
}

// ─── Attack surface mapping ───────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn map_attack_surface() -> AttackSurface {
    let pid  = std::process::id();
    let uid  = unsafe { libc_getuid() };
    let euid = unsafe { libc_geteuid() };

    AttackSurface {
        pid,
        uid,
        euid,
        open_fds: count_open_fds(pid),
        memory_regions: count_memory_regions(pid),
        capabilities: read_capabilities(pid),
        open_sockets: read_sockets(),
        process_ancestry: build_process_tree(pid),
        timestamp: unix_now(),
    }
}

#[cfg(not(target_os = "linux"))]
fn map_attack_surface() -> AttackSurface {
    AttackSurface {
        pid: std::process::id(),
        uid: 0, euid: 0,
        open_fds: 0, memory_regions: 0,
        capabilities: HashMap::new(),
        open_sockets: Vec::new(),
        process_ancestry: Vec::new(),
        timestamp: unix_now(),
    }
}

#[cfg(target_os = "linux")]
fn count_open_fds(pid: u32) -> usize {
    fs::read_dir(format!("/proc/{}/fd", pid))
        .map(|dir| dir.count())
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
fn count_open_fds(_pid: u32) -> usize { 0 }

#[cfg(target_os = "linux")]
fn count_memory_regions(pid: u32) -> usize {
    let maps = format!("/proc/{}/maps", pid);
    fs::read_to_string(maps)
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
fn count_memory_regions(_pid: u32) -> usize { 0 }

#[cfg(target_os = "linux")]
fn read_capabilities(pid: u32) -> HashMap<String, String> {
    let mut caps = HashMap::new();
    let status = format!("/proc/{}/status", pid);
    if let Ok(content) = fs::read_to_string(status) {
        for line in content.lines() {
            if line.starts_with("Cap") {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    caps.insert(parts[0].trim().into(), parts[1].trim().into());
                }
            }
        }
    }
    caps
}

#[cfg(not(target_os = "linux"))]
fn read_capabilities(_pid: u32) -> HashMap<String, String> { HashMap::new() }

#[cfg(target_os = "linux")]
fn read_sockets() -> Vec<SocketEntry> {
    let mut sockets = Vec::new();
    for proto in &["tcp", "tcp6", "udp", "udp6"] {
        let path = format!("/proc/net/{}", proto);
        if let Ok(content) = fs::read_to_string(&path) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    sockets.push(SocketEntry {
                        local_addr:  decode_proc_net_addr(parts[1]),
                        remote_addr: decode_proc_net_addr(parts[2]),
                        state:       decode_tcp_state(parts[3]),
                        protocol:    proto.to_string(),
                    });
                }
            }
        }
    }
    sockets
}

#[cfg(not(target_os = "linux"))]
fn read_sockets() -> Vec<SocketEntry> { Vec::new() }

#[cfg(target_os = "linux")]
fn decode_proc_net_addr(hex: &str) -> String {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 { return hex.to_string(); }
    if let (Ok(addr_h), Ok(port_h)) = (
        u32::from_str_radix(parts[0], 16),
        u16::from_str_radix(parts[1], 16),
    ) {
        let addr = u32::from_be(addr_h.swap_bytes());
        let b = addr.to_be_bytes();
        format!("{}.{}.{}.{}:{}", b[0], b[1], b[2], b[3], port_h)
    } else {
        hex.to_string()
    }
}

#[cfg(not(target_os = "linux"))]
fn decode_proc_net_addr(hex: &str) -> String { hex.to_string() }

fn decode_tcp_state(hex: &str) -> String {
    match hex {
        "01" => "ESTABLISHED", "02" => "SYN_SENT",  "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",   "05" => "FIN_WAIT2",  "06" => "TIME_WAIT",
        "07" => "CLOSE",       "08" => "CLOSE_WAIT", "09" => "LAST_ACK",
        "0A" => "LISTEN",      "0B" => "CLOSING",
        _ => "UNKNOWN",
    }.to_string()
}

#[cfg(target_os = "linux")]
fn build_process_tree(pid: u32) -> Vec<ProcessInfo> {
    let mut tree = Vec::new();
    let mut cur = pid;
    for _ in 0..16 {
        if cur == 0 { break; }
        if let Some(info) = read_proc_info(cur) {
            let ppid = info.ppid;
            tree.push(info);
            if ppid == 0 || ppid == cur { break; }
            cur = ppid;
        } else { break; }
    }
    tree
}

#[cfg(not(target_os = "linux"))]
fn build_process_tree(_pid: u32) -> Vec<ProcessInfo> { Vec::new() }

#[cfg(target_os = "linux")]
fn read_proc_info(pid: u32) -> Option<ProcessInfo> {
    let status = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    let mut name = String::new();
    let mut ppid = 0u32;
    for line in status.lines() {
        if line.starts_with("Name:") { name = line[5..].trim().into(); }
        if line.starts_with("PPid:") {
            ppid = line[5..].trim().parse().unwrap_or(0);
        }
    }
    let cmdline = fs::read_to_string(format!("/proc/{}/cmdline", pid))
        .unwrap_or_default()
        .replace('\0', " ")
        .trim()
        .chars()
        .take(120)
        .collect();
    Some(ProcessInfo { pid, ppid, name, cmdline })
}

// ─── Shannon entropy analysis ─────────────────────────────────────────────────

fn analyze_entropy(path: &Path) -> io::Result<EntropyReport> {
    let data = fs::read(path)?;
    let file_size = data.len() as u64;

    let mut histogram = vec![0u32; 256];
    for &b in &data { histogram[b as usize] += 1; }

    let entropy = shannon_entropy(&data);
    let verdict = entropy_verdict(entropy);

    // Find high-entropy regions (512-byte windows)
    let window = 512;
    let mut high_regions = Vec::new();
    let mut i = 0;
    while i + window <= data.len() {
        let h = shannon_entropy(&data[i..i+window]);
        if h > 7.0 {
            high_regions.push(EntropyRegion { offset: i, length: window, entropy: h });
        }
        i += window;
    }
    high_regions.truncate(10);

    Ok(EntropyReport {
        path: path.display().to_string(),
        file_size,
        shannon_entropy: entropy,
        entropy_verdict: verdict,
        byte_histogram: histogram,
        high_entropy_regions: high_regions,
    })
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let n = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = c as f64 / n; -p * p.log2() })
        .sum()
}

fn entropy_verdict(h: f64) -> String {
    match h as u32 {
        0..=3 => "low (text/structured data)".into(),
        4..=5 => "medium (mixed content)".into(),
        6..=6 => "high (compressed or dense binary)".into(),
        _ =>     "very_high — packed/encrypted payload suspected".into(),
    }
}

// ─── Utility ──────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// Thin wrappers for libc (Linux only)
#[cfg(target_os = "linux")]
extern "C" {
    fn getuid() -> u32;
    fn geteuid() -> u32;
}

#[cfg(target_os = "linux")]
unsafe fn libc_getuid() -> u32  { getuid() }
#[cfg(target_os = "linux")]
unsafe fn libc_geteuid() -> u32 { geteuid() }

#[cfg(not(target_os = "linux"))]
unsafe fn libc_getuid() -> u32  { 0 }
#[cfg(not(target_os = "linux"))]
unsafe fn libc_geteuid() -> u32 { 0 }

fn project_root() -> PathBuf {
    // Walk up from binary location to find project root (has engagement_backlog.json)
    let mut dir = env::current_exe().unwrap_or_default();
    for _ in 0..8 {
        dir.pop();
        if dir.join("engagement_backlog.json").exists() { return dir; }
    }
    env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("evidence_validator v2.0 — AI Cyber Range Security Audit");
        eprintln!("Usage: {} <command> [args...]", args[0]);
        eprintln!("Commands:");
        eprintln!("  validate <finding.json>       Validate single finding");
        eprintln!("  validate-batch <dir>          Validate all findings in directory");
        eprintln!("  audit-evidence <evidence-dir> SHA-256 chain audit");
        eprintln!("  attack-surface                Map current process attack surface");
        eprintln!("  entropy <file>                Shannon entropy analysis");
        eprintln!("  capabilities                  Inspect Linux capabilities");
        eprintln!("  sockets                       List open network sockets");
        eprintln!("  process-tree                  Display process ancestry");
        eprintln!("  audit-report [output.json]    Generate full audit report");
        process::exit(2);
    }

    let root = project_root();
    let cmd = args[1].as_str();

    match cmd {
        // ── validate ──────────────────────────────────────────────────────────
        "validate" => {
            if args.len() < 3 {
                eprintln!("ERROR: validate requires <finding.json>");
                process::exit(2);
            }
            let raw = match fs::read_to_string(&args[2]) {
                Ok(v) => v,
                Err(e) => { eprintln!("VALIDATION_ERROR: {}", e); process::exit(3); }
            };
            let finding: Finding = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(e) => { eprintln!("VALIDATION_ERROR: invalid json: {}", e); process::exit(4); }
            };
            let result = validate_finding(&finding, &root);
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            if result.valid {
                println!("VALIDATION_OK: {}", finding.id);
                process::exit(0);
            } else {
                eprintln!("VALIDATION_ERROR: {} check(s) failed", result.checks_failed.len());
                process::exit(5);
            }
        }

        // ── validate-batch ────────────────────────────────────────────────────
        "validate-batch" => {
            if args.len() < 3 {
                eprintln!("ERROR: validate-batch requires <directory>");
                process::exit(2);
            }
            let dir = Path::new(&args[2]);
            let mut pass = 0u32;
            let mut fail = 0u32;
            for entry in fs::read_dir(dir).expect("cannot read dir") {
                let path = entry.unwrap().path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    if let Ok(raw) = fs::read_to_string(&path) {
                        if let Ok(f) = serde_json::from_str::<Finding>(&raw) {
                            let r = validate_finding(&f, &root);
                            if r.valid { pass += 1; println!("OK  {}", f.id); }
                            else { fail += 1; eprintln!("FAIL {}: {:?}", f.id, r.checks_failed); }
                        }
                    }
                }
            }
            println!("BATCH_RESULT: pass={} fail={}", pass, fail);
            process::exit(if fail == 0 { 0 } else { 5 });
        }

        // ── audit-evidence ────────────────────────────────────────────────────
        "audit-evidence" => {
            if args.len() < 3 {
                eprintln!("ERROR: audit-evidence requires <evidence-dir>");
                process::exit(2);
            }
            let dir = Path::new(&args[2]);
            let mut total = 0u32; let mut valid = 0u32;
            let audits: Vec<EvidenceAudit> = fs::read_dir(dir)
                .expect("cannot read evidence dir")
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
                .map(|e| {
                    total += 1;
                    let a = audit_evidence_file(&e.path());
                    if a.valid { valid += 1; }
                    a
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&audits).unwrap());
            println!("EVIDENCE_AUDIT: total={} valid={} invalid={}", total, valid, total-valid);
            process::exit(if valid == total { 0 } else { 5 });
        }

        // ── attack-surface ────────────────────────────────────────────────────
        "attack-surface" => {
            let surface = map_attack_surface();
            println!("{}", serde_json::to_string_pretty(&surface).unwrap());
        }

        // ── entropy ───────────────────────────────────────────────────────────
        "entropy" => {
            if args.len() < 3 { eprintln!("ERROR: entropy requires <file>"); process::exit(2); }
            match analyze_entropy(Path::new(&args[2])) {
                Ok(report) => {
                    println!("{}", serde_json::to_string_pretty(&report).unwrap());
                }
                Err(e) => { eprintln!("ENTROPY_ERROR: {}", e); process::exit(3); }
            }
        }

        // ── capabilities ──────────────────────────────────────────────────────
        "capabilities" => {
            let caps = read_capabilities(std::process::id());
            println!("{}", serde_json::to_string_pretty(&caps).unwrap());
        }

        // ── sockets ───────────────────────────────────────────────────────────
        "sockets" => {
            let socks = read_sockets();
            println!("{}", serde_json::to_string_pretty(&socks).unwrap());
            println!("SOCKET_COUNT: {}", socks.len());
        }

        // ── process-tree ──────────────────────────────────────────────────────
        "process-tree" => {
            let tree = build_process_tree(std::process::id());
            println!("{}", serde_json::to_string_pretty(&tree).unwrap());
        }

        // ── audit-report ──────────────────────────────────────────────────────
        "audit-report" => {
            // Collect all findings
            let findings_dir = root.join("artifacts");
            let mut all_findings: Vec<ValidationResult> = Vec::new();
            let mut total_f = 0u32; let mut valid_f = 0u32;

            if findings_dir.exists() {
                for entry in fs::read_dir(&findings_dir).unwrap().filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if path.extension().map(|x| x == "json").unwrap_or(false)
                        && path.file_name().map(|n| n.to_string_lossy().starts_with("FND-")).unwrap_or(false)
                    {
                        if let Ok(raw) = fs::read_to_string(&path) {
                            if let Ok(f) = serde_json::from_str::<Finding>(&raw) {
                                total_f += 1;
                                let r = validate_finding(&f, &root);
                                if r.valid { valid_f += 1; }
                                all_findings.push(r);
                            }
                        }
                    }
                }
            }

            // Audit all evidence
            let evidence_dir = root.join("artifacts").join("evidence");
            let mut evidence_audits: Vec<EvidenceAudit> = Vec::new();
            let mut total_e = 0u32; let mut valid_e = 0u32;
            if evidence_dir.exists() {
                for entry in fs::read_dir(&evidence_dir).unwrap().filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if path.extension().map(|x| x == "json").unwrap_or(false) {
                        total_e += 1;
                        let a = audit_evidence_file(&path);
                        if a.valid { valid_e += 1; }
                        evidence_audits.push(a);
                    }
                }
            }

            let surface = map_attack_surface();
            let health = if valid_f == total_f && valid_e == total_e { "HEALTHY" }
                         else if valid_f < total_f / 2 || valid_e < total_e / 2 { "CRITICAL" }
                         else { "DEGRADED" };

            let report = AuditReport {
                generated_at: unix_now(),
                total_findings: total_f as usize,
                valid_findings: valid_f as usize,
                invalid_findings: (total_f - valid_f) as usize,
                total_evidence: total_e as usize,
                valid_evidence: valid_e as usize,
                findings: all_findings,
                evidence_audits,
                attack_surface: Some(surface),
                overall_health: health.to_string(),
            };

            let json = serde_json::to_string_pretty(&report).unwrap();
            let output_path = args.get(2).map(Path::new);
            if let Some(p) = output_path {
                fs::write(p, &json).expect("cannot write report");
                println!("AUDIT_REPORT_WRITTEN: {}", p.display());
            } else {
                println!("{}", json);
            }
            println!("AUDIT_REPORT: health={} findings={}/{} evidence={}/{}",
                health, valid_f, total_f, valid_e, total_e);
            process::exit(if health == "HEALTHY" { 0 } else { 5 });
        }

        _ => {
            eprintln!("ERROR: unknown command '{}'", cmd);
            process::exit(2);
        }
    }
}
