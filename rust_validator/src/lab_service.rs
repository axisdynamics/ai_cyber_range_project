// Powered by AxisDynamics — https://axisdynamics.cl · MIT License
// lab_service.rs — AI Cyber Range Lab Service (Rust)
// ====================================================
// Complete port of the C lab service to Rust.
// Memory-safe, cross-platform (macOS + Linux + Windows).
// Same CLI interface and exit codes as the C version.
//
// Techniques exercised:
//   T1190  Exploit Public-Facing Application
//   T1059  Command and Scripting Interpreter
//   T1078  Valid Accounts
//   T1548  Abuse Elevation Control Mechanism
//   T1082  System Information Discovery
//   T1003  OS Credential Dumping
//   T1021  Remote Services (Lateral Movement)
//   T1005  Data from Local System
//   T1041  Exfiltration Over C2 Channel
//   T1499  Endpoint Denial of Service
//   T1053  Scheduled Task/Job
//
// Commands:
//   add <text>          Note store — bounds check (T1190)
//   list                List stored notes
//   echo <input>        Format string surface (T1190)
//   auth <user> <pass>  Auth + timing resistance (T1078, T1190)
//   exec <cmd>          Injection detection (T1059)
//   env                 System enumeration (T1082)
//   privesc             Privilege escalation surface (T1548)
//   persist             Scheduled task surface (T1053)
//   lateral <target>    Lateral movement + sovereignty (T1021)
//   collect [path]      Data access (T1005, T1003)
//   exfil <data>        Exfiltration marker (T1041)
//   dos <count>         Load spike simulation (T1499)
//   alloc <size>        Integer overflow surface (T1190)
//   selftest            Run all 15 test cases
//   audit               Full surface scan

use std::env;
use std::fs;
use std::hint;
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, Instant};

// ── Constants ────────────────────────────────────────────────────────────────

const MAX_NOTE:  usize = 64;
const MAX_NOTES: usize = 16;
const MAX_ALLOC: i64   = 1_048_576; // 1 MiB

const EXFIL_MARKER:   &str = "SYNTHETIC_EXFIL_EVENT_NO_REAL_DATA";
const LATERAL_MARKER: &str = "SYNTHETIC_PIVOT_REQUEST";
const PRIVESC_MARKER: &str = "SYNTHETIC_PRIVILEGE_TEST";
const CRON_MARKER:    &str = "SYNTHETIC_CRON_ENTRY";
const LOAD_MARKER:    &str = "SYNTHETIC_LOAD_SPIKE";
const SYNTHETIC_PASS: &str = "SYNTHETIC_VALID_TOKEN_1234";

const SYNTHETIC_USERS: &[&str] = &["admin", "root", "service_account", "api_user"];
const LATERAL_ALLOWED: &[&str] = &[
    "api_gateway_demo", "iam_role_demo", "pipeline_demo",
    "cloud_storage_demo", "secrets_store_demo",
];

// Exit codes — identical to C service for red_team.py compatibility
const RC_OK:        i32 = 0;
const RC_WARN:      i32 = 3;
const RC_AUTH_FAIL: i32 = 10;
const RC_ERROR:     i32 = 1;

// ── State ────────────────────────────────────────────────────────────────────

struct NoteStore {
    notes: Vec<String>,
}

impl NoteStore {
    fn new() -> Self { NoteStore { notes: Vec::new() } }

    fn add(&mut self, text: &str) -> i32 {
        if self.notes.len() >= MAX_NOTES {
            eprintln!("ERROR: note capacity reached (max={})", MAX_NOTES);
            return RC_ERROR;
        }
        if text.len() >= MAX_NOTE {
            eprintln!(
                "WARN: input_validation_warning note_len={} max={} \
                 technique=T1190 surface=stack_overflow",
                text.len(), MAX_NOTE - 1
            );
            self.notes.push(text[..MAX_NOTE - 1].to_string());
            return RC_WARN;
        }
        let slot = self.notes.len() + 1;
        println!("NOTE_ADDED: slot={} len={}", slot, text.len());
        self.notes.push(text.to_string());
        RC_OK
    }

    fn list(&self) {
        if self.notes.is_empty() {
            println!("(no notes)");
        }
        for (i, n) in self.notes.iter().enumerate() {
            println!("{}: {}", i + 1, n);
        }
    }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn sep() {
    println!("─────────────────────────────────────────────");
}

/// Constant-time byte comparison — prevents timing oracle attacks
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let max_len = a.len().max(b.len());
    let mut result: u8 = 0;
    for i in 0..max_len {
        let ai = if i < a.len() { a[i] } else { 0 };
        let bi = if i < b.len() { b[i] } else { 0 };
        result |= ai ^ bi;
    }
    result == 0
}

/// Spin for ~50ms to simulate timing side-channel on auth failure
fn timing_delay() {
    let deadline = Instant::now() + Duration::from_millis(50);
    while Instant::now() < deadline {
        hint::spin_loop();
    }
}

// ── T1190: add — buffer bounds check ─────────────────────────────────────────

// (delegated to NoteStore::add)

// ── T1190: echo — format string surface ──────────────────────────────────────

fn cmd_echo(input: &str) -> i32 {
    if input.contains('%') {
        eprintln!(
            "WARN: input_validation_warning format_specifiers_detected \
             technique=T1190 surface=format_string"
        );
        println!("ECHO_SANITIZED: [format specifiers stripped]");
        return RC_WARN;
    }
    println!("ECHO: {}", input);
    RC_OK
}

// ── T1078 + T1190: auth — timing resistance + overflow check ─────────────────

fn cmd_auth(username: &str, password: &str) -> i32 {
    // Bounds check (mirrors C service behavior)
    if username.len() >= 128 {
        eprintln!(
            "WARN: input_validation_warning auth_overflow username_len={} \
             technique=T1190,T1078 surface=stack_overflow",
            username.len()
        );
    }
    if password.len() >= 128 {
        eprintln!(
            "WARN: input_validation_warning auth_overflow password_len={} \
             technique=T1190,T1078 surface=stack_overflow",
            password.len()
        );
    }

    // User existence check (linear scan — intentional timing oracle surface)
    if !SYNTHETIC_USERS.contains(&username) {
        eprintln!("AUTH_FAIL: unknown_user={} technique=T1078", username);
        return RC_AUTH_FAIL;
    }

    // Constant-time password compare
    if !ct_eq(password.as_bytes(), SYNTHETIC_PASS.as_bytes()) {
        timing_delay();
        eprintln!("AUTH_FAIL: invalid_password user={} technique=T1078", username);
        return RC_AUTH_FAIL;
    }

    println!("AUTH_OK: SYNTHETIC_VALID_TOKEN_1234 user={} technique=T1078", username);
    println!("credential_check: access_granted=true user={}", username);
    RC_OK
}

// ── T1059: exec — command injection surface ───────────────────────────────────

fn cmd_exec(input: &str) -> i32 {
    let dangerous = [";", "&&", "||", "|", "`", "$(", "${", ">", "<"];
    let mut detected = false;
    for token in &dangerous {
        if input.contains(token) {
            detected = true;
            eprintln!(
                "WARN: input_validation_warning shell_metacharacter='{}' \
                 technique=T1059 surface=command_injection",
                token
            );
        }
    }
    if detected {
        println!("EXEC_BLOCKED: injection_detected technique=T1059");
        return RC_WARN;
    }
    let display = if input.len() > 100 { &input[..100] } else { input };
    println!("EXEC_SIMULATED: cmd='{}' technique=T1059 mode=synthetic", display);
    println!("Command execution via scripting interpreter (echo only)");
    RC_OK
}

// ── T1082: env — system information discovery ────────────────────────────────

fn cmd_env() -> i32 {
    println!("ENV_DISCLOSURE: technique=T1082 surface=system_enumeration");
    sep();

    // OS info — works on both macOS and Linux
    #[cfg(target_os = "linux")]
    if let Ok(release) = fs::read_to_string("/etc/os-release") {
        for line in release.lines().take(4) {
            println!("OS: {}", line);
        }
    }
    #[cfg(target_os = "macos")]
    println!("OS: macOS (Darwin)");
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    println!("OS: synthetic_lab_environment");

    println!("PID: {}", std::process::id());

    // Capabilities (Linux only)
    #[cfg(target_os = "linux")]
    if let Ok(status) = fs::read_to_string(format!("/proc/{}/status", std::process::id())) {
        for line in status.lines() {
            if line.starts_with("Cap") || line.starts_with("Uid") {
                println!("PROC: {}", line);
            }
        }
    }

    // Environment variables
    for var in &["PATH", "HOME", "SHELL", "USER", "LOGNAME"] {
        if let Ok(val) = env::var(var) {
            println!("ENV_{}={}", var, val);
        }
    }

    println!("enumerate_fixtures: technique=T1082 discovery=true");
    sep();
    RC_OK
}

// ── T1548: privesc — privilege escalation surface ────────────────────────────

fn cmd_privesc() -> i32 {
    println!("PRIVESC_CHECK: {} technique=T1548", PRIVESC_MARKER);
    sep();
    let mut findings = 0;

    // Check SUID/setuid binaries using std::fs (cross-platform)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let suid_targets = [
            "/usr/bin/sudo", "/usr/bin/pkexec", "/usr/bin/su",
            "/usr/bin/python3", "/bin/bash",
        ];
        for target in &suid_targets {
            if let Ok(meta) = fs::metadata(target) {
                let mode = meta.permissions().mode();
                if mode & 0o4000 != 0 {
                    println!(
                        "FINDING: suid_binary={} mode={:o} technique=T1548",
                        target, mode & 0o7777
                    );
                    findings += 1;
                }
            }
        }
        // Linux capabilities
        #[cfg(target_os = "linux")]
        if let Ok(status) = fs::read_to_string(
            format!("/proc/{}/status", std::process::id())
        ) {
            for line in status.lines() {
                if line.starts_with("Cap") {
                    println!("CAP: {}", line);
                }
            }
        }
    }

    println!("SYNTHETIC_PRIVILEGE_TEST: escalation_path_simulation technique=T1548");
    println!("Privilege escalation path simulation");
    println!("privesc_findings={} technique=T1548", findings);
    sep();
    if findings > 0 { RC_WARN } else { RC_OK }
}

// ── T1053: persist — scheduled task surface ──────────────────────────────────

fn cmd_persist() -> i32 {
    println!("PERSIST_CHECK: {} technique=T1053", CRON_MARKER);
    sep();

    // Use std::fs::metadata — works on macOS AND Linux
    let cron_paths = ["/etc/crontab", "/etc/cron.d", "/var/spool/cron"];
    for path in &cron_paths {
        if let Ok(meta) = fs::metadata(path) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                println!(
                    "CRON_EXISTS: {} perms={:o} technique=T1053",
                    path, meta.permissions().mode() & 0o7777
                );
            }
            #[cfg(not(unix))]
            println!("CRON_EXISTS: {} technique=T1053", path);
        }
    }
    // macOS-specific LaunchAgents
    #[cfg(target_os = "macos")]
    {
        let launch_paths = [
            "~/Library/LaunchAgents",
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
        ];
        for path in &launch_paths {
            let expanded = path.replace('~', &env::var("HOME").unwrap_or_default());
            if fs::metadata(&expanded).is_ok() {
                println!("LAUNCHAGENT_EXISTS: {} technique=T1053", expanded);
            }
        }
    }

    println!("SYNTHETIC_CRON_ENTRY: scheduled_task simulation technique=T1053");
    println!("Scheduled task simulation (no real task created)");
    sep();
    RC_OK
}

// ── T1021: lateral — lateral movement + sovereignty ──────────────────────────

fn cmd_lateral(target: &str) -> i32 {
    if !LATERAL_ALLOWED.contains(&target) {
        eprintln!(
            "SOVEREIGNTY_VIOLATION: target='{}' not authorized \
             allow_external_targets=false technique=T1021",
            target
        );
        return RC_WARN;
    }
    println!(
        "LATERAL_MOVE: {} target={} technique=T1021 mode=synthetic",
        LATERAL_MARKER, target
    );
    println!("Lateral movement simulation between local fixture assets");
    sep();
    RC_OK
}

// ── T1005 + T1003: collect — data access surface ─────────────────────────────

fn cmd_collect(path: &str) -> i32 {
    println!("COLLECT: path={} technique=T1005,T1003", path);
    sep();

    // Cross-platform file existence: std::fs::metadata (no stat() needed)
    match fs::metadata(path) {
        Ok(meta) => {
            println!("file_accessible=True path={} size={}", path, meta.len());

            // Sensitivity check
            let is_sensitive = path.contains("credential")
                || path.contains("password")
                || path.contains("secret")
                || path.contains("shadow")
                || path.contains("assets.json");

            if is_sensitive {
                println!(
                    "SENSITIVE_FILE_ACCESS: path={} technique=T1003,T1005 \
                     data_classification=confidential",
                    path
                );
                eprintln!("WARN: sensitive_data_access path={} technique=T1003", path);
            }

            // Read first line (simulated data staging)
            if let Ok(content) = fs::read_to_string(path) {
                if let Some(first) = content.lines().next() {
                    let preview = if first.len() > 80 { &first[..80] } else { first };
                    println!("FIRST_LINE: {}", preview);
                }
            }
            println!(
                "Fixture de datos '{}' es accesible sin autenticación adicional.\n\
                 Validar controles de acceso y auditoría.",
                path
            );
            sep();
            RC_WARN
        }
        Err(e) => {
            println!("file_accessible=False path={} error={}", path, e);
            sep();
            RC_OK
        }
    }
}

// ── T1041: exfil — exfiltration marker ───────────────────────────────────────

fn cmd_exfil(data: &str) -> i32 {
    let display = if data.len() > 20 { &data[..20] } else { data };
    println!("EXFIL: {} data_len={} technique=T1041", EXFIL_MARKER, data.len());
    sep();
    println!("Simulated POST to https://exfil.invalid/upload (no real network)");
    println!("Simulated DNS query to {}.attacker.invalid", display);
    println!(
        "SYNTHETIC_EXFIL_EVENT_NO_REAL_DATA channel=dns payload_len={}",
        data.len()
    );
    println!("Synthetic egress event (no real network)");
    sep();
    RC_WARN
}

// ── T1499: dos — denial of service simulation ────────────────────────────────

fn cmd_dos(count: i64) -> i32 {
    if count <= 0 || count > 10_000 {
        eprintln!("ERROR: count must be 1-10000, got {}", count);
        return RC_ERROR;
    }
    println!("DOS_SIM: {} count={} technique=T1499", LOAD_MARKER, count);
    sep();
    // Bounded CPU burn — no real DoS
    let iters = count as u64 * 500;
    let burn: u64 = (0..iters).fold(0u64, |acc, i| acc.wrapping_add(i.wrapping_mul(i)));
    println!(
        "LOAD_SPIKE_SIMULATED: iterations={} cpu_burn={} technique=T1499",
        iters,
        burn % 1_000_000
    );
    println!("SYNTHETIC_LOAD_SPIKE: resource_exhaustion_simulation");
    println!("DoS simulation: synthetic load spike on fixture");
    sep();
    RC_WARN
}

// ── T1190: alloc — integer overflow surface ───────────────────────────────────

fn cmd_alloc(size: i64) -> i32 {
    println!(
        "ALLOC_CHECK: requested={} technique=T1190 surface=integer_overflow",
        size
    );
    sep();
    if size <= 0 {
        eprintln!(
            "WARN: input_validation_warning alloc_negative={} \
             technique=T1190 surface=integer_overflow",
            size
        );
        return RC_WARN;
    }
    if size > MAX_ALLOC {
        eprintln!(
            "WARN: input_validation_warning alloc_too_large={} max={} \
             payload_size={} technique=T1190 surface=heap_overflow",
            size, MAX_ALLOC, size
        );
        return RC_WARN;
    }
    // Rust Vec allocation — memory-safe by design, but we verify the bounds
    let v: Vec<u8> = vec![0xAAu8; size as usize];
    println!("ALLOC_OK: size={} ptr_valid=true", size);
    drop(v);
    sep();
    RC_OK
}

// ── Selftest ──────────────────────────────────────────────────────────────────

fn cmd_selftest() -> i32 {
    let mut pass = 0u32;
    let mut fail = 0u32;

    println!("SELFTEST: running all validation paths");
    sep();

    macro_rules! check {
        ($label:expr, $got:expr, $want:expr) => {{
            let rc: i32 = $got;
            if rc == $want {
                println!("PASS: {} rc={}", $label, rc);
                pass += 1;
            } else {
                println!("FAIL: {} got={} want={}", $label, rc, $want);
                fail += 1;
            }
        }};
    }

    let mut store = NoteStore::new();

    check!("T1190_overflow",      store.add(&"A".repeat(256)),       RC_WARN);
    check!("T1190_note_ok",       store.add("short note"),           RC_OK);
    check!("T1190_fmt_string",    cmd_echo("%s%n%x"),                RC_WARN);
    check!("T1190_echo_ok",       cmd_echo("hello world"),           RC_OK);
    check!("T1078_valid_auth",    cmd_auth("admin","SYNTHETIC_VALID_TOKEN_1234"), RC_OK);
    check!("T1078_bad_auth",      cmd_auth("admin","wrong"),         RC_AUTH_FAIL);
    check!("T1059_inject",        cmd_exec("ls; id"),                RC_WARN);
    check!("T1059_clean",         cmd_exec("echo hi"),               RC_OK);
    check!("T1190_alloc_neg",     cmd_alloc(-1),                     RC_WARN);
    check!("T1190_alloc_big",     cmd_alloc(MAX_ALLOC + 1),         RC_WARN);
    check!("T1190_alloc_ok",      cmd_alloc(64),                     RC_OK);
    check!("T1041_exfil",         cmd_exfil("test"),                 RC_WARN);
    check!("T1499_dos",           cmd_dos(10),                       RC_WARN);
    check!("T1021_sovereignty",   cmd_lateral("external_10.0.0.1"),  RC_WARN);
    check!("T1021_valid_lateral", cmd_lateral("api_gateway_demo"),   RC_OK);

    sep();
    println!(
        "SELFTEST_RESULT: passed={} failed={} total={}",
        pass, fail, pass + fail
    );
    if fail == 0 {
        println!("SELFTEST_OK: all validation paths exercised safely");
        RC_OK
    } else {
        eprintln!("SELFTEST_FAIL: {} tests failed", fail);
        RC_ERROR
    }
}

// ── Audit ─────────────────────────────────────────────────────────────────────

fn cmd_audit() -> i32 {
    println!("AUDIT: full_surface_scan technique=T1082,T1003,T1548,T1053,T1005,T1190");
    sep();
    cmd_env();
    cmd_privesc();
    cmd_persist();
    cmd_collect("python_orchestrator/data/assets.json");
    cmd_alloc(1);
    println!("AUDIT_COMPLETE: technique_coverage=T1082,T1003,T1548,T1053,T1005,T1190");
    RC_OK
}

// ── Usage ─────────────────────────────────────────────────────────────────────

fn usage(prog: &str) {
    println!(
        "Usage: {} <cmd> [args]\n\
         \n  add <text>         Note store (T1190 bounds check)\
         \n  list               List stored notes\
         \n  echo <input>       Format string surface (T1190)\
         \n  auth <user> <pass> Authentication (T1078, T1190)\
         \n  exec <cmd>         Injection detection (T1059)\
         \n  env                System enumeration (T1082)\
         \n  privesc            Privilege escalation surface (T1548)\
         \n  persist            Scheduled task surface (T1053)\
         \n  lateral <target>   Lateral movement (T1021)\
         \n  collect [path]     Data access (T1005, T1003)\
         \n  exfil <data>       Exfiltration marker (T1041)\
         \n  dos <count>        DoS simulation (T1499)\
         \n  alloc <size>       Integer overflow check (T1190)\
         \n  selftest           Run all test cases\
         \n  audit              Full surface scan",
        prog
    );
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage(&args[0]);
        std::process::exit(RC_OK);
    }

    let mut store = NoteStore::new();
    let cmd = args[1].as_str();
    let rc = match cmd {
        "add" => {
            if args.len() < 3 { eprintln!("ERROR: add <text>"); RC_ERROR }
            else { store.add(&args[2]) }
        }
        "list" => { store.list(); RC_OK }
        "echo" => {
            if args.len() < 3 { eprintln!("ERROR: echo <input>"); RC_ERROR }
            else { cmd_echo(&args[2]) }
        }
        "auth" => {
            if args.len() < 4 { eprintln!("ERROR: auth <user> <pass>"); RC_ERROR }
            else { cmd_auth(&args[2], &args[3]) }
        }
        "exec" => {
            if args.len() < 3 { eprintln!("ERROR: exec <cmd>"); RC_ERROR }
            else { cmd_exec(&args[2]) }
        }
        "env"     => cmd_env(),
        "privesc" => cmd_privesc(),
        "persist" => cmd_persist(),
        "lateral" => {
            if args.len() < 3 { eprintln!("ERROR: lateral <target>"); RC_ERROR }
            else { cmd_lateral(&args[2]) }
        }
        "collect" => {
            let path = args.get(2).map(String::as_str)
                .unwrap_or("python_orchestrator/data/assets.json");
            cmd_collect(path)
        }
        "exfil" => {
            if args.len() < 3 { eprintln!("ERROR: exfil <data>"); RC_ERROR }
            else { cmd_exfil(&args[2]) }
        }
        "dos" => {
            let n = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(100i64);
            cmd_dos(n)
        }
        "alloc" => {
            if args.len() < 3 { eprintln!("ERROR: alloc <size>"); RC_ERROR }
            else { args[2].parse::<i64>().map(cmd_alloc).unwrap_or_else(|_| {
                eprintln!("ERROR: size must be an integer"); RC_ERROR
            })}
        }
        "selftest" => cmd_selftest(),
        "audit"    => cmd_audit(),
        other => {
            eprintln!("ERROR: unknown command '{}'", other);
            usage(&args[0]);
            RC_ERROR
        }
    };

    // Flush stdout before exit
    let _ = io::stdout().flush();
    std::process::exit(rc);
}
