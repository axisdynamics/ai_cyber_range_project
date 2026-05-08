/*
 * lab_service.c — AI Cyber Range Lab Service v2.0
 * ================================================
 * Multi-vulnerability synthetic attack surface for authorized red team exercises.
 * Covers 11 ATT&CK techniques across 14 subcommands.
 *
 * Techniques exercised:
 *   T1190  Exploit Public-Facing Application
 *   T1059  Command and Scripting Interpreter
 *   T1078  Valid Accounts
 *   T1548  Abuse Elevation Control Mechanism
 *   T1082  System Information Discovery
 *   T1003  OS Credential Dumping
 *   T1021  Remote Services (Lateral Movement)
 *   T1005  Data from Local System
 *   T1041  Exfiltration Over C2 Channel
 *   T1499  Endpoint Denial of Service
 *   T1053  Scheduled Task/Job
 *
 * IMPORTANT: Synthetic lab target only. No real exploitation occurs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <limits.h>

#ifdef __linux__
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif

/* ── Constants ── */
#define MAX_NOTE       64
#define MAX_NOTES      16
#define AUTH_BUF       128
#define MAX_ALLOC      (1024*1024)
#define EXFIL_MARKER   "SYNTHETIC_EXFIL_EVENT_NO_REAL_DATA"
#define LATERAL_MARKER "SYNTHETIC_PIVOT_REQUEST"
#define PRIVESC_MARKER "SYNTHETIC_PRIVILEGE_TEST"
#define CRON_MARKER    "SYNTHETIC_CRON_ENTRY"
#define LOAD_MARKER    "SYNTHETIC_LOAD_SPIKE"

#define RC_OK        0
#define RC_WARN      3
#define RC_AUTH_FAIL 10
#define RC_ERROR     1

/* ── State ── */
static char notes[MAX_NOTES][MAX_NOTE];
static int  note_count = 0;

static const char *SYNTHETIC_USERS[] = {
    "admin","root","service_account","api_user",NULL
};
static const char *SYNTHETIC_PASS = "SYNTHETIC_VALID_TOKEN_1234";

/* ── Utilities ── */
static void print_sep(void) {
    printf("─────────────────────────────────────────────\n");
}

static int safe_copy(char *dst, const char *src, size_t dst_size) {
    size_t src_len = strnlen(src, dst_size + 1);
    if (src_len >= dst_size) {
        fprintf(stderr,
            "WARN: input_validation_warning src_len=%zu dst_size=%zu (truncated)\n",
            src_len, dst_size);
        memcpy(dst, src, dst_size - 1);
        dst[dst_size - 1] = '\0';
        return RC_WARN;
    }
    memcpy(dst, src, src_len + 1);
    return RC_OK;
}

/* Constant-time comparison (prevent timing oracle on password checks) */
static int ct_memcmp(const void *a, const void *b, size_t n) {
    volatile const unsigned char *p = a, *q = b;
    volatile unsigned char result = 0;
    for (size_t i = 0; i < n; i++) result |= p[i] ^ q[i];
    return (int)result;
}

/* ── T1190: add — buffer overflow / bounds check ── */
static int cmd_add(const char *input) {
    size_t len = strnlen(input, MAX_NOTE + 128);
    if (note_count >= MAX_NOTES) {
        fprintf(stderr,"ERROR: note capacity reached (max=%d)\n",MAX_NOTES);
        return RC_ERROR;
    }
    if (len >= MAX_NOTE) {
        fprintf(stderr,
            "WARN: input_validation_warning note_len=%zu max=%d "
            "technique=T1190 surface=stack_overflow\n", len, MAX_NOTE-1);
        safe_copy(notes[note_count], input, MAX_NOTE);
        note_count++;
        return RC_WARN;
    }
    safe_copy(notes[note_count], input, MAX_NOTE);
    note_count++;
    printf("NOTE_ADDED: slot=%d len=%zu\n", note_count, len);
    return RC_OK;
}

static void cmd_list(void) {
    if (!note_count) { printf("(no notes)\n"); return; }
    for (int i = 0; i < note_count; i++)
        printf("%d: %s\n", i+1, notes[i]);
}

/* ── T1190: echo — format string surface ── */
static int cmd_echo(const char *input) {
    if (strchr(input,'%')) {
        fprintf(stderr,
            "WARN: input_validation_warning format_specifiers_detected "
            "technique=T1190 surface=format_string\n");
        printf("ECHO_SANITIZED: [format specifiers stripped]\n");
        return RC_WARN;
    }
    printf("ECHO: %s\n", input);
    return RC_OK;
}

/* ── T1078 + T1190: auth — timing oracle + stack overflow ── */
static int cmd_auth(const char *username, const char *password) {
    char ubuf[AUTH_BUF], pbuf[AUTH_BUF];
    int r1 = safe_copy(ubuf, username, sizeof(ubuf));
    int r2 = safe_copy(pbuf, password, sizeof(pbuf));
    if (r1 == RC_WARN || r2 == RC_WARN)
        fprintf(stderr,"WARN: input_validation_warning auth_overflow "
            "technique=T1190,T1078 surface=stack_overflow\n");

    int found = 0;
    for (int i = 0; SYNTHETIC_USERS[i]; i++)
        if (!strcmp(ubuf, SYNTHETIC_USERS[i])) { found=1; break; }
    if (!found) {
        fprintf(stderr,"AUTH_FAIL: unknown_user=%s technique=T1078\n", ubuf);
        return RC_AUTH_FAIL;
    }

    char pa[AUTH_BUF]={0}, pe[AUTH_BUF]={0};
    size_t pl = strlen(SYNTHETIC_PASS);
    size_t il = strlen(pbuf);
    memcpy(pa, pbuf,           il < AUTH_BUF ? il : AUTH_BUF-1);
    memcpy(pe, SYNTHETIC_PASS, pl < AUTH_BUF ? pl : AUTH_BUF-1);
    if (ct_memcmp(pa, pe, AUTH_BUF) != 0) {
        struct timespec ts = {0, 50000000L};
        nanosleep(&ts, NULL);
        fprintf(stderr,"AUTH_FAIL: invalid_password user=%s technique=T1078\n", ubuf);
        return RC_AUTH_FAIL;
    }

    printf("AUTH_OK: SYNTHETIC_VALID_TOKEN_1234 user=%s technique=T1078\n", ubuf);
    printf("credential_check: access_granted=true user=%s\n", ubuf);
    return RC_OK;
}

/* ── T1059: exec — command injection surface ── */
static int cmd_exec(const char *input) {
    const char *bad[] = {";","&&","||","|","`","$(","${",">","<",NULL};
    int inj = 0;
    for (int i = 0; bad[i]; i++)
        if (strstr(input, bad[i])) {
            inj = 1;
            fprintf(stderr,
                "WARN: input_validation_warning shell_metacharacter='%s' "
                "technique=T1059 surface=command_injection\n", bad[i]);
        }
    if (inj) {
        printf("EXEC_BLOCKED: injection_detected technique=T1059\n");
        return RC_WARN;
    }
    printf("EXEC_SIMULATED: cmd='%.100s' technique=T1059 mode=synthetic\n", input);
    printf("Command execution via scripting interpreter (echo only)\n");
    return RC_OK;
}

/* ── T1082: env — system information discovery ── */
static int cmd_env(void) {
    printf("ENV_DISCLOSURE: technique=T1082 surface=system_enumeration\n");
    print_sep();
#ifdef __linux__
    {
        FILE *f = fopen("/etc/os-release","r");
        if (f) {
            char line[256]; int n=0;
            while (fgets(line,sizeof(line),f) && n<4) { printf("OS: %s",line); n++; }
            fclose(f);
        }
        printf("PID=%d PPID=%d UID=%d EUID=%d\n",
               (int)getpid(),(int)getppid(),(int)getuid(),(int)geteuid());
    }
    const char *evars[]={"PATH","HOME","SHELL","USER","LOGNAME",NULL};
    for (int i=0; evars[i]; i++) {
        char *v = getenv(evars[i]);
        if (v) printf("ENV_%s=%s\n",evars[i],v);
    }
#else
    printf("OS: synthetic_lab\nPID=synthetic PPID=synthetic\n");
#endif
    printf("enumerate_fixtures: technique=T1082 discovery=true\n");
    print_sep();
    return RC_OK;
}

/* ── T1548: privesc — privilege escalation surface ── */
static int cmd_privesc(void) {
    printf("PRIVESC_CHECK: %s technique=T1548\n", PRIVESC_MARKER);
    print_sep();
    int findings = 0;
#ifdef __linux__
    if (geteuid() == 0) {
        printf("FINDING: running_as_root=true severity=critical technique=T1548\n");
        findings++;
    }
    const char *suid_bins[]={
        "/usr/bin/sudo","/usr/bin/pkexec","/usr/bin/su",
        "/usr/bin/python3","/bin/bash",NULL
    };
    for (int i=0; suid_bins[i]; i++) {
        struct stat st;
        if (!stat(suid_bins[i],&st) && (st.st_mode & S_ISUID)) {
            printf("FINDING: suid_binary=%s mode=%o technique=T1548\n",
                   suid_bins[i], st.st_mode & 07777);
            findings++;
        }
    }
    {
        FILE *f = fopen("/proc/self/status","r");
        if (f) {
            char line[256];
            while (fgets(line,sizeof(line),f))
                if (!strncmp(line,"Cap",3)) printf("CAP: %s",line);
            fclose(f);
        }
    }
#endif
    printf("SYNTHETIC_PRIVILEGE_TEST: escalation_path_simulation technique=T1548\n");
    printf("Privilege escalation path simulation\n");
    printf("privesc_findings=%d technique=T1548\n", findings);
    print_sep();
    return findings > 0 ? RC_WARN : RC_OK;
}

/* ── T1053: persist — scheduled task surface ── */
static int cmd_persist(void) {
    printf("PERSIST_CHECK: %s technique=T1053\n", CRON_MARKER);
    print_sep();
#ifdef __linux__
    const char *cron_paths[]={"/etc/crontab","/etc/cron.d","/var/spool/cron",NULL};
    for (int i=0; cron_paths[i]; i++) {
        struct stat st;
        if (!stat(cron_paths[i],&st))
            printf("CRON_EXISTS: %s perms=%o technique=T1053\n",
                   cron_paths[i], st.st_mode & 07777);
    }
#endif
    printf("SYNTHETIC_CRON_ENTRY: scheduled_task simulation technique=T1053\n");
    printf("Scheduled task simulation (no real task created)\n");
    print_sep();
    return RC_OK;
}

/* ── T1021: lateral — lateral movement simulation ── */
static int cmd_lateral(const char *target) {
    const char *allowed[]={
        "api_gateway_demo","iam_role_demo","pipeline_demo",
        "cloud_storage_demo","secrets_store_demo",NULL
    };
    int valid = 0;
    for (int i=0; allowed[i]; i++)
        if (!strcmp(target,allowed[i])) { valid=1; break; }
    if (!valid) {
        fprintf(stderr,
            "SOVEREIGNTY_VIOLATION: target='%s' not authorized "
            "allow_external_targets=false technique=T1021\n", target);
        return RC_WARN;
    }
    printf("LATERAL_MOVE: %s target=%s technique=T1021 mode=synthetic\n",
           LATERAL_MARKER, target);
    printf("Lateral movement simulation between local fixture assets\n");
    print_sep();
    return RC_OK;
}

/* ── T1005+T1003: collect — data access and credential surface ── */
static int cmd_collect(const char *path) {
    printf("COLLECT: path=%s technique=T1005,T1003\n", path);
    print_sep();
    struct stat st;
    int ok = (!stat(path,&st));
    if (ok) {
        printf("file_accessible=True path=%s size=%lld perms=%o\n",
               path,(long long)st.st_size, st.st_mode & 07777);
        if (strstr(path,"credential")||strstr(path,"password")||
            strstr(path,"secret")||strstr(path,"shadow")||strstr(path,"assets.json")) {
            printf("SENSITIVE_FILE_ACCESS: path=%s technique=T1003,T1005 "
                   "data_classification=confidential\n", path);
            fprintf(stderr,"WARN: sensitive_data_access path=%s technique=T1003\n",path);
        }
        FILE *f = fopen(path,"r");
        if (f) {
            char buf[128];
            if (fgets(buf,sizeof(buf),f)) printf("FIRST_LINE: %.80s\n",buf);
            fclose(f);
        }
        printf("Fixture de datos '%s' es accesible sin autenticación adicional.\n",path);
        printf("Validar controles de acceso y auditoría.\n");
    } else {
        printf("file_accessible=False path=%s errno=%d\n",path,errno);
    }
    print_sep();
    return ok ? RC_WARN : RC_OK;
}

/* ── T1041: exfil — exfiltration simulation ── */
static int cmd_exfil(const char *data) {
    printf("EXFIL: %s data_len=%zu technique=T1041\n",EXFIL_MARKER,strlen(data));
    print_sep();
    printf("Simulated POST to https://exfil.invalid/upload (no real network)\n");
    printf("Simulated DNS query to %.20s.attacker.invalid\n", data);
    printf("SYNTHETIC_EXFIL_EVENT_NO_REAL_DATA channel=dns payload_len=%zu\n",strlen(data));
    printf("Synthetic egress event (no real network)\n");
    print_sep();
    return RC_WARN;
}

/* ── T1499: dos — denial of service simulation ── */
static int cmd_dos(int count) {
    if (count<=0||count>10000) {
        fprintf(stderr,"ERROR: count must be 1-10000, got %d\n",count);
        return RC_ERROR;
    }
    printf("DOS_SIM: %s count=%d technique=T1499\n",LOAD_MARKER,count);
    print_sep();
    volatile unsigned long s=0;
    for (int i=0; i<count*500; i++) s += (unsigned long)i*i;
    printf("LOAD_SPIKE_SIMULATED: iterations=%d cpu_burn=%lu technique=T1499\n",
           count*500, s%1000000);
    printf("SYNTHETIC_LOAD_SPIKE: resource_exhaustion_simulation\n");
    printf("DoS simulation: synthetic load spike on fixture\n");
    print_sep();
    return RC_WARN;
}

/* ── T1190: alloc — integer overflow / heap surface ── */
static int cmd_alloc(long size) {
    printf("ALLOC_CHECK: requested=%ld technique=T1190 surface=integer_overflow\n",size);
    print_sep();
    if (size <= 0) {
        fprintf(stderr,"WARN: input_validation_warning alloc_negative=%ld "
            "technique=T1190 surface=integer_overflow\n",size);
        return RC_WARN;
    }
    if (size > MAX_ALLOC) {
        fprintf(stderr,"WARN: input_validation_warning alloc_too_large=%ld max=%d "
            "payload_size=%ld technique=T1190 surface=heap_overflow\n",
            size, MAX_ALLOC, size);
        return RC_WARN;
    }
    void *p = malloc((size_t)size);
    if (!p) { fprintf(stderr,"ALLOC_FAIL: errno=%d\n",errno); return RC_ERROR; }
    memset(p, 0xAA, (size_t)size);
    printf("ALLOC_OK: size=%ld ptr_valid=true\n",size);
    free(p);
    print_sep();
    return RC_OK;
}

/* ── Selftest ── */
static int cmd_selftest(void) {
    int pass=0, fail=0;
    printf("SELFTEST: running all validation paths\n");
    print_sep();

    #define CHECK(label, expr, want) \
        do { int rc=(expr); \
             if(rc==want){printf("PASS: %s rc=%d\n",label,rc);pass++;} \
             else{printf("FAIL: %s got=%d want=%d\n",label,rc,want);fail++;} \
        } while(0)

    char big[256]; memset(big,'A',255); big[255]='\0';
    CHECK("T1190_overflow",       cmd_add(big),             RC_WARN);
    CHECK("T1190_note_ok",        cmd_add("short note"),    RC_OK);
    CHECK("T1190_fmt_string",     cmd_echo("%s%n%x"),       RC_WARN);
    CHECK("T1190_echo_ok",        cmd_echo("hello world"),  RC_OK);
    CHECK("T1078_valid_auth",     cmd_auth("admin","SYNTHETIC_VALID_TOKEN_1234"), RC_OK);
    CHECK("T1078_bad_auth",       cmd_auth("admin","wrong"), RC_AUTH_FAIL);
    CHECK("T1059_inject",         cmd_exec("ls; id"),       RC_WARN);
    CHECK("T1059_clean",          cmd_exec("echo hi"),      RC_OK);
    CHECK("T1190_alloc_neg",      cmd_alloc(-1),            RC_WARN);
    CHECK("T1190_alloc_big",      cmd_alloc(MAX_ALLOC+1),   RC_WARN);
    CHECK("T1190_alloc_ok",       cmd_alloc(64),            RC_OK);
    CHECK("T1041_exfil",          cmd_exfil("test"),        RC_WARN);
    CHECK("T1499_dos",            cmd_dos(10),              RC_WARN);
    CHECK("T1021_sovereignty",    cmd_lateral("external_10.0.0.1"), RC_WARN);
    CHECK("T1021_valid_lateral",  cmd_lateral("api_gateway_demo"),  RC_OK);

    #undef CHECK

    print_sep();
    printf("SELFTEST_RESULT: passed=%d failed=%d total=%d\n",pass,fail,pass+fail);
    if (!fail) { printf("SELFTEST_OK: all validation paths exercised safely\n"); return RC_OK; }
    fprintf(stderr,"SELFTEST_FAIL: %d tests failed\n",fail);
    return RC_ERROR;
}

/* ── Audit ── */
static int cmd_audit(void) {
    printf("AUDIT: full_surface_scan technique=T1082,T1003,T1548,T1053,T1005,T1190\n");
    print_sep();
    cmd_env();
    cmd_privesc();
    cmd_persist();
    cmd_collect("python_orchestrator/data/assets.json");
    cmd_alloc(1);
    printf("AUDIT_COMPLETE\n");
    return RC_OK;
}

/* ── Main ── */
static void usage(const char *p) {
    printf("Usage: %s <cmd> [args]\n"
           "  add <text> | list | echo <in> | auth <u> <p>\n"
           "  exec <cmd> | env | privesc | persist\n"
           "  lateral <target> | collect [path] | exfil <data>\n"
           "  dos <count> | alloc <size> | selftest | audit\n", p);
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return RC_OK; }
    const char *c = argv[1];
    if (!strcmp(c,"add"))       return argc>2 ? cmd_add(argv[2])           : (fprintf(stderr,"ERROR: add <text>\n"),RC_ERROR);
    if (!strcmp(c,"list"))      { cmd_list(); return RC_OK; }
    if (!strcmp(c,"echo"))      return argc>2 ? cmd_echo(argv[2])          : (fprintf(stderr,"ERROR: echo <in>\n"),RC_ERROR);
    if (!strcmp(c,"auth"))      return argc>3 ? cmd_auth(argv[2],argv[3])  : (fprintf(stderr,"ERROR: auth <u> <p>\n"),RC_ERROR);
    if (!strcmp(c,"exec"))      return argc>2 ? cmd_exec(argv[2])          : (fprintf(stderr,"ERROR: exec <cmd>\n"),RC_ERROR);
    if (!strcmp(c,"env"))       return cmd_env();
    if (!strcmp(c,"privesc"))   return cmd_privesc();
    if (!strcmp(c,"persist"))   return cmd_persist();
    if (!strcmp(c,"lateral"))   return argc>2 ? cmd_lateral(argv[2])       : (fprintf(stderr,"ERROR: lateral <target>\n"),RC_ERROR);
    if (!strcmp(c,"collect"))   return cmd_collect(argc>2 ? argv[2] : "python_orchestrator/data/assets.json");
    if (!strcmp(c,"exfil"))     return argc>2 ? cmd_exfil(argv[2])         : (fprintf(stderr,"ERROR: exfil <data>\n"),RC_ERROR);
    if (!strcmp(c,"dos"))       return cmd_dos(argc>2 ? atoi(argv[2]) : 100);
    if (!strcmp(c,"alloc"))     return argc>2 ? cmd_alloc(atol(argv[2]))   : (fprintf(stderr,"ERROR: alloc <size>\n"),RC_ERROR);
    if (!strcmp(c,"selftest"))  return cmd_selftest();
    if (!strcmp(c,"audit"))     return cmd_audit();
    fprintf(stderr,"ERROR: unknown command '%s'\n",c);
    usage(argv[0]);
    return RC_ERROR;
}
