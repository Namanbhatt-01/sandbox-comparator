/**
 * Browser-Level DOM XSS Regression Test Suite using JSDOM.
 * Directly executes web/static/index.html in a WHATWG-compliant DOM environment
 * and verifies that malicious payloads in process names, file names, URLs,
 * lineage paths, and limitation descriptions cannot execute scripts or inject raw DOM tags.
 */

const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

function runDomSecuritySuite() {
  const candidateRoot = fs.existsSync(path.join(__dirname, 'web', 'static', 'index.html'))
    ? __dirname
    : path.join(__dirname, '..');
  const htmlPath = path.join(candidateRoot, 'web', 'static', 'index.html');
  const htmlContent = fs.readFileSync(htmlPath, 'utf8');

  // Set up virtual DOM with script execution enabled
  const dom = new JSDOM(htmlContent, {
    runScripts: 'dangerously',
    resources: 'usable',
    url: 'http://127.0.0.1:8000/'
  });

  const { window } = dom;
  const { document } = window;

  // Global canary that any successful XSS execution would flip to true
  window.XSS_EXECUTED = false;
  window.xssCanary = () => {
    window.XSS_EXECUTED = true;
  };

  const hostilePayload = {
    sample_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    report_a_id: "report_a<script>window.XSS_EXECUTED=true</script>",
    report_b_id: "report_b<img src=x onerror='window.XSS_EXECUTED=true'>",
    provenance_metadata: {},
    metrics: {
      matched_processes: 1,
      unresolved_processes: 0,
      matched_files: 1,
      unresolved_files: 0,
      matched_network: 1,
      unresolved_network: 0,
      total_limitations: 1
    },
    analysis_summary: {
      verdict: "CORROBORATED COMPROMISE<script>window.XSS_EXECUTED=true</script>",
      text: "Compromise observed <img src=x onerror='window.XSS_EXECUTED=true'>"
    },
    investigation_findings: [
      {
        title: "Malicious Finding <script>window.XSS_EXECUTED=true</script>",
        category: "EXECUTION\"><script>window.XSS_EXECUTED=true</script>",
        severity: "CRITICAL\"><script>window.XSS_EXECUTED=true</script>",
        detail: "Hostile detail <svg onload='window.XSS_EXECUTED=true'>"
      }
    ],
    mitre_tactics: [
      {
        id: "TA0002<script>window.XSS_EXECUTED=true</script>",
        name: "Execution <img src=x onerror='window.XSS_EXECUTED=true'>",
        technique: "T1059 <svg onload='window.XSS_EXECUTED=true'>"
      }
    ],
    reconciled_processes: [
      {
        image: "bad_proc.exe\"><script>window.XSS_EXECUTED=true</script>",
        image_name: "bad_proc.exe\"><script>window.XSS_EXECUTED=true</script>",
        lineage_path: ["explorer.exe", "cmd.exe\"><svg onload='window.XSS_EXECUTED=true'>"],
        depth: 2,
        observation_presence: "OBSERVED_IN_BOTH",
        confidence: "MATCHED",
        heuristic_similarity_score: 0.95,
        matching_rationale: "Matched by identical name",
        causal_explanation: "CORROBORATED_EXECUTION",
        epistemic_interpretation: "Corroborated execution <script>window.XSS_EXECUTED=true</script>",
        pids: { "rep_a": "100<script>window.XSS_EXECUTED=true</script>", "rep_b": "200" },
        commands: {},
        evidence_pointers: {
          "rep_a": {
            report_id: "rep_a",
            json_pointer: "/behavior/processes/0\"><script>window.XSS_EXECUTED=true</script>",
            event_summary: "PID created <img src=x onerror='window.XSS_EXECUTED=true'>",
            is_available: true,
            raw_snippet: { cmd: "<script>window.XSS_EXECUTED=true</script>" }
          }
        },
        alternatives: []
      }
    ],
    reconciled_files: [
      {
        sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        observation_presence: "OBSERVED_IN_BOTH",
        causal_explanation: "CORROBORATED_EXECUTION",
        filenames: {
          "report_a<script>window.XSS_EXECUTED=true</script>": "dropped_evil.exe\"><script>window.XSS_EXECUTED=true</script>",
          "report_b<img src=x onerror='window.XSS_EXECUTED=true'>": "target.exe\"><img src=x onerror='window.XSS_EXECUTED=true'>"
        },
        paths: {},
        epistemic_interpretation: "Dropped file confirmed <script>window.XSS_EXECUTED=true</script>",
        is_malformed_hash: false,
        evidence_pointers: {
          "report_a": {
            report_id: "report_a",
            json_pointer: "/behavior/dropped/0\"><script>window.XSS_EXECUTED=true</script>",
            event_summary: "Dropped file <script>window.XSS_EXECUTED=true</script>",
            is_available: true,
            raw_snippet: { file: "test<script>window.XSS_EXECUTED=true</script>" }
          }
        }
      }
    ],
    reconciled_network: [
      {
        connection: "evil-c2.com:443\"><script>window.XSS_EXECUTED=true</script>",
        observation_presence: "OBSERVED_IN_BOTH",
        connection_state: "ESTABLISHED\"><script>window.XSS_EXECUTED=true</script>",
        causal_status: "UNEXPLAINED\"><script>window.XSS_EXECUTED=true</script>",
        causal_explanation: "UNEXPLAINED",
        policy_record: "BLOCK_PORT_443\"><script>window.XSS_EXECUTED=true</script>",
        cross_report_correlation: "DIRECT_MATCH",
        epistemic_interpretation: "C2 observed <script>window.XSS_EXECUTED=true</script>",
        observed_in: ["rep_a"],
        unobserved_in: [],
        evidence_pointers: {
          "rep_a": {
            report_id: "rep_a",
            json_pointer: "/behavior/network/dns/0\"><script>window.XSS_EXECUTED=true</script>",
            event_summary: "DNS query <script>window.XSS_EXECUTED=true</script>",
            is_available: true,
            raw_snippet: { host: "evil" }
          }
        }
      }
    ],
    collection_limitations: {
      "report_a": [
        {
          code: "TIMEOUT_<script>window.XSS_EXECUTED=true</script>",
          description: "Execution timed out <img src=x onerror='window.XSS_EXECUTED=true'>",
          category: "TIMEOUT\"><script>window.XSS_EXECUTED=true</script>",
          target_pattern: "net:<script>window.XSS_EXECUTED=true</script>",
          evidence: null
        }
      ]
    }
  };

  // 1. Render hostile comparison into the live DOM
  window.renderComparison(hostilePayload);

  // Assert canary was never triggered
  if (window.XSS_EXECUTED) {
    throw new Error("FAIL: window.XSS_EXECUTED was set to true during initial table render!");
  }

  // 2. Verify that NO unescaped <script>, <img>, <svg>, or rogue event handlers were injected as elements
  const containers = [
    'tbody-procs',
    'tbody-files',
    'tbody-net',
    'tbody-lims',
    'analysis-card',
    'investigation-findings-grid',
    'analysis-mitre-chips'
  ];
  for (const tid of containers) {
    const el = document.getElementById(tid);
    if (!el) {
      throw new Error(`FAIL: Element #${tid} not found in DOM`);
    }
    
    // Check for injected active elements
    const scripts = el.getElementsByTagName('script');
    if (scripts.length > 0) {
      throw new Error(`FAIL: Found ${scripts.length} unescaped <script> element(s) in #${tid}!`);
    }
    const svgs = el.getElementsByTagName('svg');
    if (svgs.length > 0) {
      throw new Error(`FAIL: Injected raw <svg> element found in #${tid}!`);
    }
    const imgs = el.getElementsByTagName('img');
    if (imgs.length > 0) {
      throw new Error(`FAIL: Injected raw <img> element found in #${tid}!`);
    }

    // Check for rogue event handler attributes on any child element
    const rogueOnload = el.querySelectorAll('[onload]');
    if (rogueOnload.length > 0) {
      throw new Error(`FAIL: Found element with rogue onload attribute in #${tid}!`);
    }
    const rogueOnerror = el.querySelectorAll('[onerror]');
    if (rogueOnerror.length > 0) {
      throw new Error(`FAIL: Found element with rogue onerror attribute in #${tid}!`);
    }
    const rogueOnmouse = el.querySelectorAll('[onmouseover]');
    if (rogueOnmouse.length > 0) {
      throw new Error(`FAIL: Found element with rogue onmouseover attribute in #${tid}!`);
    }

    // For any onclick handlers, ensure they strictly call openEvidenceByIndex with an integer argument
    const onclickEls = el.querySelectorAll('[onclick]');
    onclickEls.forEach(target => {
      const onclickAttr = target.getAttribute('onclick') || '';
      if (!/^openEvidenceByIndex\(\d+\)$/.test(onclickAttr)) {
        throw new Error(`FAIL: Unauthorized or non-numeric onclick attribute found: "${onclickAttr}"`);
      }
    });
  }

  // 3. Test Drawer Evidence Inspector
  // Click all evidence entries registered in evidenceRegistry
  const regLength = window.evidenceRegistry ? window.evidenceRegistry.length : 0;
  if (regLength === 0) {
    throw new Error("FAIL: evidenceRegistry is empty; expected registered evidence items.");
  }

  for (let i = 0; i < regLength; i++) {
    window.openEvidenceByIndex(i);
    if (window.XSS_EXECUTED) {
      throw new Error(`FAIL: XSS executed when opening evidence drawer for index ${i}!`);
    }
    const drawer = document.getElementById('drawer');
    if (drawer.getElementsByTagName('script').length > 0) {
      throw new Error("FAIL: <script> tag created in drawer!");
    }
    const rogueOnerror = drawer.querySelectorAll('[onerror]');
    if (rogueOnerror.length > 0) {
      throw new Error("FAIL: Rogue onerror handler in drawer!");
    }
  }

  console.log(`PASS: Browser-level DOM security suite verified across ${containers.length} containers and ${regLength} drawer evidence items (0 script executions, 0 injected elements, 0 rogue attributes).`);
}

try {
  runDomSecuritySuite();
  process.exit(0);
} catch (err) {
  console.error("DOM XSS Suite FAILED:", err.message);
  process.exit(1);
}
