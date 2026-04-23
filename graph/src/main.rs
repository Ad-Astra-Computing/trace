//! trace-graph-builder.
//!
//! Two modes:
//!
//!   trace-graph-builder [--rev <sha>]
//!     Emit a minimal stub snapshot (hand-written single node). Preserved
//!     for the binary/schema smoke tests and for working offline.
//!
//!   trace-graph-builder extract --rev <sha> --nixpkgs <path>
//!                               --attrs a,b,c [--system <sys>] [--out <file>]
//!     Shell out to `nix eval --json --file <embedded extract.nix>` against a
//!     pinned nixpkgs and a caller-supplied attr list. Emit a schema-valid
//!     snapshot covering only the sampled attrs. reverse_closure is computed
//!     within the sample (drvPath overlap with other sampled attrs'
//!     build_inputs_drvs). CPE/PURL enrichment is deliberately left empty
//!     for v0 — Scout's identifier-lookup table is a separate layer that
//!     sits on top of this graph, not inside it.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::env;
use std::io::{self, Write};
use std::process::{Command, ExitCode, Stdio};

const SCHEMA_VERSION: &str = "1.0.0";
const DEFAULT_REV: &str = "0000000000000000000000000000000000000000";
const GENERATOR: &str = concat!("trace-graph-builder ", env!("CARGO_PKG_VERSION"));
const STUB_GENERATED_AT: &str = "2026-04-23T00:00:00Z";
const EXTRACT_NIX: &str = include_str!("nix/extract.nix");

#[derive(Serialize)]
struct Maintainer {
    #[serde(skip_serializing_if = "Option::is_none")]
    github: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Serialize)]
struct Node {
    attr_path: String,
    drv_path: String,
    pname: String,
    version: String,
    cpes: Vec<String>,
    purls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    src_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    src_hash: Option<String>,
    reverse_closure: Vec<String>,
    critical_downstreams: Vec<String>,
    maintainers: Vec<Maintainer>,
}

#[derive(Serialize)]
struct Snapshot {
    schema_version: &'static str,
    nixpkgs_rev: String,
    generator: String,
    generated_at: String,
    nodes: Vec<Node>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enrichment: Option<EnrichmentAudit>,
}

#[derive(Serialize)]
struct EnrichmentAudit {
    sources: Vec<EnrichmentSource>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    purl_mappings_applied: Vec<AppliedPurlMapping>,
}

#[derive(Serialize)]
struct EnrichmentSource {
    path: String,
    sha256: String,
}

#[derive(Serialize)]
struct AppliedPurlMapping {
    attr_path: String,
    purl: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    template: Option<String>,
    source: String,
    confidence: String,
}

#[derive(Deserialize)]
struct EnrichmentManifest {
    #[allow(dead_code)]
    schema_version: String,
    mappings: Vec<ManifestMapping>,
}

#[derive(Deserialize)]
struct ManifestMapping {
    attr_path: String,
    purls: Vec<ManifestPurlEntry>,
}

#[derive(Deserialize)]
struct ManifestPurlEntry {
    value: String,
    source: String,
    confidence: String,
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("extract") => cmd_extract(&args[1..]),
        Some("stub") => cmd_stub(&args[1..]),
        Some("--help") | Some("-h") => {
            print_usage();
            ExitCode::from(0)
        }
        // Backward compat: first arg starts with `-` → implicit stub.
        Some(s) if s.starts_with('-') => cmd_stub(&args),
        None => cmd_stub(&args),
        Some(other) => {
            eprintln!("error: unknown subcommand {:?}", other);
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn print_usage() {
    eprintln!(
        "usage: trace-graph-builder [--rev <sha>]\n\
         usage: trace-graph-builder stub [--rev <sha>]\n\
         usage: trace-graph-builder extract --rev <sha> --nixpkgs <path>\n\
         \x20                                --attrs a,b,c [--system <sys>] [--out <file>]\n\
         \x20                                [--enrichment <purls.json>]\n\
         \n\
         stub mode emits a single hand-written node (schema-valid fixture).\n\
         extract mode runs `nix eval --json` against an embedded expression.\n\
         --enrichment merges a PURL manifest into node.purls and records the\n\
         audit trail in snapshot.enrichment.\n"
    );
}

// ─── stub ───────────────────────────────────────────────────────────────────

fn cmd_stub(args: &[String]) -> ExitCode {
    let mut rev: String = DEFAULT_REV.to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_usage();
                return ExitCode::from(0);
            }
            "--rev" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --rev requires a value");
                    return ExitCode::from(2);
                }
                rev = args[i].clone();
            }
            other => {
                eprintln!("error: unknown argument {:?}", other);
                print_usage();
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let snapshot = stub_snapshot(rev);
    emit(&snapshot, None)
}

fn stub_snapshot(rev: String) -> Snapshot {
    Snapshot {
        schema_version: SCHEMA_VERSION,
        nixpkgs_rev: rev,
        generator: format!("{} (stub)", GENERATOR),
        generated_at: STUB_GENERATED_AT.to_string(),
        enrichment: None,
        nodes: vec![Node {
            attr_path: "libexample".into(),
            drv_path: "/nix/store/00000000000000000000000000000001-libexample-1.4.7.drv".into(),
            pname: "libexample".into(),
            version: "1.4.7".into(),
            cpes: vec!["cpe:2.3:a:example:libexample:1.4.7:*:*:*:*:*:*:*".into()],
            purls: vec!["pkg:generic/libexample@1.4.7".into()],
            src_url: Some("https://example.invalid/libexample-1.4.7.tar.gz".into()),
            src_hash: Some("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into()),
            reverse_closure: vec![
                "exampleApp".into(),
                "exampleServer".into(),
                "exampleCli".into(),
            ],
            critical_downstreams: vec!["exampleServer".into()],
            maintainers: vec![
                Maintainer {
                    github: Some("example-maintainer-a".into()),
                    email: None,
                    name: None,
                },
                Maintainer {
                    github: Some("example-maintainer-b".into()),
                    email: None,
                    name: None,
                },
            ],
        }],
    }
}

// ─── extract ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RawExtracted {
    attr_path: String,
    drv_path: String,
    pname: String,
    version: String,
    src_url: Option<String>,
    src_hash: Option<String>,
    #[serde(default)]
    build_inputs_drvs: Vec<String>,
    #[serde(default)]
    maintainers: Vec<RawMaintainer>,
}

#[derive(Deserialize)]
struct RawMaintainer {
    github: Option<String>,
    email: Option<String>,
    name: Option<String>,
}

fn cmd_extract(args: &[String]) -> ExitCode {
    let mut rev: Option<String> = None;
    let mut nixpkgs: Option<String> = None;
    let mut attrs_csv: Option<String> = None;
    let mut system: Option<String> = None;
    let mut out: Option<String> = None;
    let mut enrichment_path: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_usage();
                return ExitCode::from(0);
            }
            "--rev" => {
                i += 1;
                rev = match args.get(i) {
                    Some(v) => Some(v.clone()),
                    None => {
                        eprintln!("error: --rev requires a value");
                        return ExitCode::from(2);
                    }
                };
            }
            "--nixpkgs" => {
                i += 1;
                nixpkgs = match args.get(i) {
                    Some(v) => Some(v.clone()),
                    None => {
                        eprintln!("error: --nixpkgs requires a value");
                        return ExitCode::from(2);
                    }
                };
            }
            "--attrs" => {
                i += 1;
                attrs_csv = match args.get(i) {
                    Some(v) => Some(v.clone()),
                    None => {
                        eprintln!("error: --attrs requires a value");
                        return ExitCode::from(2);
                    }
                };
            }
            "--system" => {
                i += 1;
                system = args.get(i).cloned();
            }
            "--out" => {
                i += 1;
                out = args.get(i).cloned();
            }
            "--enrichment" => {
                i += 1;
                enrichment_path = args.get(i).cloned();
            }
            other => {
                eprintln!("error: unknown argument {:?}", other);
                print_usage();
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let rev = match rev {
        Some(r) if r.len() == 40 && r.chars().all(|c| c.is_ascii_hexdigit()) => r,
        Some(_) => {
            eprintln!("error: --rev must be a 40-hex commit hash");
            return ExitCode::from(2);
        }
        None => {
            eprintln!("error: extract requires --rev");
            return ExitCode::from(2);
        }
    };
    let nixpkgs = match nixpkgs {
        Some(p) => p,
        None => {
            eprintln!("error: extract requires --nixpkgs");
            return ExitCode::from(2);
        }
    };
    let attrs: Vec<String> = match attrs_csv {
        Some(s) => s
            .split(',')
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty())
            .collect(),
        None => {
            eprintln!("error: extract requires --attrs");
            return ExitCode::from(2);
        }
    };
    if attrs.is_empty() {
        eprintln!("error: --attrs parsed empty");
        return ExitCode::from(2);
    }

    let raw = match run_nix_eval(&nixpkgs, &attrs, system.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: nix eval failed: {}", e);
            return ExitCode::from(1);
        }
    };

    let mut nodes = build_nodes(raw);
    let enrichment = match enrichment_path.as_deref() {
        Some(path) => match apply_purl_enrichment(path, &mut nodes) {
            Ok(audit) => Some(audit),
            Err(e) => {
                eprintln!("error: enrichment failed: {}", e);
                return ExitCode::from(1);
            }
        },
        None => None,
    };

    let snapshot = Snapshot {
        schema_version: SCHEMA_VERSION,
        nixpkgs_rev: rev,
        generator: format!("{} (extract)", GENERATOR),
        generated_at: current_utc_timestamp(),
        nodes,
        enrichment,
    };
    emit(&snapshot, out.as_deref())
}

fn apply_purl_enrichment(
    path: &str,
    nodes: &mut [Node],
) -> Result<EnrichmentAudit, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("reading enrichment manifest {}: {}", path, e))?;
    let manifest: EnrichmentManifest = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parsing enrichment manifest {}: {}", path, e))?;

    let sha256 = hex_sha256(&bytes);

    // Index mappings by attr_path for O(1) node-side lookup.
    let mut by_attr: HashMap<String, &ManifestMapping> = HashMap::new();
    for m in &manifest.mappings {
        by_attr.insert(m.attr_path.clone(), m);
    }

    let mut applied: Vec<AppliedPurlMapping> = Vec::new();
    for node in nodes.iter_mut() {
        if let Some(mapping) = by_attr.get(&node.attr_path) {
            for entry in &mapping.purls {
                let template = if entry.value.contains("{version}") {
                    Some(entry.value.clone())
                } else {
                    None
                };
                let purl = entry.value.replace("{version}", &node.version);
                if !purl.starts_with("pkg:") {
                    return Err(format!(
                        "enrichment produced non-PURL value {:?} for {}",
                        purl, node.attr_path
                    ));
                }
                if !node.purls.iter().any(|p| p == &purl) {
                    node.purls.push(purl.clone());
                }
                applied.push(AppliedPurlMapping {
                    attr_path: node.attr_path.clone(),
                    purl,
                    template,
                    source: entry.source.clone(),
                    confidence: entry.confidence.clone(),
                });
            }
        }
    }

    Ok(EnrichmentAudit {
        sources: vec![EnrichmentSource {
            path: path.to_string(),
            sha256,
        }],
        purl_mappings_applied: applied,
    })
}

fn hex_sha256(bytes: &[u8]) -> String {
    // Tiny sha256 implementation; keeps the crate's two-dep footprint. Standard
    // library has no hash primitive; serde already pulls a lot, and adding ring
    // / sha2 just for the enrichment audit manifest is not proportionate.
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize_hex()
}

struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        let mut offset = 0;
        while offset < data.len() {
            let take = core::cmp::min(64 - self.buffer_len, data.len() - offset);
            self.buffer[self.buffer_len..self.buffer_len + take]
                .copy_from_slice(&data[offset..offset + take]);
            self.buffer_len += take;
            offset += take;
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
        }
    }

    fn finalize_hex(mut self) -> String {
        let bit_len = self.total_len.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buffer_len != 56 {
            self.update(&[0u8]);
        }
        let len_bytes = bit_len.to_be_bytes();
        self.update(&len_bytes);
        let mut out = String::with_capacity(64);
        for word in self.state {
            for b in word.to_be_bytes() {
                out.push(hex_nibble(b >> 4));
                out.push(hex_nibble(b & 0xf));
            }
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let mj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(mj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => unreachable!(),
    }
}

fn run_nix_eval(
    nixpkgs: &str,
    attrs: &[String],
    system: Option<&str>,
) -> Result<Vec<RawExtracted>, String> {
    // Write extract.nix and the spec JSON to separate temp files. Spec
    // contents carry ALL user-controlled data (nixpkgs path, attrs, system);
    // the --expr passed to nix only references the two temp file paths, which
    // are generated under Rust's control. No attacker-influenced bytes ever
    // flow through Nix expression source — the code-eval boundary collapses
    // to "can you make Rust's tempdir mount hostile?".
    let pid = std::process::id();
    let nix_path = env::temp_dir().join(format!("trace-graph-extract-{}.nix", pid));
    let spec_path = env::temp_dir().join(format!("trace-graph-extract-{}.spec.json", pid));

    std::fs::write(&nix_path, EXTRACT_NIX)
        .map_err(|e| format!("writing extract.nix to {}: {}", nix_path.display(), e))?;

    let mut spec = serde_json::Map::new();
    spec.insert("nixpkgsPath".into(), serde_json::Value::String(nixpkgs.to_string()));
    spec.insert(
        "attrs".into(),
        serde_json::Value::Array(attrs.iter().map(|a| serde_json::Value::String(a.clone())).collect()),
    );
    if let Some(sys) = system {
        if !sys.is_empty() {
            spec.insert("system".into(), serde_json::Value::String(sys.to_string()));
        }
    }
    let spec_body = serde_json::Value::Object(spec).to_string();
    std::fs::write(&spec_path, &spec_body)
        .map_err(|e| format!("writing spec to {}: {}", spec_path.display(), e))?;

    // --impure is required because extract.nix reads the spec path outside
    // the Nix store (tempdir). The expression passed here has no user data.
    let expr = format!(
        "(import {nix_path}) {{ specPath = {spec_path}; }}",
        nix_path = nix_path.display(),
        spec_path = spec_path.display(),
    );

    let mut cmd = Command::new("nix");
    cmd.args([
        "--extra-experimental-features",
        "nix-command",
        "eval",
        "--impure",
        "--json",
        "--expr",
    ]);
    cmd.arg(&expr);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd.output().map_err(|e| format!("spawning nix eval: {}", e))?;
    let _ = std::fs::remove_file(&nix_path);
    let _ = std::fs::remove_file(&spec_path);

    if !output.status.success() {
        return Err(format!(
            "nix eval exited with {}\n--- stderr ---\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    serde_json::from_slice::<Vec<RawExtracted>>(&output.stdout)
        .map_err(|e| format!("parsing nix eval JSON output: {}", e))
}

fn build_nodes(raw: Vec<RawExtracted>) -> Vec<Node> {
    // Build the direct reverse-dependent edge set within the sample:
    //   direct_reverse[A] = [ B | B in sample, A.drv_path in B.build_inputs_drvs ]
    //
    // Then compute transitive closure per attr via BFS. `reverse_closure`
    // therefore matches its name and the schema description: every attr that
    // would rebuild if this node changes, transitively, within the sample.
    let drv_to_attr: HashMap<String, String> = raw
        .iter()
        .map(|r| (r.drv_path.clone(), r.attr_path.clone()))
        .collect();

    let mut direct_reverse: HashMap<String, Vec<String>> = HashMap::new();
    for r in &raw {
        for input_drv in &r.build_inputs_drvs {
            if let Some(dep_attr) = drv_to_attr.get(input_drv) {
                if dep_attr != &r.attr_path {
                    direct_reverse
                        .entry(dep_attr.clone())
                        .or_default()
                        .push(r.attr_path.clone());
                }
            }
        }
    }

    raw.into_iter()
        .map(|r| {
            let reverse_closure = transitive_reverse_closure(&r.attr_path, &direct_reverse);
            Node {
                attr_path: r.attr_path,
                drv_path: r.drv_path,
                pname: r.pname,
                version: r.version,
                cpes: Vec::new(),
                purls: Vec::new(),
                src_url: r.src_url,
                src_hash: r.src_hash,
                reverse_closure,
                critical_downstreams: Vec::new(),
                maintainers: r
                    .maintainers
                    .into_iter()
                    .map(|m| Maintainer {
                        github: m.github,
                        email: m.email,
                        name: m.name,
                    })
                    .collect(),
            }
        })
        .collect()
}

fn transitive_reverse_closure(
    start: &str,
    direct_reverse: &HashMap<String, Vec<String>>,
) -> Vec<String> {
    // BFS over the reverse-dependent edges, excluding `start` from the result
    // so cyclic graphs (pathological in nixpkgs, possible in synthetic sets)
    // don't report a node as its own blast radius.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    if let Some(direct) = direct_reverse.get(start) {
        for n in direct {
            if n != start && seen.insert(n.clone()) {
                queue.push_back(n.clone());
            }
        }
    }
    while let Some(attr) = queue.pop_front() {
        if let Some(next) = direct_reverse.get(&attr) {
            for n in next {
                if n != start && seen.insert(n.clone()) {
                    queue.push_back(n.clone());
                }
            }
        }
    }
    seen.into_iter().collect()
}

fn current_utc_timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (y, mo, d, h, mi, s) = unix_to_ymdhms(now);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, mo, d, h, mi, s
    )
}

fn unix_to_ymdhms(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    // Howard Hinnant's civil_from_days; UTC; good for 1970..2262.
    let days = (secs / 86_400) as i64;
    let sod = (secs % 86_400) as u64;
    let hour = (sod / 3_600) as u32;
    let minute = ((sod % 3_600) / 60) as u32;
    let second = (sod % 60) as u32;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y0 = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = (if m <= 2 { y0 + 1 } else { y0 }) as i32;
    (y, m, d, hour, minute, second)
}

// ─── emit ───────────────────────────────────────────────────────────────────

fn emit(snapshot: &Snapshot, out: Option<&str>) -> ExitCode {
    let body = match serde_json::to_string_pretty(snapshot) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to serialize snapshot: {}", e);
            return ExitCode::from(1);
        }
    };
    match out {
        Some(path) => {
            if let Err(e) = std::fs::write(path, body + "\n") {
                eprintln!("error: writing {}: {}", path, e);
                return ExitCode::from(1);
            }
        }
        None => {
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            if let Err(e) = writeln!(handle, "{}", body) {
                eprintln!("error: writing stdout: {}", e);
                return ExitCode::from(1);
            }
        }
    }
    ExitCode::from(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_snapshot_serializes_to_valid_json() {
        let s = stub_snapshot(DEFAULT_REV.to_string());
        let body = serde_json::to_string(&s).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("parse");
        assert_eq!(parsed["schema_version"], "1.0.0");
        assert_eq!(parsed["nodes"].as_array().unwrap().len(), 1);
        let node = &parsed["nodes"][0];
        assert_eq!(node["attr_path"], "libexample");
        assert!(!node["reverse_closure"].as_array().unwrap().is_empty());
    }

    fn _raw(attr: &str, drv: &str, inputs: &[&str]) -> RawExtracted {
        RawExtracted {
            attr_path: attr.into(),
            drv_path: drv.into(),
            pname: attr.into(),
            version: "1".into(),
            src_url: None,
            src_hash: None,
            build_inputs_drvs: inputs.iter().map(|s| s.to_string()).collect(),
            maintainers: vec![],
        }
    }

    #[test]
    fn reverse_closure_is_transitive_within_sample() {
        // Chain: a -> b -> c -> d  (each right-hand attr build-depends on the
        // left). reverse_closure(a) must include b, c, AND d (transitive).
        let raw = vec![
            _raw("a", "/nix/store/a.drv", &[]),
            _raw("b", "/nix/store/b.drv", &["/nix/store/a.drv"]),
            _raw("c", "/nix/store/c.drv", &["/nix/store/b.drv"]),
            _raw("d", "/nix/store/d.drv", &["/nix/store/c.drv"]),
        ];
        let nodes = build_nodes(raw);
        let by_attr: std::collections::HashMap<_, _> =
            nodes.iter().map(|n| (n.attr_path.clone(), n)).collect();
        assert_eq!(
            by_attr["a"].reverse_closure,
            vec!["b".to_string(), "c".to_string(), "d".to_string()]
        );
        assert_eq!(
            by_attr["b"].reverse_closure,
            vec!["c".to_string(), "d".to_string()]
        );
        assert_eq!(by_attr["c"].reverse_closure, vec!["d".to_string()]);
        assert!(by_attr["d"].reverse_closure.is_empty());
    }

    #[test]
    fn reverse_closure_deduplicates_diamond() {
        // Diamond: b and c both depend on a; d depends on both b and c.
        // reverse_closure(a) = {b, c, d} — d once, not twice.
        let raw = vec![
            _raw("a", "/nix/store/a.drv", &[]),
            _raw("b", "/nix/store/b.drv", &["/nix/store/a.drv"]),
            _raw("c", "/nix/store/c.drv", &["/nix/store/a.drv"]),
            _raw("d", "/nix/store/d.drv", &["/nix/store/b.drv", "/nix/store/c.drv"]),
        ];
        let nodes = build_nodes(raw);
        let by_attr: std::collections::HashMap<_, _> =
            nodes.iter().map(|n| (n.attr_path.clone(), n)).collect();
        let mut rca = by_attr["a"].reverse_closure.clone();
        rca.sort();
        assert_eq!(rca, vec!["b".to_string(), "c".to_string(), "d".to_string()]);
    }

    #[test]
    fn reverse_closure_handles_cycles_without_infinite_loop() {
        // a -> b -> a (hypothetical cycle). build_nodes must terminate and
        // produce a closed set. The BFS tracks seen so cycles are safe.
        let raw = vec![
            _raw("a", "/nix/store/a.drv", &["/nix/store/b.drv"]),
            _raw("b", "/nix/store/b.drv", &["/nix/store/a.drv"]),
        ];
        let nodes = build_nodes(raw);
        let by_attr: std::collections::HashMap<_, _> =
            nodes.iter().map(|n| (n.attr_path.clone(), n)).collect();
        assert_eq!(by_attr["a"].reverse_closure, vec!["b".to_string()]);
        assert_eq!(by_attr["b"].reverse_closure, vec!["a".to_string()]);
    }

    #[test]
    fn sha256_matches_known_vectors() {
        // Known SHA-256 vectors.
        assert_eq!(
            hex_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn timestamp_is_rfc3339_utc() {
        let ts = current_utc_timestamp();
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
        assert!(&ts[4..5] == "-" && &ts[7..8] == "-");
        assert!(&ts[10..11] == "T" && &ts[13..14] == ":" && &ts[16..17] == ":");
    }
}
