//! qbind-envelope: CLI tool for upgrade envelope inspection and verification (T225).
//!
//! This tool allows MainNet operators to:
//!
//! - Inspect upgrade envelopes (human-readable summary)
//! - Verify envelope signatures against council keyset
//! - Verify binary hashes against local files
//!
//! # Usage
//!
//! ```bash
//! # Inspect an envelope
//! qbind-envelope inspect envelope.json
//!
//! # Verify an envelope with all checks
//! qbind-envelope verify \
//!     --envelope envelope.json \
//!     --council-keys council-pubkeys.json \
//!     --binary /usr/local/bin/qbind-node \
//!     --platform linux-x86_64
//!
//! # Verify signatures only (no binary hash check)
//! qbind-envelope verify \
//!     --envelope envelope.json \
//!     --council-keys council-pubkeys.json
//! ```
//!
//! # Exit Codes
//!
//! - 0: Success (verification passed)
//! - 1: Verification failed (threshold not met, invalid signatures, etc.)
//! - 2: Invalid arguments or I/O error

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use qbind_gov::{
    sha3_256_file_hex, verify_envelope, CouncilKeySet, UpgradeEnvelope,
};

/// Exit codes for the CLI.
mod exit_codes {
    pub const SUCCESS: u8 = 0;
    pub const VERIFICATION_FAILED: u8 = 1;
    pub const INVALID_ARGS: u8 = 2;
}

/// qbind-envelope: Upgrade envelope inspection and verification tool.
#[derive(Parser, Debug)]
#[command(
    name = "qbind-envelope",
    version = "0.1.0",
    author = "QBIND Team",
    about = "Upgrade envelope inspection and verification tool (T225)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Inspect an upgrade envelope (human-readable summary).
    Inspect {
        /// Path to the upgrade envelope JSON file.
        envelope: PathBuf,
    },

    /// Verify an upgrade envelope (signatures, binary hash, threshold).
    Verify {
        /// Path to the upgrade envelope JSON file.
        #[arg(short, long)]
        envelope: PathBuf,

        /// Path to the council public keys JSON file.
        #[arg(short = 'k', long)]
        council_keys: PathBuf,

        /// Path to a local binary to verify hash against (optional).
        #[arg(short, long)]
        binary: Option<PathBuf>,

        /// Platform ID for binary hash verification (e.g., "linux-x86_64").
        #[arg(short, long, default_value = "linux-x86_64")]
        platform: String,

        /// Output format: "text" (default) or "json".
        #[arg(long, default_value = "text")]
        output: String,
    },

    /// Show the envelope digest (SHA3-256 hash for signing).
    Digest {
        /// Path to the upgrade envelope JSON file.
        envelope: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Inspect { envelope } => cmd_inspect(&envelope),
        Commands::Verify {
            envelope,
            council_keys,
            binary,
            platform,
            output,
        } => cmd_verify(&envelope, &council_keys, binary.as_deref(), &platform, &output),
        Commands::Digest { envelope } => cmd_digest(&envelope),
    }
}

/// Handle the 'inspect' subcommand.
fn cmd_inspect(envelope_path: &std::path::Path) -> ExitCode {
    // Load envelope
    let envelope = match UpgradeEnvelope::from_file(envelope_path) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error loading envelope: {}", e);
            return ExitCode::from(exit_codes::INVALID_ARGS);
        }
    };

    // Print human-readable summary
    println!("=== Upgrade Envelope ===");
    println!();
    println!("Envelope ID:        {}", envelope.envelope_id);
    println!("Envelope Version:   {}", envelope.envelope_version);
    println!("Protocol Version:   {}", envelope.protocol_version);
    println!("Network:            {}", envelope.network_environment);
    println!("Upgrade Class:      {}", envelope.class);

    if !envelope.version.is_empty() {
        println!("Version:            {}", envelope.version);
    }

    if envelope.activation_height > 0 {
        println!("Activation Height:  {}", envelope.activation_height);
    }

    println!();
    println!("Binary Hashes:");
    if envelope.binary_hashes.is_empty() {
        println!("  (none)");
    } else {
        for (platform, hash) in &envelope.binary_hashes {
            println!("  {}: {}", platform, hash.as_str());
        }
    }

    println!();
    println!("Council Approvals:  {} signature(s)", envelope.approval_count());
    for approval in &envelope.council_approvals {
        println!("  - {} ({})", approval.member_id, approval.timestamp);
    }

    if !envelope.notes.is_empty() {
        println!();
        println!("Notes:");
        println!("  {}", envelope.notes);
    }

    // Validate structure
    println!();
    if let Err(e) = envelope.validate() {
        println!("⚠ Validation Warning: {}", e);
    } else {
        println!("✓ Structure validation passed");
    }

    ExitCode::from(exit_codes::SUCCESS)
}

/// Handle the 'verify' subcommand.
fn cmd_verify(
    envelope_path: &std::path::Path,
    keyset_path: &std::path::Path,
    binary_path: Option<&std::path::Path>,
    platform: &str,
    output: &str,
) -> ExitCode {
    // Load envelope
    let envelope = match UpgradeEnvelope::from_file(envelope_path) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error loading envelope: {}", e);
            return ExitCode::from(exit_codes::INVALID_ARGS);
        }
    };

    // Load keyset
    let keyset = match CouncilKeySet::from_file(keyset_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Error loading council keys: {}", e);
            return ExitCode::from(exit_codes::INVALID_ARGS);
        }
    };

    // Validate keyset
    if let Err(e) = keyset.validate() {
        eprintln!("Error: invalid council keyset: {}", e);
        return ExitCode::from(exit_codes::INVALID_ARGS);
    }

    // Validate envelope structure
    if let Err(e) = envelope.validate() {
        eprintln!("Error: invalid envelope structure: {}", e);
        return ExitCode::from(exit_codes::VERIFICATION_FAILED);
    }

    // Verify signatures
    let result = match verify_envelope(&envelope, &keyset) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error during verification: {}", e);
            return ExitCode::from(exit_codes::VERIFICATION_FAILED);
        }
    };

    // Verify binary hash (if requested)
    let binary_hash_ok = if let Some(binary) = binary_path {
        verify_binary_hash(&envelope, binary, platform)
    } else {
        None // Not checked
    };

    // Output results
    if output == "json" {
        output_json(&result, binary_hash_ok);
    } else {
        output_text(&result, binary_hash_ok, &keyset);
    }

    // Determine exit code
    let signatures_ok = result.is_valid();
    let binary_ok = binary_hash_ok.unwrap_or(true);

    if signatures_ok && binary_ok {
        ExitCode::from(exit_codes::SUCCESS)
    } else {
        ExitCode::from(exit_codes::VERIFICATION_FAILED)
    }
}

/// Verify binary hash against envelope.
fn verify_binary_hash(envelope: &UpgradeEnvelope, binary_path: &std::path::Path, platform: &str) -> Option<bool> {
    let expected = match envelope.binary_hash(platform) {
        Some(h) => h,
        None => {
            eprintln!("Warning: no binary hash for platform '{}' in envelope", platform);
            return None;
        }
    };

    let actual = match sha3_256_file_hex(binary_path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error computing binary hash: {}", e);
            return Some(false);
        }
    };

    Some(actual == expected.as_str())
}

/// Output results in text format.
fn output_text(
    result: &qbind_gov::VerificationResult,
    binary_hash_ok: Option<bool>,
    _keyset: &CouncilKeySet,
) {
    println!("=== Verification Results ===");
    println!();
    println!("Envelope Digest:    {}", result.digest_hex);
    println!();

    // Signature summary
    println!(
        "Signatures:         {}/{} valid (threshold: {})",
        result.valid_count,
        result.signatures.len(),
        result.threshold
    );

    if result.is_valid() {
        println!("Threshold Check:    ✓ PASSED");
    } else {
        println!("Threshold Check:    ✗ FAILED (need {} more)", result.threshold - result.valid_count);
    }

    // Individual signatures
    if !result.signatures.is_empty() {
        println!();
        println!("Signature Details:");
        for sig in &result.signatures {
            let status = if sig.valid { "✓" } else { "✗" };
            print!("  {} {}", status, sig.member_id);
            if let Some(ref err) = sig.error {
                print!(" - {}", err);
            }
            println!();
        }
    }

    // Binary hash
    if let Some(ok) = binary_hash_ok {
        println!();
        if ok {
            println!("Binary Hash:        ✓ MATCHED");
        } else {
            println!("Binary Hash:        ✗ MISMATCH");
        }
    }

    // Final verdict
    println!();
    let sig_ok = result.is_valid();
    let bin_ok = binary_hash_ok.unwrap_or(true);

    if sig_ok && bin_ok {
        println!("=== VERIFICATION PASSED ===");
    } else {
        println!("=== VERIFICATION FAILED ===");
        if !sig_ok {
            println!("  - Signature threshold not met");
        }
        if !bin_ok {
            println!("  - Binary hash mismatch");
        }
    }
}

/// Output results in JSON format.
fn output_json(result: &qbind_gov::VerificationResult, binary_hash_ok: Option<bool>) {
    #[derive(serde::Serialize)]
    struct JsonOutput {
        valid: bool,
        digest_hex: String,
        valid_count: usize,
        threshold: usize,
        binary_hash_ok: Option<bool>,
        signatures: Vec<JsonSignature>,
    }

    #[derive(serde::Serialize)]
    struct JsonSignature {
        member_id: String,
        valid: bool,
        error: Option<String>,
    }

    let output = JsonOutput {
        valid: result.is_valid() && binary_hash_ok.unwrap_or(true),
        digest_hex: result.digest_hex.clone(),
        valid_count: result.valid_count,
        threshold: result.threshold,
        binary_hash_ok,
        signatures: result
            .signatures
            .iter()
            .map(|s| JsonSignature {
                member_id: s.member_id.clone(),
                valid: s.valid,
                error: s.error.clone(),
            })
            .collect(),
    };

    match serde_json::to_string_pretty(&output) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Error serializing JSON: {}", e),
    }
}

/// Handle the 'digest' subcommand.
fn cmd_digest(envelope_path: &std::path::Path) -> ExitCode {
    // Load envelope
    let envelope = match UpgradeEnvelope::from_file(envelope_path) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error loading envelope: {}", e);
            return ExitCode::from(exit_codes::INVALID_ARGS);
        }
    };

    // Compute digest
    match qbind_gov::envelope_digest_hex(&envelope) {
        Ok(hex) => {
            println!("{}", hex);
            ExitCode::from(exit_codes::SUCCESS)
        }
        Err(e) => {
            eprintln!("Error computing digest: {}", e);
            ExitCode::from(exit_codes::INVALID_ARGS)
        }
    }
}