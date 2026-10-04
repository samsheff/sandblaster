// Generates the iOS static instruction corpus as an assembly file that
// `ios_static_corpus.rs` embeds directly into this crate via
// `core::arch::global_asm!(include_str!(...))`. Because it's embedded (not a
// separately linked archive), it's automatically part of whatever binary
// `sandblaster-mobile-ffi` ends up in -- no extra Xcode link step needed.
//
// This runs on the HOST at `cargo build` time (build scripts always build
// and run for the host, even when the crate itself is cross-compiled via
// `--target aarch64-apple-ios`), so it can use `sandblaster-corpusgen`'s real
// ARM64 execution feedback (via `MacosArm64Backend`) on Apple Silicon to
// drive corpus generation regardless of the final target.
//
// Range/mode are configurable via `SANDBLASTER_IOS_CORPUS_*` env vars (see
// `sandblaster_corpusgen::CorpusConfig::from_env`); sensible defaults mean
// `cargo build -p sandblaster-mobile-ffi` just works without any of them set.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=SANDBLASTER_IOS_CORPUS_MODE");
    println!("cargo:rerun-if-env-changed=SANDBLASTER_IOS_CORPUS_START");
    println!("cargo:rerun-if-env-changed=SANDBLASTER_IOS_CORPUS_END");
    println!("cargo:rerun-if-env-changed=SANDBLASTER_IOS_CORPUS_SEED");
    println!("cargo:rerun-if-env-changed=SANDBLASTER_IOS_CORPUS_COUNT");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("cargo sets OUT_DIR for build scripts"));

    let config = sandblaster_corpusgen::CorpusConfig::from_env();
    let corpus = sandblaster_corpusgen::generate(&config).unwrap_or_else(|error| {
        panic!(
            "sandblaster-mobile-ffi: failed to generate the iOS static instruction corpus: {error}"
        )
    });

    std::fs::write(
        out_dir.join("corpus.s"),
        sandblaster_corpusgen::render_assembly(&corpus),
    )
    .expect("failed to write generated corpus.s");
}
