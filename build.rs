use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());

    // XKCP source tree. Defaults to the pinned git submodule; override with
    // XKCP_DIR to point at an existing checkout/installation.
    let xkcp_dir = std::env::var("XKCP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest.join("third_party/xkcp"));

    if !xkcp_dir.join("Makefile").exists() {
        panic!(
            "XKCP not found at {:?}.\n\
             Initialise the submodule first:\n    git submodule update --init --depth 1\n\
             or set XKCP_DIR to an existing XKCP checkout.",
            xkcp_dir
        );
    }

    let target = std::env::var("XKCP_TARGET").unwrap_or_else(|_| "x86-64".to_string());
    let lib_dir = xkcp_dir.join("bin").join(&target);
    let lib = lib_dir.join("libXKCP.a");
    let header_dir = lib_dir.join("libXKCP.a.headers");

    // Build libXKCP.a from the submodule if it is not already present.
    if !lib.exists() {
        let status = Command::new("make")
            .arg(format!("{target}/libXKCP.a"))
            .current_dir(&xkcp_dir)
            .status()
            .unwrap_or_else(|e| panic!("failed to spawn `make` for XKCP: {e}"));
        if !status.success() {
            panic!(
                "building XKCP failed (make {target}/libXKCP.a in {:?}). \
                 Ensure make/gcc/xsltproc are installed.",
                xkcp_dir
            );
        }
    }

    if !lib.exists() || !header_dir.exists() {
        panic!(
            "expected {:?} and {:?} after building XKCP",
            lib, header_dir
        );
    }

    // Compile the C shim against the freshly built XKCP headers.
    cc::Build::new()
        .file("c_shim/suw_ffi.c")
        .include(&header_dir)
        .opt_level(3)
        .compile("suw_ffi");

    // Link the static XKCP library.
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=XKCP");

    println!("cargo:rerun-if-changed=c_shim/suw_ffi.c");
    println!("cargo:rerun-if-changed={}", Path::new("build.rs").display());
    println!("cargo:rerun-if-env-changed=XKCP_DIR");
    println!("cargo:rerun-if-env-changed=XKCP_TARGET");
}
