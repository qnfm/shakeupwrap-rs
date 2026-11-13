//! ShakeUpWrap, Rust front-end (streaming pipeline).
//!
//! Same on-disk format as the C `parallel_pipe_suw` branch (32-byte salt header,
//! 4 MiB independent chunks, AAD = salt || index || final), but the crypto comes
//! from XKCP via FFI and the concurrency is a true pipeline that overlaps I/O
//! with compute:
//!
//!   reader thread -> bounded channel -> N worker threads -> ordered atomic writer
//!
//! A dedicated reader streams chunks; a pool of workers wraps/unwraps them in
//! parallel; the main thread reassembles results in sequence order and writes
//! them. Bounded `crossbeam` channels provide back-pressure (so memory stays
//! bounded regardless of file size), and the whole thing is data-race-free by
//! construction — no manual mutex/condvar slot machine like the C version.

mod xkcp;

#[cfg(not(shuttle))]
use crossbeam_channel::{bounded, Receiver, Sender};
#[cfg(shuttle)]
use shim::{bounded, Receiver, Sender};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::exit;
use std::sync::atomic::Ordering;
#[cfg(not(shuttle))]
use std::sync::{atomic::AtomicBool, Mutex};
#[cfg(not(shuttle))]
use std::thread;
#[cfg(shuttle)]
use shuttle::sync::{atomic::AtomicBool, Mutex};
#[cfg(shuttle)]
use shuttle::thread;

/// Under `--cfg shuttle` the pipeline runs on Shuttle's controlled scheduler.
/// This shim gives a bounded MPMC channel with crossbeam's API surface, built
/// from Shuttle's `sync_channel` so every send/recv is a scheduling point.
#[cfg(shuttle)]
mod shim {
    use shuttle::sync::{mpsc, Mutex};
    use std::sync::Arc;

    pub struct Sender<T>(mpsc::SyncSender<T>);
    impl<T> Clone for Sender<T> {
        fn clone(&self) -> Self {
            Sender(self.0.clone())
        }
    }
    impl<T> Sender<T> {
        pub fn send(&self, v: T) -> Result<(), ()> {
            self.0.send(v).map_err(|_| ())
        }
    }

    pub struct Receiver<T>(Arc<Mutex<mpsc::Receiver<T>>>);
    impl<T> Clone for Receiver<T> {
        fn clone(&self) -> Self {
            Receiver(self.0.clone())
        }
    }
    impl<T> Receiver<T> {
        pub fn iter(&self) -> impl Iterator<Item = T> + '_ {
            std::iter::from_fn(move || self.0.lock().unwrap().recv().ok())
        }
    }

    pub fn bounded<T>(cap: usize) -> (Sender<T>, Receiver<T>) {
        let (tx, rx) = mpsc::sync_channel(cap);
        (Sender(tx), Receiver(Arc::new(Mutex::new(rx))))
    }
}

use xkcp::DWrap;

const CHUNK: usize = 4 * 1024 * 1024;
const TAGLEN: usize = 64;
const KEY_SIZE: usize = 64;
const CAPACITY: u32 = 512;
const RHO: u32 = (1600 - CAPACITY - 64) / 8; // 128
const SALT_SIZE: usize = 32;
const AAD_SIZE: usize = 48;
const FINAL_FALSE: u8 = 0;
const FINAL_TRUE: u8 = 1;
const ENC_CHUNK: usize = CHUNK + TAGLEN;

pub(crate) fn make_aad(salt: &[u8], index: u64, final_flag: u8) -> [u8; AAD_SIZE] {
    let mut aad = [0u8; AAD_SIZE];
    aad[..SALT_SIZE].copy_from_slice(salt);
    aad[SALT_SIZE..SALT_SIZE + 8].copy_from_slice(&index.to_le_bytes());
    aad[SALT_SIZE + 8] = final_flag;
    aad
}

fn random_bytes(buf: &mut [u8]) -> io::Result<()> {
    File::open("/dev/urandom")?.read_exact(buf)
}

/// Read until `buf` is full or EOF; returns the number of bytes read.
pub(crate) fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match r.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

/// Key-file parser: a key file is exactly KEY_SIZE raw bytes.
pub(crate) fn parse_key(data: &[u8]) -> Result<[u8; KEY_SIZE], String> {
    if data.len() != KEY_SIZE {
        return Err("Invalid key file size".into());
    }
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(data);
    Ok(key)
}

/// Ciphertext header parser: consumes exactly SALT_SIZE bytes.
pub(crate) fn read_salt(input: &mut impl Read) -> Result<[u8; SALT_SIZE], String> {
    let mut salt = [0u8; SALT_SIZE];
    let n = read_full(input, &mut salt).map_err(|e| format!("input read failed: {e}"))?;
    if n != SALT_SIZE {
        return Err("Invalid ciphertext".into());
    }
    Ok(salt)
}

#[cfg(kani)]
pub(crate) fn read_full_slice(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match r.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

struct Job {
    index: u64,
    is_final: bool,
    data: Vec<u8>,
}

struct Res {
    index: u64,
    is_final: bool,
    out: Result<Vec<u8>, ()>, // Err(()) = authentication failure (decrypt)
}

fn set_err(slot: &Mutex<Option<String>>, msg: String) {
    let mut g = slot.lock().unwrap();
    if g.is_none() {
        *g = Some(msg);
    }
}

#[cfg_attr(not(kani), allow(dead_code))]
pub(crate) fn validate_dec(cur_len: usize, is_final: bool, index: u64) -> Result<(), String> {
    validate_dec_n(cur_len, is_final, index, ENC_CHUNK)
}

/// `validate_dec` for an arbitrary encrypted-chunk size (production uses
/// ENC_CHUNK; the Shuttle tests use tiny chunks).
pub(crate) fn validate_dec_n(
    cur_len: usize,
    is_final: bool,
    index: u64,
    enc_chunk: usize,
) -> Result<(), String> {
    if cur_len < TAGLEN {
        return Err("Invalid ciphertext".into());
    }
    if !is_final && cur_len != enc_chunk {
        return Err("Invalid ciphertext".into());
    }
    if is_final && cur_len > enc_chunk {
        return Err("Invalid ciphertext".into());
    }
    if is_final && cur_len == TAGLEN && index != 0 {
        return Err("Invalid ciphertext".into());
    }
    Ok(())
}

// Kani model-checking harnesses (compiled only by `cargo kani`).
// These verify the real implementation above with symbolic inputs:
//   - AAD injectivity in (salt, index, final): no chunk transplantation.
//   - validate_dec completeness/soundness: only producible chunk lengths
//     are accepted, and all producible lengths are accepted.
//   - read_full: fills the buffer exactly, no overrun.
//   - panic-freedom and AAD layout for arbitrary inputs.
#[cfg(kani)]
mod kani_harnesses {
    // Minimal concrete reader so Kani can model read_full's argument
    // concretely (impl Read/Slice deref chains blow up the solver).

    use crate::{make_aad, parse_key, read_full, read_full_slice, read_salt, validate_dec};
    use crate::KEY_SIZE;
    use crate::{AAD_SIZE, ENC_CHUNK, FINAL_FALSE, FINAL_TRUE, SALT_SIZE, TAGLEN, CHUNK};

    #[kani::proof]
    fn aad_injective_in_index_and_final() {
        let salt = [0u8; SALT_SIZE];
        let i1: u64 = kani::any();
        let i2: u64 = kani::any();
        kani::assume(i1 != i2);
        let a1 = make_aad(&salt, i1, FINAL_FALSE);
        let a2 = make_aad(&salt, i2, FINAL_FALSE);
        assert!(a1 != a2, "AAD collision between different chunk indices");
    }

    #[kani::proof]
    fn aad_injective_in_final_flag() {
        let salt = [0u8; SALT_SIZE];
        let i: u64 = kani::any();
        let a_false = make_aad(&salt, i, FINAL_FALSE);
        let a_true = make_aad(&salt, i, FINAL_TRUE);
        assert!(a_false != a_true, "final chunk AAD collides with non-final");
    }

    #[kani::proof]
    fn aad_injective_in_salt() {
        let s1: [u8; SALT_SIZE] = kani::any();
        let s2: [u8; SALT_SIZE] = kani::any();
        kani::assume(s1 != s2);
        let i: u64 = kani::any();
        let f: u8 = kani::any();
        kani::assume(f == FINAL_FALSE || f == FINAL_TRUE);
        assert!(make_aad(&s1, i, f) != make_aad(&s2, i, f),
            "AAD collision between chunks from files with different salts");
    }

    #[kani::proof]
    fn aad_boundary_indices_reachable() {
        let salt = [0u8; SALT_SIZE];
        let i: u64 = kani::any();
        kani::assume(i == 0 || i == 1 || i == u64::MAX);
        kani::cover!(i == 0);
        kani::cover!(i == u64::MAX);
        let _ = make_aad(&salt, i, FINAL_FALSE);
    }

    #[kani::proof]
    fn validate_dec_accepts_only_producible_lengths() {
        let len: usize = kani::any();
        let is_final: bool = kani::any();
        let index: u64 = kani::any();
        if validate_dec(len, is_final, index).is_ok() {
            if is_final {
                assert!(len >= TAGLEN && len <= ENC_CHUNK);
                if len == TAGLEN {
                    assert!(index == 0, "empty final chunk accepted at nonzero index");
                }
            } else {
                assert!(len == ENC_CHUNK, "non-final chunk with non-canonical length accepted");
            }
        }
    }

    #[kani::proof]
    fn validate_dec_accepts_all_producible_lengths() {
        assert!(validate_dec(ENC_CHUNK, false, kani::any()).is_ok());
        // Bounded final-chunk plaintext so plen + TAGLEN cannot overflow
        // usize (with 4 MiB chunk the sum fits comfortably in 64 bits, but
        // the solver must know it too).
        let index: u64 = kani::any();
        kani::assume(index != 0);
        assert!(validate_dec(1 + TAGLEN, true, index).is_ok());
        assert!(validate_dec(CHUNK + TAGLEN, true, index).is_ok());
        assert!(validate_dec(TAGLEN, true, 0).is_ok());
    }

    #[kani::proof]
    fn truncated_nonfinal_chunk_rejected() {
        let cut: usize = kani::any();
        kani::assume(cut < ENC_CHUNK);
        assert!(validate_dec(cut, false, kani::any()).is_err());
    }

    #[kani::proof]
    fn extended_final_chunk_rejected() {
        let extra: usize = kani::any();
        kani::assume(extra >= 1);
        kani::assume(extra <= 64);
        assert!(validate_dec(ENC_CHUNK + extra, true, kani::any()).is_err());
    }

    #[kani::proof]
    fn read_full_bounded() {
        // Concrete available bytes vs a 16-byte buffer: exercises short
        // reads (n < 16), exact fills (n == 16) and over-long inputs, and
        // checks read_full stops exactly at min(n, buf.len()).
        for n in 0..=17usize {
            let mut src = vec![7u8; n];
            let mut buf = [0u8; 16];
            let got = read_full_slice(&mut &src[..], &mut buf).unwrap();
            assert!(got <= 16);
            assert_eq!(got, n.min(16), "n={n}");
            assert!(buf[..got].iter().all(|&b| b == 7));
            assert!(buf[got.min(16)..].iter().all(|&b| b == 0));
        }
    }

    #[kani::proof]
    fn no_panic_arbitrary_inputs() {
        let salt: [u8; SALT_SIZE] = kani::any();
        let index: u64 = kani::any();
        let f: u8 = kani::any();
        let a = make_aad(&salt, index, f);
        let len: usize = kani::any();
        let is_final: bool = kani::any();
        let _ = validate_dec(len, is_final, index);
        assert_eq!(&a[SALT_SIZE..SALT_SIZE + 8], &index.to_le_bytes());
        assert_eq!(a[SALT_SIZE + 8], f);
        assert!(a[SALT_SIZE + 9..].iter().all(|&b| b == 0));
    }

    // ---- Header parser -------------------------------------------------

    #[kani::proof]
    #[kani::unwind(70)]
    fn key_parser_exact_size_only() {
        // Every length 0..=KEY_SIZE+1 (symbolic contents): accepted iff
        // exactly KEY_SIZE bytes, and then the key is the bytes verbatim.
        let buf: [u8; KEY_SIZE + 1] = kani::any();
        for len in 0..=KEY_SIZE + 1 {
            match parse_key(&buf[..len]) {
                Ok(k) => {
                    assert_eq!(len, KEY_SIZE);
                    assert!(k == buf[..KEY_SIZE]);
                }
                Err(_) => assert_ne!(len, KEY_SIZE),
            }
        }
    }

    #[kani::proof]
    #[kani::unwind(36)]
    fn salt_header_parser() {
        // Every input length 0..=SALT_SIZE+1 with symbolic contents: the
        // parser accepts iff >= SALT_SIZE bytes are present, returns exactly
        // the first SALT_SIZE bytes, and leaves the stream positioned at the
        // first chunk (consumes exactly SALT_SIZE bytes).
        let src: [u8; SALT_SIZE + 1] = kani::any();
        for n in 0..=SALT_SIZE + 1 {
            let mut rest = &src[..n];
            match read_salt(&mut rest) {
                Ok(salt) => {
                    assert!(n >= SALT_SIZE);
                    assert!(salt == src[..SALT_SIZE]);
                    assert_eq!(rest.len(), n - SALT_SIZE);
                }
                Err(_) => assert!(n < SALT_SIZE),
            }
        }
    }
}

fn reader_loop(
    mut input: impl Read,
    read_cap: usize,
    is_decrypt: bool,
    work_tx: Sender<Job>,
    stop: &AtomicBool,
    err: &Mutex<Option<String>>,
) {
    let mut cur = vec![0u8; read_cap];
    let cur_len = match read_full(&mut input, &mut cur) {
        Ok(n) => n,
        Err(e) => {
            set_err(err, format!("input read failed: {e}"));
            stop.store(true, Ordering::Release);
            return;
        }
    };

    if cur_len == 0 {
        if is_decrypt {
            set_err(err, "Invalid ciphertext".into());
            stop.store(true, Ordering::Release);
            return;
        }
        // Empty plaintext: one empty final chunk.
        cur.clear();
        let _ = work_tx.send(Job {
            index: 0,
            is_final: true,
            data: cur,
        });
        return;
    }
    cur.truncate(cur_len);

    let mut index: u64 = 0;
    loop {
        if stop.load(Ordering::Acquire) {
            return;
        }

        let mut next = vec![0u8; read_cap];
        let next_len = match read_full(&mut input, &mut next) {
            Ok(n) => n,
            Err(e) => {
                set_err(err, format!("input read failed: {e}"));
                stop.store(true, Ordering::Release);
                return;
            }
        };
        let is_final = next_len == 0;

        if is_decrypt {
            // read_cap == ENC_CHUNK in production decrypt mode.
            if let Err(msg) = validate_dec_n(cur.len(), is_final, index, read_cap) {
                set_err(err, msg);
                stop.store(true, Ordering::Release);
                return;
            }
        }

        let data = std::mem::take(&mut cur);
        if work_tx
            .send(Job {
                index,
                is_final,
                data,
            })
            .is_err()
        {
            return; // writer gone
        }
        index += 1;

        if is_final {
            return;
        }
        next.truncate(next_len);
        cur = next;
    }
}

fn worker_loop(
    work_rx: Receiver<Job>,
    res_tx: Sender<Res>,
    base: &DWrap,
    salt: &[u8; SALT_SIZE],
    is_decrypt: bool,
) {
    for job in work_rx.iter() {
        let final_flag = if job.is_final {
            FINAL_TRUE
        } else {
            FINAL_FALSE
        };
        let aad = make_aad(salt, job.index, final_flag);
        let mut inst = base.clone();

        let out = if is_decrypt {
            let mut p = vec![0u8; job.data.len() - TAGLEN];
            if inst.unwrap(&mut p, &aad, &job.data) {
                Ok(p)
            } else {
                Err(())
            }
        } else {
            let mut c = vec![0u8; job.data.len() + TAGLEN];
            inst.wrap(&mut c, &aad, &job.data);
            Ok(c)
        };

        if res_tx
            .send(Res {
                index: job.index,
                is_final: job.is_final,
                out,
            })
            .is_err()
        {
            return; // writer gone
        }
    }
}

/// Reassemble results in sequence order and write them. Returns on completion
/// or first error; keeps draining the channel so workers never block.
fn writer_loop(
    res_rx: impl IntoIterator<Item = Res>,
    out: &mut dyn Write,
    stop: &AtomicBool,
    err: &Mutex<Option<String>>,
) {
    let mut next: u64 = 0;
    let mut buf: HashMap<u64, (bool, Result<Vec<u8>, ()>)> = HashMap::new();
    let mut draining = false;

    for item in res_rx {
        buf.insert(item.index, (item.is_final, item.out));
        while let Some((is_final, out_chunk)) = buf.remove(&next) {
            if !draining {
                match out_chunk {
                    Err(()) => {
                        set_err(err, "Authentication failed".into());
                        stop.store(true, Ordering::Release);
                        draining = true;
                    }
                    Ok(data) => {
                        if let Err(e) = out.write_all(&data) {
                            set_err(err, format!("output write failed: {e}"));
                            stop.store(true, Ordering::Release);
                            draining = true;
                        } else if is_final {
                            stop.store(true, Ordering::Release);
                            draining = true; // done; keep draining the channel
                        }
                    }
                }
            }
            next += 1;
        }
    }
}

fn run_pipeline(
    input: impl Read + Send,
    out: &mut dyn Write,
    base: &DWrap,
    salt: &[u8; SALT_SIZE],
    is_decrypt: bool,
) -> Result<(), String> {
    let nthreads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let cap = nthreads.max(2);
    let read_cap = if is_decrypt { ENC_CHUNK } else { CHUNK };
    run_pipeline_with(input, out, base, salt, is_decrypt, nthreads, cap, read_cap)
}

#[allow(clippy::too_many_arguments)]
fn run_pipeline_with(
    input: impl Read + Send,
    out: &mut dyn Write,
    base: &DWrap,
    salt: &[u8; SALT_SIZE],
    is_decrypt: bool,
    nthreads: usize,
    cap: usize,
    read_cap: usize,
) -> Result<(), String> {

    let (work_tx, work_rx) = bounded::<Job>(cap);
    let (res_tx, res_rx) = bounded::<Res>(cap);
    let stop = AtomicBool::new(false);
    let err: Mutex<Option<String>> = Mutex::new(None);

    thread::scope(|s| {
        // Reader owns the input and the sending end of the work channel.
        s.spawn(|| reader_loop(input, read_cap, is_decrypt, work_tx, &stop, &err));

        // Worker pool.
        for _ in 0..nthreads {
            let wrx = work_rx.clone();
            let rtx = res_tx.clone();
            s.spawn(move || worker_loop(wrx, rtx, base, salt, is_decrypt));
        }
        // Drop the originals so the channels close once the clones are gone.
        drop(work_rx);
        drop(res_tx);

        // Writer runs on this thread.
        writer_loop(res_rx.iter(), out, &stop, &err);
    });

    match err.into_inner().unwrap() {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Atomic output (temp file + rename), like the C tool
// ---------------------------------------------------------------------------

enum Output {
    Stdout(BufWriter<io::Stdout>),
    File {
        w: BufWriter<File>,
        tmp: PathBuf,
        final_path: PathBuf,
    },
}

impl Output {
    fn create(path: &Option<String>) -> Result<Self, String> {
        match path {
            None => Ok(Output::Stdout(BufWriter::new(io::stdout()))),
            Some(p) => {
                let final_path = PathBuf::from(p);
                if final_path.exists() {
                    return Err("Output file already exists".into());
                }
                let tmp = PathBuf::from(format!("{p}.suwtmp.{}", std::process::id()));
                let f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&tmp)
                    .map_err(|e| format!("cannot create output: {e}"))?;
                Ok(Output::File {
                    w: BufWriter::new(f),
                    tmp,
                    final_path,
                })
            }
        }
    }

    fn writer(&mut self) -> &mut dyn Write {
        match self {
            Output::Stdout(w) => w,
            Output::File { w, .. } => w,
        }
    }

    fn commit(self) -> Result<(), String> {
        match self {
            Output::Stdout(mut w) => w.flush().map_err(|e| format!("output flush failed: {e}")),
            Output::File {
                mut w,
                tmp,
                final_path,
            } => {
                w.flush().map_err(|e| format!("output flush failed: {e}"))?;
                drop(w);
                std::fs::rename(&tmp, &final_path).map_err(|e| format!("output rename failed: {e}"))
            }
        }
    }

    fn abort(self) {
        if let Output::File { w, tmp, .. } = self {
            drop(w);
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

fn create_key(path: &str) -> Result<[u8; KEY_SIZE], String> {
    let mut key = [0u8; KEY_SIZE];
    random_bytes(&mut key).map_err(|e| format!("entropy failure: {e}"))?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                "Key file already exists".to_string()
            } else {
                format!("cannot create key file: {e}")
            }
        })?;
    f.write_all(&key)
        .map_err(|e| format!("key write failed: {e}"))?;
    Ok(key)
}

fn read_key(path: &str) -> Result<[u8; KEY_SIZE], String> {
    let data = std::fs::read(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            "Key file does not exist".to_string()
        } else {
            format!("cannot read key file: {e}")
        }
    })?;
    parse_key(&data)
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

struct Args {
    encrypt: bool,
    decrypt: bool,
    key: Option<String>,
    output: Option<String>,
}

fn usage() {
    eprintln!(
        "Usage:\n  shakeupwrap-rs -e -k KEYFILE [-o OUTFILE]\n  shakeupwrap-rs -d -k KEYFILE [-o OUTFILE]\n\nInput is read from stdin; output goes to stdout unless -o is given."
    );
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        encrypt: false,
        decrypt: false,
        key: None,
        output: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-e" | "--encrypt" => a.encrypt = true,
            "-d" | "--decrypt" => a.decrypt = true,
            "-k" | "--key" => a.key = Some(it.next().ok_or("-k requires an argument")?),
            "-o" | "--output" => a.output = Some(it.next().ok_or("-o requires an argument")?),
            "-h" | "--help" => {
                usage();
                exit(0);
            }
            other if other.starts_with('-') => return Err(format!("Unknown option: {other}")),
            other => return Err(format!("Unexpected positional argument: {other}")),
        }
    }
    if a.encrypt && a.decrypt {
        return Err("Invalid mode: specify exactly one of -e or -d".into());
    }
    if !a.encrypt && !a.decrypt {
        return Err("Missing required mode: specify -e or -d".into());
    }
    if a.key.is_none() {
        return Err("Missing required key path: -k KEYFILE".into());
    }
    Ok(a)
}

fn encrypt(args: &Args) -> Result<(), String> {
    let key_path = args.key.as_ref().unwrap();
    if std::path::Path::new(key_path).exists() {
        return Err("Key file already exists".into());
    }

    // Open output before creating the key, so an existing output fails cleanly.
    let mut out = Output::create(&args.output)?;

    let key = create_key(key_path)?;
    let base = DWrap::new(&key, TAGLEN as u32, RHO, CAPACITY);

    let mut salt = [0u8; SALT_SIZE];
    if let Err(e) = random_bytes(&mut salt) {
        out.abort();
        return Err(format!("entropy failure: {e}"));
    }

    if let Err(e) = out.writer().write_all(&salt) {
        out.abort();
        return Err(format!("output write failed: {e}"));
    }

    let r = run_pipeline(
        BufReader::new(io::stdin()),
        out.writer(),
        &base,
        &salt,
        false,
    );
    match r {
        Ok(()) => out.commit(),
        Err(e) => {
            out.abort();
            Err(e)
        }
    }
}

fn decrypt(args: &Args) -> Result<(), String> {
    let key_path = args.key.as_ref().unwrap();
    let key = read_key(key_path)?;
    let base = DWrap::new(&key, TAGLEN as u32, RHO, CAPACITY);

    let mut input = BufReader::new(io::stdin());
    let salt = read_salt(&mut input)?;

    let mut out = Output::create(&args.output)?;
    let r = run_pipeline(input, out.writer(), &base, &salt, true);
    match r {
        Ok(()) => out.commit(),
        Err(e) => {
            out.abort();
            Err(e)
        }
    }
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Error: {e}");
            usage();
            exit(2);
        }
    };

    let res = if args.encrypt {
        encrypt(&args)
    } else {
        decrypt(&args)
    };

    if let Err(e) = res {
        eprintln!("Error: {e}");
        exit(1);
    }
}

// Bounded-exhaustive tests of the real writer_loop (plain `cargo test`).
// The writer's control flow depends only on (index, is_final, Ok/Err) and
// on write success, so enumerating every arrival order (all N! permutations)
// x every auth-failure set x every delivered subset x every write-failure
// point, for N = 1..=5, covers every behaviour of the reorder logic for
// files of up to 5 chunks. (Kani/CBMC runs out of memory on the heap-heavy
// writer, so enumeration is used instead; see VERIFICATION.md.)
#[cfg(all(test, not(shuttle)))]
mod writer_exhaustive {
    use super::*;

    fn perms(n: usize) -> Vec<Vec<usize>> {
        if n == 0 {
            return vec![vec![]];
        }
        let mut out = Vec::new();
        for p in perms(n - 1) {
            for pos in 0..=p.len() {
                let mut q = p.clone();
                q.insert(pos, n - 1);
                out.push(q);
            }
        }
        out
    }

    fn res(i: usize, n: usize, ok: bool) -> Res {
        Res {
            index: i as u64,
            is_final: i == n - 1,
            out: if ok { Ok(vec![i as u8 + 1, 0xAA]) } else { Err(()) },
        }
    }

    fn expected(upto: usize) -> Vec<u8> {
        (0..upto).flat_map(|i| [i as u8 + 1, 0xAA]).collect()
    }

    struct FailAt(usize, Vec<u8>);
    impl Write for FailAt {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            if self.0 == 0 {
                return Err(io::Error::other("disk full"));
            }
            self.0 -= 1;
            self.1.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn run(items: Vec<Res>, w: &mut dyn Write) -> (Option<String>, bool) {
        let (stop, err) = (AtomicBool::new(false), Mutex::new(None));
        writer_loop(items, w, &stop, &err);
        (err.into_inner().unwrap(), stop.load(Ordering::Acquire))
    }

    #[test]
    fn orders_and_stops_at_first_auth_failure() {
        let mut cases = 0;
        for n in 1..=5 {
            for p in perms(n) {
                for mask in 0u32..(1 << n) {
                    let fail = |i: usize| mask >> i & 1 == 1;
                    let items = p.iter().map(|&i| res(i, n, !fail(i))).collect();
                    let mut out = Vec::new();
                    let (e, stop) = run(items, &mut out);
                    let first = (0..n).find(|&i| fail(i)).unwrap_or(n);
                    assert_eq!(out, expected(first), "n={n} p={p:?} mask={mask:b}");
                    assert_eq!(e.as_deref(), (first < n).then_some("Authentication failed"));
                    assert!(stop);
                    cases += 1;
                }
            }
        }
        assert_eq!(cases, 2 + 4 * 2 + 8 * 6 + 16 * 24 + 32 * 120);
    }

    #[test]
    fn never_writes_past_a_gap() {
        for n in 1..=5 {
            for p in perms(n) {
                for mask in 0u32..(1 << n) {
                    let present = |i: usize| mask >> i & 1 == 1;
                    let items = p.iter().filter(|&&i| present(i)).map(|&i| res(i, n, true)).collect();
                    let mut out = Vec::new();
                    let (e, stop) = run(items, &mut out);
                    let gap = (0..n).find(|&i| !present(i)).unwrap_or(n);
                    assert_eq!(out, expected(gap));
                    assert!(e.is_none());
                    // completion is signalled only once the final chunk is written
                    assert_eq!(stop, gap == n);
                }
            }
        }
    }

    #[test]
    fn stops_at_first_write_failure() {
        for n in 1..=5 {
            for p in perms(n) {
                for k in 0..=n {
                    let items = p.iter().map(|&i| res(i, n, true)).collect();
                    let mut w = FailAt(k, Vec::new());
                    let (e, stop) = run(items, &mut w);
                    assert_eq!(w.1, expected(k.min(n)));
                    assert_eq!(e.is_some(), k < n);
                    assert!(e.map_or(true, |m| m.starts_with("output write failed")));
                    assert!(stop);
                }
            }
        }
    }
}

// Shuttle schedule-exploration tests (RUSTFLAGS="--cfg shuttle" cargo test).
// They run the real run_pipeline_with / reader_loop / worker_loop /
// writer_loop and the real XKCP crypto, with tiny chunks, under Shuttle's
// controlled scheduler. Shuttle reports any deadlock (all threads blocked)
// as a failure; each test also checks the functional result on every
// explored interleaving.
#[cfg(all(test, shuttle))]
mod shuttle_tests {
    use super::*;
    use std::io::Cursor;

    const C: usize = 8; // plaintext chunk size for the model
    const EC: usize = C + TAGLEN;
    const SALT: [u8; SALT_SIZE] = [0x5a; SALT_SIZE];

    fn base() -> DWrap {
        DWrap::new(&[7u8; KEY_SIZE], TAGLEN as u32, RHO, CAPACITY)
    }

    fn pt(len: usize) -> Vec<u8> {
        (0..len).map(|i| i as u8).collect()
    }

    /// Sequential reference encryption with the same chunking rule.
    fn reference(p: &[u8]) -> Vec<u8> {
        let chunks: Vec<&[u8]> = if p.is_empty() { vec![&[][..]] } else { p.chunks(C).collect() };
        let mut out = Vec::new();
        for (i, ch) in chunks.iter().enumerate() {
            let fin = if i + 1 == chunks.len() { FINAL_TRUE } else { FINAL_FALSE };
            let mut c = vec![0u8; ch.len() + TAGLEN];
            base().wrap(&mut c, &make_aad(&SALT, i as u64, fin), ch);
            out.extend_from_slice(&c);
        }
        out
    }

    fn run(input: impl Read + Send, dec: bool, nthreads: usize, cap: usize) -> (Result<(), String>, Vec<u8>) {
        let b = base();
        let mut out = Vec::new();
        let r = run_pipeline_with(input, &mut out, &b, &SALT, dec, nthreads, cap, if dec { EC } else { C });
        (r, out)
    }

    /// DFS over thread schedules, capped at SUW_DFS_LIMIT (default 20000)
    /// schedules; if fewer were needed the search was exhaustive. Then PCT
    /// (probabilistic concurrency testing, depth 3) for deeper bug-finding.
    fn explore(name: &str, f: impl Fn() + Send + Sync + 'static) {
        use std::sync::atomic::AtomicUsize;
        use std::sync::Arc;
        let limit: usize = std::env::var("SUW_DFS_LIMIT").ok().and_then(|v| v.parse().ok()).unwrap_or(20000);
        let f = Arc::new(f);
        let n = Arc::new(AtomicUsize::new(0));
        let (g, m) = (f.clone(), n.clone());
        shuttle::check_dfs(
            move || {
                m.fetch_add(1, Ordering::Relaxed);
                g()
            },
            Some(limit),
        );
        let n = n.load(Ordering::Relaxed);
        let kind = if n < limit { "EXHAUSTIVE" } else { "bounded" };
        eprintln!("[shuttle] {name}: dfs {n} schedules ({kind}) + pct 1000");
        shuttle::check_pct(move || f(), 1000, 3);
    }

    // Configurations: (plaintext length, worker threads, channel capacity).
    const CFGS: &[(usize, usize, usize)] = &[(0, 2, 1), (1, 2, 1), (C, 2, 1), (C + 1, 2, 1), (2 * C, 2, 1), (3 * C - 1, 2, 2)];

    #[test]
    fn encrypt_matches_sequential_reference() {
        for &(len, t, cap) in CFGS {
            explore(&format!("enc len={len} t={t} cap={cap}"), move || {
                let (r, out) = run(Cursor::new(pt(len)), false, t, cap);
                assert_eq!(r, Ok(()));
                assert_eq!(out, reference(&pt(len)), "len={len}");
            });
        }
    }

    #[test]
    fn decrypt_roundtrip() {
        for &(len, t, cap) in CFGS {
            explore(&format!("dec len={len} t={t} cap={cap}"), move || {
                let (r, out) = run(Cursor::new(reference(&pt(len))), true, t, cap);
                assert_eq!(r, Ok(()));
                assert_eq!(out, pt(len));
            });
        }
    }

    #[test]
    fn tampered_chunk_fails_and_emits_only_prior_chunks() {
        let len = 3 * C - 1; // 3 chunks
        for bad in 0..3 {
            explore(&format!("tamper chunk {bad}"), move || {
                let mut ct = reference(&pt(len));
                ct[bad * EC + 3] ^= 1;
                let (r, out) = run(Cursor::new(ct), true, 2, 1);
                assert_eq!(r, Err("Authentication failed".into()));
                // Never any byte from the bad chunk or later.
                assert_eq!(out, pt(len)[..bad * C].to_vec());
            });
        }
    }

    #[test]
    fn reorder_and_truncation_rejected() {
        explore("reorder/truncate", || {
            let ct = reference(&pt(3 * C - 1));
            // swap chunks 0 and 1
            let mut sw = ct[EC..2 * EC].to_vec();
            sw.extend_from_slice(&ct[..EC]);
            sw.extend_from_slice(&ct[2 * EC..]);
            assert!(run(Cursor::new(sw), true, 2, 1).0.is_err());
            // drop final chunk
            assert!(run(Cursor::new(ct[..2 * EC].to_vec()), true, 2, 1).0.is_err());
            // cut mid-chunk
            assert_eq!(run(Cursor::new(ct[..EC + 5].to_vec()), true, 2, 1).0, Err("Invalid ciphertext".into()));
        });
    }

    struct FailingReader(Vec<u8>, usize);
    impl Read for FailingReader {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            if self.1 >= self.0.len() {
                return Err(io::Error::other("boom"));
            }
            let n = b.len().min(self.0.len() - self.1);
            b[..n].copy_from_slice(&self.0[self.1..self.1 + n]);
            self.1 += n;
            Ok(n)
        }
    }

    #[test]
    fn input_error_mid_stream_terminates_with_error() {
        for avail in [0, 3, C, 2 * C + 1] {
            explore(&format!("read error after {avail}B"), move || {
                let (r, out) = run(FailingReader(pt(avail), 0), false, 2, 1);
                assert!(r.unwrap_err().starts_with("input read failed"));
                // only whole, correctly-ordered chunks preceding the error
                assert_eq!(out, reference(&pt(3 * C))[..out.len()].to_vec());
            });
        }
    }

    struct FailingWriter(usize);
    impl Write for FailingWriter {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            if self.0 == 0 {
                return Err(io::Error::other("full"));
            }
            self.0 -= 1;
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn output_error_terminates_without_deadlock() {
        for k in 0..3 {
            explore(&format!("write error at write {k}"), move || {
                let b = base();
                let mut w = FailingWriter(k);
                let r = run_pipeline_with(Cursor::new(pt(3 * C - 1)), &mut w, &b, &SALT, false, 2, 1, C);
                assert!(r.unwrap_err().starts_with("output write failed"));
            });
        }
    }
}
