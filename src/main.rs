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

use crossbeam_channel::{bounded, Receiver, Sender};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread;

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

fn make_aad(salt: &[u8], index: u64, final_flag: u8) -> [u8; AAD_SIZE] {
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
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
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

fn validate_dec(cur_len: usize, is_final: bool, index: u64) -> Result<(), String> {
    if cur_len < TAGLEN {
        return Err("Invalid ciphertext".into());
    }
    if !is_final && cur_len != ENC_CHUNK {
        return Err("Invalid ciphertext".into());
    }
    if is_final && cur_len > ENC_CHUNK {
        return Err("Invalid ciphertext".into());
    }
    if is_final && cur_len == TAGLEN && index != 0 {
        return Err("Invalid ciphertext".into());
    }
    Ok(())
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
        let _ = work_tx.send(Job { index: 0, is_final: true, data: cur });
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
            if let Err(msg) = validate_dec(cur.len(), is_final, index) {
                set_err(err, msg);
                stop.store(true, Ordering::Release);
                return;
            }
        }

        let data = std::mem::take(&mut cur);
        if work_tx.send(Job { index, is_final, data }).is_err() {
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
        let final_flag = if job.is_final { FINAL_TRUE } else { FINAL_FALSE };
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
            .send(Res { index: job.index, is_final: job.is_final, out })
            .is_err()
        {
            return; // writer gone
        }
    }
}

/// Reassemble results in sequence order and write them. Returns on completion
/// or first error; keeps draining the channel so workers never block.
fn writer_loop(
    res_rx: Receiver<Res>,
    out: &mut dyn Write,
    stop: &AtomicBool,
    err: &Mutex<Option<String>>,
) {
    let mut next: u64 = 0;
    let mut buf: HashMap<u64, (bool, Result<Vec<u8>, ()>)> = HashMap::new();
    let mut draining = false;

    for item in res_rx.iter() {
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
    let nthreads = thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let cap = nthreads.max(2);
    let read_cap = if is_decrypt { ENC_CHUNK } else { CHUNK };

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
        writer_loop(res_rx, out, &stop, &err);
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
            Output::File { mut w, tmp, final_path } => {
                w.flush().map_err(|e| format!("output flush failed: {e}"))?;
                drop(w);
                std::fs::rename(&tmp, &final_path)
                    .map_err(|e| format!("output rename failed: {e}"))
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
    f.write_all(&key).map_err(|e| format!("key write failed: {e}"))?;
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
    if data.len() != KEY_SIZE {
        return Err("Invalid key file size".into());
    }
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&data);
    Ok(key)
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
    let mut a = Args { encrypt: false, decrypt: false, key: None, output: None };
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

    let r = run_pipeline(BufReader::new(io::stdin()), out.writer(), &base, &salt, false);
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
    let mut salt = [0u8; SALT_SIZE];
    let n = read_full(&mut input, &mut salt).map_err(|e| format!("input read failed: {e}"))?;
    if n != SALT_SIZE {
        return Err("Invalid ciphertext".into());
    }

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

    let res = if args.encrypt { encrypt(&args) } else { decrypt(&args) };

    if let Err(e) = res {
        eprintln!("Error: {e}");
        exit(1);
    }
}
