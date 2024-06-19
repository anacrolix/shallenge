use anyhow::Result;
use hex::ToHex;
use num_format::*;
use rand::{thread_rng, Rng};
use sha2::digest::generic_array::GenericArray;
use sha2::digest::{ OutputSizeUser};
use sha2::Digest;
use std::io::Read;
use std::iter;
use std::num::NonZero;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{atomic, mpsc};
use std::time::{Duration, Instant};

fn sample_base64_alphabet(rng: &mut impl rand::Rng) -> u8 {
    let alphabet_bytes = base64::alphabet::STANDARD.as_str().as_bytes();
    alphabet_bytes[rng.gen_range(0..alphabet_bytes.len())]
}

fn main() -> Result<()> {
    print_hash("seletskiy/18GHs/1xRTX4090/Hi+HackerNews/0000itHpMYmC1+2");
    let mut parallelism = std::thread::available_parallelism()?;
    // parallelism = NonZero::new(1).unwrap();
    eprintln!("parallelism is {}", parallelism);
    let (merge_sender, merge_receiver) = mpsc::channel();
    let hash_count = AtomicU64::new(0);
    std::thread::scope(|scope| {
        for _ in 0..parallelism.into() {
            let nonce_prefix = String::from_utf8(
                iter::repeat_with(|| sample_base64_alphabet(&mut thread_rng()))
                    .take(16)
                    .collect::<Vec<u8>>(),
            )
            .unwrap();
            let merge_sender = merge_sender.clone();
            let hash_count = &hash_count;
            scope.spawn(move || {
                eprintln!("starting worker with nonce prefix {}", nonce_prefix);
                let nonce_prefix = nonce_prefix.as_bytes();
                explore("anacrolix", &nonce_prefix, merge_sender, hash_count);
                eprintln!("thread ended");
            });
        }
        scope.spawn(|| {
            let mut last_count = 0;
            let mut last_instant = Instant::now();
            let mut duration = Duration::from_secs(1);
            loop {
                std::thread::sleep(duration);
                duration *= 2;
                let new_count = hash_count.load(Ordering::Relaxed);
                let now_instant = Instant::now();
                let hash_rate = (new_count - last_count) as f64
                    / now_instant.duration_since(last_instant).as_secs_f64();
                eprintln!(
                    "{} hashes/s",
                    (hash_rate.ceil() as u64)
                        .to_formatted_string(&SystemLocale::default().unwrap())
                );
                last_count = new_count;
                last_instant = now_instant;
            }
        });
        let mut best: Option<Output> = None;
        for output in merge_receiver {
            // eprintln!("received {:?}", &output);
            if best
                .as_ref()
                .map(|best| output.score <= best.score)
                .unwrap_or_default()
            {
                continue;
            }
            println!("{:x} {} {}", output.hash, output.score, output.input);
            best = Some(output);
        }
        eprintln!("finishing merging");
    });
    Ok(())
}

fn print_hash(data: impl AsRef<[u8]>) {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    println!("{:x}", result);
}

#[derive(Debug, Clone)]
struct Output {
    hash: GenericArray<u8, <sha2::Sha256 as OutputSizeUser>::OutputSize>,
    input: String,
    score: usize,
}

fn consecutive_zeroes(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0xf])
        .take_while(|nibble| *nibble == 0)
        .count()
}

fn explore(
    username: &str,
    nonce_prefix: &[u8],
    merge: mpsc::Sender<Output>,
    hash_count: &AtomicU64,
) {
    let mut buf = Vec::from(username);
    buf.push(b'/');
    let nonce_start_index = buf.len();
    buf.extend(nonce_prefix);
    let explore_start_index = buf.len();
    buf.extend(std::iter::repeat(b'0').take(64 - nonce_prefix.len()));
    let nonce_slice = &mut buf[nonce_start_index..];
    assert_eq!(nonce_slice.len(), 64);
    let mut hasher = sha2::Sha256::new();
    let mut best: Option<Output> = None;
    const HASH_COUNT_BATCH: u64 = 1000;
    let mut local_hash_count = 0;
    let mut hash = Default::default();
    explore_nonce(&mut buf, explore_start_index, &mut |slice| {
        hasher.update(slice);
        hasher.finalize_into_reset(&mut hash);
        // let hash = hasher.finalize_reset();
        local_hash_count += 1;
        if local_hash_count % HASH_COUNT_BATCH == 0 {
            hash_count.fetch_add(HASH_COUNT_BATCH, atomic::Ordering::Relaxed);
        }
        let score = consecutive_zeroes(&hash);
        if best
            .as_ref()
            .map(|best| best.score >= score)
            .unwrap_or_default()
        {
            return;
        }
        let slice_as_str = unsafe { std::str::from_utf8_unchecked(slice) };
        let output = Output {
            hash: hash.try_into().unwrap(),
            input: slice_as_str.to_string(),
            score,
        };
        merge.send(output.clone()).unwrap();
        best = Some(output);
    });
}

fn explore_nonce(space: &mut [u8], index: usize, run: &mut impl FnMut(&[u8])) {
    if index == space.len() {
        run(space);
        return;
    }
    for value in base64::alphabet::STANDARD.as_str().bytes() {
        space[index] = value;
        explore_nonce(space, index + 1, run);
    }
}
