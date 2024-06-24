use anyhow::Result;
use itertools::Itertools;
use num_format::*;
use rand::{thread_rng, Rng};
use sha2::digest::generic_array::GenericArray;
use sha2::digest::OutputSizeUser;
use sha2::Digest;
use std::iter;
use std::iter::repeat;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{atomic, mpsc};
use std::time::{Duration, Instant};

fn sample_base64_alphabet(rng: &mut impl Rng) -> u8 {
    let alphabet_bytes = base64::alphabet::STANDARD.as_str().as_bytes();
    alphabet_bytes[rng.gen_range(0..alphabet_bytes.len())]
}

fn main() -> Result<()> {
    print_hash("seletskiy/18GHs/1xRTX4090/Hi+HackerNews/0000itHpMYmC1+2");
    let mut parallelism = std::thread::available_parallelism()?;
    parallelism = std::num::NonZero::new(usize::from(parallelism) - 2).unwrap();
    eprintln!("parallelism is {}", parallelism);
    let (merge_sender, merge_receiver) = mpsc::channel();
    let hash_count = AtomicU64::new(0);
    let start_instant = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..parallelism.into() {
            let nonce_prefix = String::from_utf8(
                iter::repeat_with(|| sample_base64_alphabet(&mut thread_rng()))
                    .take(8)
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
                let now_instant = Instant::now();
                let new_count = hash_count.load(Ordering::Relaxed);
                let duration = now_instant.duration_since(last_instant);
                let hash_rate = (new_count - last_count) as f64 / duration.as_secs_f64();
                eprintln!(
                    "last {:?}: {} hashes/s",
                    duration,
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
                .map(|best| output.hash > best.hash)
                .unwrap_or_default()
            {
                continue;
            }
            println!(
                "after {:?}:\n{:x} {} {}",
                Instant::now().duration_since(start_instant),
                output.hash,
                output.score,
                output.input
            );
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
    let nonce_slice = &mut buf[nonce_start_index..];
    assert!(nonce_slice.len() < 64);
    let mut hasher = sha2::Sha256::new();
    hasher.update(&buf[..explore_start_index]);
    let mut best: Option<Output> = None;
    const HASH_COUNT_BATCH: u64 = 1_000_000;
    let mut local_hash_count = 0;
    let mut hash = Default::default();
    while buf[nonce_start_index..].len() <= 64 {
        explore_nonce(&mut buf, explore_start_index, &mut |slice| {
            let mut hasher = hasher.clone();
            hasher.update(&slice[explore_start_index..]);
            hasher.finalize_into(&mut hash);
            // let hash = hasher.finalize_reset();
            local_hash_count += 1;
            if local_hash_count % HASH_COUNT_BATCH == 0 {
                hash_count.fetch_add(HASH_COUNT_BATCH, atomic::Ordering::Relaxed);
            }
            if best
                .as_ref()
                .map(|best| best.hash < hash)
                .unwrap_or_default()
            {
                return;
            }
            let score = consecutive_zeroes(&hash);
            let slice_as_str = unsafe { std::str::from_utf8_unchecked(slice) };
            let output = Output {
                hash,
                input: slice_as_str.to_string(),
                score,
            };
            merge.send(output.clone()).unwrap();
            best = Some(output);
        });
        buf.push(0);
    }
}

fn explore_nonce(space: &mut [u8], index: usize, run: &mut impl FnMut(&[u8])) {
    if true {
        if index == space.len() {
            run(space);
            return;
        }
        for value in base64::alphabet::STANDARD.as_str().bytes() {
            space[index] = value;
            explore_nonce(space, index + 1, run);
        }
    } else {
        for suffix in repeat(base64::alphabet::STANDARD.as_str().bytes())
            .take(space.len() - index)
            .multi_cartesian_product()
        {
            space[index..].copy_from_slice(&suffix);
            run(space)
        }
    }
}
