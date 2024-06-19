use sha2::digest::generic_array::GenericArray;
use sha2::digest::OutputSizeUser;
use sha2::Digest;
use std::io::Read;

fn main() {
    print_hash("seletskiy/18GHs/1xRTX4090/Hi+HackerNews/0000itHpMYmC1+2");
    explore("anacrolix", b"");
}

fn print_hash(data: impl AsRef<[u8]>) {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    println!("{:x}", result);
}

struct Output {
    hash: [u8; 32],
    input: String,
    score: usize,
}

fn consecutive_zeroes(bytes: &[u8]) -> usize {
    bytes.iter().take_while(|byte| **byte == 0).count()
}

fn explore(username: &str, nonce_prefix: &[u8]) {
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
    explore_nonce(&mut buf, explore_start_index, &mut |slice| {
        hasher.update(slice);
        let hash = hasher.finalize_reset();
        let score = consecutive_zeroes(&hash);
        if best
            .as_ref()
            .map(|best| best.score >= score)
            .unwrap_or_default()
        {
            return;
        }
        let slice_as_str = unsafe { std::str::from_utf8_unchecked(slice) };
        best = Some(Output {
            hash: hash.try_into().unwrap(),
            input: slice_as_str.to_string(),
            score,
        });
        println!("{:x} {}", hash, slice_as_str);
        // println!("{}", unsafe { std::str::from_utf8_unchecked(slice) })
    });
}

fn explore_nonce(space: &mut [u8], index: usize, run: &mut impl FnMut(&[u8])) {
    if index == space.len() {
        run(space);
        return;
    }
    for value in b'0'..b'9' {
        space[index] = value;
        explore_nonce(space, index + 1, run);
    }
}
