//! This code is commented and documented verbosely because it is intented to be
//! beginner friendly and easy to follow. Something obvious to you
//! might not be obvious to someone else.
//! This library follows the same naming scheme described in <https://doi.org/10.6028%2FNIST.FIPS.180-4>
//! SHS FIPS 180-4 standard, later referenced as SHS.
//! SHA-1 has two main stages: preprocessing and hash computation.
//! I have marked these stages with capital letters in the code.
pub mod x86_64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sse2_support() {
        assert!(is_x86_feature_detected!("sse2"), "SSE2 not supported");
    }

    #[test]
    fn test_ssse3_support() {
        assert!(is_x86_feature_detected!("ssse3"), "SSSE3 not supported");
    }

    #[test]
    fn test_avx_support() {
        assert!(is_x86_feature_detected!("avx"), "AVX not supported");
    }

    #[test]
    fn test_sse4_1_support() {
        assert!(is_x86_feature_detected!("sse4.1"), "SSE4.1 not supported");
    }

    #[test]
    fn test_sse4_2_support() {
        assert!(is_x86_feature_detected!("sse4.2"), "SSE4.2 not supported");
    }

    #[test]
    fn test_sha_support() {
        assert!(is_x86_feature_detected!("sha"), "SHA-NI not supported");
    }

    #[test]
    fn sha1_abc() {
        let message = b"abc";
        let test_vector: [u32; 5] = [0xa9993e36, 0x4706816a, 0xba3e2571, 0x7850c26c, 0x9cd0d89d];
        let hash = unsafe { x86_64::Sha1::digest(message) };
        assert!(hash.verify(test_vector));
    }

    #[test]
    fn sha1_empty() {
        let message = b"";
        let test_vector: [u32; 5] = [0xda39a3ee, 0x5e6b4b0d, 0x3255bfef, 0x95601890, 0xafd80709];
        let hash = unsafe { x86_64::Sha1::digest(message)};
        assert!(hash.verify(test_vector));
    }

    #[test]
    fn sha1_56_bytes() {
        let message = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let test_vector: [u32; 5] = [0x84983e44, 0x1c3bd26e, 0xbaae4aa1, 0xf95129e5, 0xe54670f1];
        let hash = unsafe { x86_64::Sha1::digest(message) };
        assert!(hash.verify(test_vector));
    }

    #[test]
    fn sha1_112_bytes() {
        let message = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let test_vector: [u32; 5] = [0xa49b2446, 0xa02c645b, 0xf419f995, 0xb6709125, 0x3a04a259];
        let hash = unsafe { x86_64::Sha1::digest(message) };
        assert!(hash.verify(test_vector));
    }

    #[test]
    fn sha1_million_a() {
        let message = &vec![b'a'; 1000000];
        let test_vector: [u32; 5] = [0x34aa973c, 0xd4c4daa4, 0xf61eeb2b, 0xdbad2731, 0x6534016f];
        let hash = unsafe { x86_64::Sha1::digest(message) };
        assert!(hash.verify(test_vector));
    }

    #[test]
    fn sha1_len_2_33() {
        let repeats = 16_777_216;
        let pieces = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";
        let alloc = repeats * pieces.len();
        let mut message: Vec<u8> = Vec::with_capacity(alloc);
        for _ in 0..repeats {
            message.extend_from_slice(pieces);
        }
        let test_vector: [u32; 5] = [0x7789f0c9, 0xef7bfc40, 0xd9331114, 0x3dfbe69e, 0x2017f592];
        let hash = unsafe { x86_64::Sha1::digest(&message) };
        assert!(hash.verify(test_vector));
    }
}
