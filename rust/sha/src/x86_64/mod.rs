//! This module contains Hardware accelerated SHA-1 for x86_64 based systems.
//! You may find the intrinsic descriptions and documentation from
//! <https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html>

// Including achitecture specific intinsics requires some safeguarding to ensure the code works
// and does not compile on wrong machines.
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

// Please note that because of the fact that this module uses intrinsics,
// SHA-1 constants or round functions don't need to be declared as they are
// baked into the hardware.

// Hash length of SHA-1 hash in 32-bit words. Hash length of SHA-1 is
// 160 bits = 20 bytes = 5 words.
// (SHS, p. 3)
const HLEN_W: usize = 5;

// Block size of SHA-1 hash is 512 bits (64 bytes).
// (SHS, p. 3)
const BLOCK_SIZE: usize = 64;

// Let's define some type aliases for readability for beginners and learners.
// These are indeed not needed at all for this code to work. They are purely for
// the purpose of making this code more beginner and learner friendly.
// A word in SHA-1 is 32-bits or 4 bytes.
type Word = u32;

// Message can be a string of bytes of any length that can be represented in
// unsigned 64 bits.
// (SHS, p. 3)
type Message = [u8];

// Hash state contains the h0, h1, h2, h3 and h4 hash words that make up the hash.
type Hash = [Word; HLEN_W];

// Initial hash values for SHA-1 (h0..h4) in their respective order. 
// (SHS, p. 14)
const H0: Hash = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sha1 {
    // Inner state of the hash (h0..h4)
    hash_state: [Word; HLEN_W],
}

impl Default for Sha1 {
    /// Initializes the inner state, setting hash to `const H0` as defined above.
    fn default() -> Self {
        Self {
            hash_state: H0,
        }
    }
}

impl Sha1 {
    // Require the compiler to check if these are supported on the machine
    #[target_feature(enable = "sha,sse,sse2,ssse3,sse4.1")]
    pub unsafe fn digest(message: &Message) -> Self {
        // ----------------------
        // STAGE 1: PREPROCESSING
        // ----------------------
        //
        // As described in SHS, p. 18, section 6.1.1, the SHA-1 preprocessing stage
        // needs to set the initial hash value to H0 and parse the message, which is
        // mainly its length in bits.

        // Initialize the hash setting it to H0
        let mut sha: Self = Self::default();

        // Get the length of the bytestring (in bytes) we will later convert this
        // into bit length and 8 big endian bytes
        let message_len: usize = message.len();

        // This will hold the message tail: the remaining bytes, padding, and final 64-bit length field.
        // Just a declaration and we will fill it later. We need to buffer the tail and padding because the 
        // `message` does not contain the padding or the length in bits itself.
        let mut message_tail_with_padding: Vec<u8>;

        // Count the blocks we need to digest. It will be at least 1.
        let block_count: usize = {

            // These blocks are the ones the message itself occupies wholly
            let whole_blocks_count: usize = message_len as usize / BLOCK_SIZE;

            // Tail bytes are the bytes that are on the last block and we can simply count them with modulo.
            let tail_bytes_count: usize = message_len % BLOCK_SIZE;

            // The padding requires at least 9 bytes at the end:
            //      - 1 byte for the '1' bit padded with tailing zeros
            //      - 8 bytes for the length counted in bits and in big endian order
            //
            // So we need to handle both possible outcomes:
            //
            //      1) The last slice of the message can be padded (length less than 56 bytes)
            //
            //      2) The last slice cannot fit padding (length more than or equal to 56 bytes)
            //
            // This will give us one or two extra blocks to hash.
            let tail_blocks_count: usize = {

                // Padding fits: set `tail_blocks_count` to 1
                if tail_bytes_count < 56 {
                    1

                // Padding does not fit: set `tail_blocks_count` to 2
                } else {
                    2
                }
            };

            // We now initialize the tail buffer, which will be:
            //      - Initialized with zeros
            //      - 1 or 2 blocks wide (`tail_blocks_count`), blocks being 64 bytes each
            let tail_buffer_size: usize = tail_blocks_count * BLOCK_SIZE;
            message_tail_with_padding = vec![0; tail_buffer_size];

            // Copy the trailing bytes from the `message` into the beginning of `message_tail_with_padding`
            message_tail_with_padding[0..tail_bytes_count]
                .copy_from_slice(&message[message_len - tail_bytes_count..message_len]);

            // Put the bit '1' in the end of the message tail immediately adter the last message byte.
            // To clarify: 0x80 is 0b1000_0000 in bits
            message_tail_with_padding[tail_bytes_count] = 0x80;

            // Then we finally put the bit length of the message into the last 8 bytes of `message_tail_with_padding`.
            // This length needs to be in big endian order and represent the amount of **bits** in the message.
            // Therefore we need to multiply the length (currently represented as amount of bytes) with 8.
            message_tail_with_padding[tail_buffer_size - 8..]
                .copy_from_slice(&((message_len * 8) as u64).to_be_bytes());

            // Return the block count and set it into `block_count` variable
            whole_blocks_count + tail_blocks_count
        };

        // -------------------------
        // STAGE 2: HASH COMPUTATION
        // -------------------------
        //
        // This stage is the heart of the SHA-1 algorithm.
        // For each 512-bit message block, we perform the following steps:
        //
        //  1) Message Schedule:
        //     Extend the 512-bit block (16 words) into 80 words using a defined algorithm.
        //     This schedule introduces non-linearity and diffusion to the hash.
        //
        //  2) Initialize Working Variables:
        //     Set up the five 32-bit working variables a, b, c, d, and e
        //     from the current hash state.
        //
        //  3) Process the Message Schedule:
        //     Iterate over all 80 words, updating the working variables using
        //     SHA-1 logic (including rotation, selection, and mixing functions).
        //
        //  4) Update Hash State:
        //     Add the final values of a, b, c, d, and e back into the hash state.
        //
        // -------------------------------------------
        // The Good News: SHA-NI Intrinsics Help A LOT
        // -------------------------------------------
        // Intel’s SHA-NI instruction set accelerates SHA-1 by implementing many
        // of the operations in hardware. That means fewer manual bit operations.
        //
        // But: SHA-NI intrinsics still require the message block to be loaded
        // into 128-bit SIMD registers (4 words at a time), and some setup is
        // still necessary (like byte order conversion).
        //
        // Intrinsics Used in This Stage
        // -----------------------------
        // SHA-1 specific intrinsics:
        //   - _mm_sha1msg1_epu32(a: __m128i, b: __m128i) -> __m128i
        //       Performs the first step of the SHA-1 message schedule expansion.
        //
        //   - _mm_sha1msg2_epu32(a: __m128i, b: __m128i) -> __m128i
        //       Performs the second step of the SHA-1 message schedule expansion.
        //
        //   - _mm_sha1nexte_epu32(a: __m128i, b: __m128i) -> __m128i
        //       Computes the next value of the SHA-1 `e` variable using message input.
        //
        //   - _mm_sha1rnds4_epu32(a: __m128i, b: __m128i, func: i32) -> __m128i
        //       Runs 4 SHA-1 rounds on 128-bit vectors with a selected round function.
        //
        // SIMD/vector handling intrinsics:
        //   - _mm_loadu_si128(mem_addr: *const __m128i) -> __m128i
        //       Loads 128 bits (4 words) from memory without requiring alignment.
        //
        //   - _mm_storeu_si128(mem_addr: *mut __m128i, a: __m128i)
        //       Puts 128 bits into memory without requiring alignment.
        //
        //   - _mm_set_epi8(e15, ..., e0) -> __m128i
        //       Constructs a 128-bit vector from 16 individual bytes.
        //
        //   - _mm_set_epi32(e3: i32, e2: i32, e1: i32, e0: i32) -> __m128i
        //       Constructs a 128-bit vector from 4 individual words.
        //
        //   - _mm_extract_epi32(a: __m128i, b: i32) -> i32
        //       Gives a word out of a vector.
        //
        //   - _mm_shuffle_epi8(a: __m128i, mask: __m128i) -> __m128i
        //       Rearranges bytes in a vector according to a byte-level shuffle mask.
        //
        //   - _mm_shuffle_epi32(a: __m128i, imm8: i32) -> __m128i
        //       Rearranges 32-bit words in a vector based on an immediate mask.
        //
        //   - _mm_add_epi32(a: __m128i, b: __m128i) -> __m128i
        //       Adds packed 32-bit integers lane-wise in two vectors.
        //
        //   - _mm_xor_si128(a: __m128i, b: __m128i) -> __m128i
        //       Xors two vectors.
        //
        // We’ll explain each intrinsic in more detail when it’s used,
        // so don’t worry if these names look intimidating.

        // First, let’s prepare a mask for byte reordering. This is necessary because x86 CPUs use
        // little-endian byte order by default, but SHA-1 expects big-endian input.
        // The `_mm_shuffle_epi8` intrinsic lets us reorder bytes within a 128-bit register using
        // a shuffle mask. Each byte in the mask selects which byte from the input should go
        // into its corresponding output position.
        //
        // For example, if the 15th byte in the mask is 0, the 0th byte from the input
        // will be placed at byte 15 in the output.
        //
        // This sets up a 128-bit vector with the value:
        //      0x000102030405060708090A0B0C0D0E0F
        //
        // When used with `_mm_shuffle_epi8`, this mask *preserves* the byte order
        // (i.e., it leaves the input unchanged).
        let vector_byte_mask: __m128i = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);


        // This shuffle mask is used with `_mm_shuffle_epi32` to preserve the original order
        // of 4 x 32-bit words (h0, h1, h2, h3) when loading them into a SIMD register. It is defined as
        // a constant because shuffle expects it to be a constant.
        //
        // `_mm_shuffle_epi32` takes a 2-bit control code per word (total 8 bits = 4 x 2),
        // each specifying which word (0..3) to select for that position in the output.
        //
        // To maintain the order [0, 1, 2, 3], we construct a control byte like this:
        //    - 0b00 selects word 0
        //    - 0b01 selects word 1
        //    - 0b10 selects word 2
        //    - 0b11 selects word 3
        //
        // Therefore, the mask becomes: 0b00_01_10_11 = 0x1B
        const VECTOR_WORD_MASK: i32 = 0b00_01_10_11;

        // SHA-1’s state is 160 bits (5 words), but a 128-bit SIMD vector (__m128i) holds only 4.
        // So we load the first 4 words (h0–h3) into one register — this will represent a, b, c, and d.
        //
        // `_mm_loadu_si128` loads the data from memory, and `_mm_shuffle_epi32` ensures the word order
        // matches SHA-1's expected layout. (SHS, p. 19, step 2)
        let mut working_variables_abcd: __m128i = _mm_shuffle_epi32(
            _mm_loadu_si128(sha.hash_state.as_ptr().cast()),
            VECTOR_WORD_MASK
        );

        // Next, we set up the working variable `e`, which holds the 5th word of the hash state (h4).
        // Since we're using SIMD, we store `e` in a separate 128-bit vector - placing it in the
        // highest 32-bit lane, with the remaining lanes set to zero.
        //
        // `_mm_set_epi32` takes four signed 32-bit integers (i32), so we cast from u32.
        let mut working_variable_e: __m128i =  _mm_set_epi32(sha.hash_state[4] as i32, 0, 0, 0);

        // Now we begin parsing the 512-bit message blocks including the padded blocks. This will iterate through them all.
        for block in 0..block_count {
            // Let's mark the starting index and ending index of the block for readability
            let block_start: usize = block * BLOCK_SIZE;
            let block_end: usize = block_start + BLOCK_SIZE;

            // Define a block pointer (`*const __m128i`) which will later be used
            // to point to the start of the current 64-byte block, interpreted as 4-lane SIMD vectors.
            let block_pointer: *const __m128i;

            // Define five working variables for word scheduling. In SHA-1 spec the scheduling for the words is done
            // with the following logic:
            //
            //      For round_counter < 16:
            //          scheduled_words[round_counter] = block_words[round_counter]
            //
            //      For round_counter >= 16:
            //          scheduled_words[round_counter] = (
            //                  scheduled_words[round_counter-3]
            //                  ^ scheduled_words[round_counter-8]
            //                  ^ scheduled_words[round_counter-14]
            //                  ^ scheduled_words[round_counter-16]
            //          ).rotate_left(1);
            //
            // In the above example the words are in a array of type [u32; 80] and it holds the whole message schedule after
            // iterating through round_counter 0..80. In our case, we will be calculating them when they are needed from the
            // earlier `scheduled_words_x_to_y` variables. This means that we will reuse these 5 variables for
            // each 20 word chuck in 80 word schedule.
            //
            // You can think of this as a sliding window: leftmost words (`scheduled_words_0_to_3`) slide out,
            // and the next four scheduled words are computed into `scheduled_words_17_to_20` from the previous rightmost
            // 16 words on demand when we need them. (SHS, p. 19, step 1)
            let mut scheduled_words_0_to_3: __m128i;
            let mut scheduled_words_4_to_7: __m128i;
            let mut scheduled_words_8_to_11: __m128i;
            let mut scheduled_words_12_to_16: __m128i;
            // initialize this to keep compiler happy (possibly-uninitialized variable error)
            let mut scheduled_words_17_to_20: __m128i = _mm_set_epi32(0, 0, 0, 0);

            // To perform hashing with SHA-NI instructions, we first need to load each 64-byte (512-bit) block of
            // the message into 128-bit SIMD vectors. These intrinsics (like `_mm_sha1rnds4_epu32`) operate
            // directly on these 128-bit registers. See Intel's SHA-1 intrinsics reference for details:
            // <https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=_mm_sha1>
            //
            // A quick note about performance:
            // Modern CPUs use pipelining and register reuse to execute instructions efficiently. To take
            // advantage of this, compilers need to understand:
            //      - Which data will be used next
            //      - Which registers can be reused
            // In highly optimized code, this often means *manually unrolling loops* so that the compiler
            // can better schedule instructions and reduce branching overhead.
            //
            // However, for the sake of *clarity and learning*, we’re choosing *not to unroll* the
            // SHA-1 round loops manually here. Even though manual unrolling could make this faster, it would
            // also make the code much harder to follow—especially for beginners trying to understand SHA-NI.
            //
            // This trade-off is intentional: readability and comprehension take priority over squeezing out
            // every ounce of performance in this educational implementation. However, if you are intrested
            // in seeing more performance oriented, fully unrolled version (less beginner friendly),
            // check the RustCrypto SHA-1 implementation:
            // <https://github.com/RustCrypto/hashes/blob/5edffca31f40a9f9c0dde329227f0f493e4aca9d/sha1/src/compress/x86.rs>
            //
            // So before calling SHA-NI instructions, we load the data into the expected 128-bit format
            // using `unsafe` intrinsics like `_mm_loadu_si128`, and process it using clear, structured loops.
            //
            // Now we determine whether this block is part of the original message or part of the padding. If it’s a tail
            // block, we load it from the `message_tail_with_padding` buffer; otherwise, we take it directly from `message`.
            if block_start < message_len && block_end <= message_len {
                // This `if block` handles the normal blocks

                // We then use that block index to get a pointer to the beginning of the current block in `message`.
                block_pointer = message[block_start..].as_ptr().cast();

            } else {
                // This handles the padded tail blocks.

                // We prepared `message_tail_with_padding` earlier during preprocessing. Depending on how much padding
                // was required, it might be one or two blocks wide.
                if block == block_count - 1 && message_tail_with_padding.len() > BLOCK_SIZE {
                    // If we’re in the second block of a two-block tail, load from the second half.
                    block_pointer = message_tail_with_padding[BLOCK_SIZE..].as_ptr().cast();
                } else {
                    // Otherwise, load from the beginning of the tail buffer.
                    block_pointer = message_tail_with_padding.as_ptr().cast();
                }
            }

            // As explained earlier, we use the `_mm_shuffle_epi8` intrinsic to preserve the message byte order by
            // using the vector mask created earlier. Read the first 16 bytes (4 words) from the beginnig of the block.
            // We don't need to use the method `offset` on the first word vector because the pointer already points to it.
            scheduled_words_0_to_3 = _mm_shuffle_epi8(
                _mm_loadu_si128(block_pointer),
                vector_byte_mask
            );

            // Read next 16 bytes after the first 16. We achieve that by adding 16 to the
            // `block_start` index e.g. by using the pointer method `offset(1)`.
            scheduled_words_4_to_7 = _mm_shuffle_epi8(
                _mm_loadu_si128(block_pointer.offset(1)),
                vector_byte_mask
            );

            // Then the next 16 bytes following the same logic as earlier.
            scheduled_words_8_to_11 = _mm_shuffle_epi8(
                _mm_loadu_si128(block_pointer.offset(2)),
                vector_byte_mask
            );

            // And the final words from the block into the fourth SIMD vector.
            scheduled_words_12_to_16 = _mm_shuffle_epi8(
                _mm_loadu_si128(block_pointer.offset(3)),
                vector_byte_mask
            );

            // We could use the current hash state (`sha.hash`) directly here, but it would require casting
            // into SIMD types. For clarity and simplicity, we’ll declare two intermediate variables and
            // assign values from the working variables instead.
            //
            // Now, here’s the important part: `intermediate_hash_2` requires special handling.
            // This is because of how `_mm_sha1rnds4_epu32` works internally.
            //
            // Recall from the SHA-1 spec that in each round we compute the temporary value T:
            //     T = (a <<< 5) + f[t](b, c, d) + e + K + W[t]     (SHS, p. 19, step 3)
            //
            // However, in the first round of `_mm_sha1rnds4_epu32`, the pseudocode shows:
            //
            //     A[1] := f(B, C, D) + (A <<< 5) + W[0] + K
            //             |-------------------------------|
            //                Notice: `e` is missing here
            //
            // This is intentional. The first `W[0]` must include the `e` value up front.
            //
            // For the remaining 3 internal rounds (within the same intrinsic call), `e` is used as expected:
            //
            //     FOR i := 1 to 3
            //         A[i+1] := f(B[i], C[i], D[i]) + (A[i] <<< 5) + W[i] + E[i] + K
            //         ...                                                   ----
            //     ENDFOR
            //
            // So, to correctly initialize the state for `_mm_sha1rnds4_epu32`, we:
            //
            //     - Copy `abcd` into `intermediate_hash_1`
            //
            //     - Pre-add `e` to the first 4 words in the message schedule,
            //       and store that in `intermediate_hash_2` so it becomes:
            //
            //             | W0+e | W1 | W2 | W3 |
            //
            //       if you mentally divide the 128-bit vector as 4 * 32-bit words.
            let mut intermediate_hash_1: __m128i = working_variables_abcd;
            let mut intermediate_hash_2: __m128i = _mm_add_epi32(working_variable_e, scheduled_words_0_to_3);

            // Now we begin the rounds. As earlier stated, this would be more efficient if unroleld, but we do it the more
            // easy to understand standpoint so let's just use loops. Message schedule is 80 words long, so we do 80 rounds.
            // SHA-NI instructions for SHA-1 do 4 rounds in a row.
            //
            // This for loop loops through the stages for round function f and round constant K (which are built in to SHA-NI).
            // First iteration will handle the words that need the first constant and function (words 0 to 19) and second
            // will handle the next 20 and so on, until every single one of the 80 words have been processed.
            // We just tell the istructions what f and K to use with numbers 0, 1, 2, and 3. The inner loop will handle the 20
            // word chunks four scheduled words at a time (Intel Intrinsics Guide, _mm_sha1rnds4_epu32). We will first calculate the hash
            // by using the block words but after processing the 16 message words, we need to start extending the words, because
            // there is no 80 words yet. (SHS, p. 19, steps 1 and 3)
            for round_function_and_constant in 0..4 {

                for scheduled_4_word_chunk in 0..5 {
                    // Load the next scheduled words into a variable for easier code flow. Note that this is
                    // copying the data which has an impact on performace if the compiler isn't wise enough to notice
                    // and optimise away the recurring pattern. Therefore this isn't really recommended if you want
                    // to achieve performance. Notice: This let statement ends after the `else` block.
                    let next_scheduled_words: __m128i = {

                        // Do the following if we are dealing with the first 16 words. Remember, that we have already scheduled the
                        // first 4 words, when we loaded the intermediate_hash_2 with the e and first words.
                        if round_function_and_constant == 0 && scheduled_4_word_chunk < 4 {

                            match scheduled_4_word_chunk {
                                0 => scheduled_words_4_to_7,   // Already loaded earlier
                                1 => scheduled_words_8_to_11,  // Already loaded earlier
                                2 => scheduled_words_12_to_16, // Already loaded earlier
                                _ => {
                                    // Does not exist yet -> the words need to be extended. Remember the explanation for the
                                    // `scheduled_words` variables when we declared them. We do just that, but one four word
                                    // chunk at a time. The function for word extention was as follows:
                                    //
                                    //      W[t] = (W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]).rotate_left(1)
                                    //
                                    // This means taking the words from `scheduled_words_0_to_3` and `scheduled_words_4_to_7`
                                    // and give them to intrinsic `_mm_sha1msg1_epu32`, which will perform the following according
                                    // to its pseudocode on Intel Intrinsics Guide:
                                    //
                                    //      W0 := a[127:96]
                                    //      W1 := a[95:64]
                                    //      W2 := a[63:32]
                                    //      W3 := a[31:0]
                                    //      W4 := b[127:96]
                                    //      W5 := b[95:64]
                                    //      dst[127:96] := W2 XOR W0
                                    //      dst[95:64] := W3 XOR W1
                                    //      dst[63:32] := W4 XOR W2
                                    //      dst[31:0] := W5 XOR W3
                                    //
                                    // Which really boils down to this:
                                    //
                                    //      extended_words[t] = W[t-16] ^ W[t-14]
                                    //      extended_words[t+1] = W[t+1-16] ^ W[t+1-14]
                                    //      extended_words[t+2] = W[t+2-16] ^ W[t+2-14]
                                    //      extended_words[t+3] = W[t+3-16] ^ W[t+3-14]
                                    //
                                    // But wait! Didn't I just say that we need to perform it to W[t-3] and W[t-8] as well?
                                    // Yes I did. The `_mm_sha1msg1_epu32` will only take care of the t-16 and t-14 words for the next
                                    // four W[t] values. We will take the output given by the `_mm_sha1msg1_epu32` and xor it with the
                                    // `scheduled_words_8_to_11`, we get to the W[t-8] ^ W[t-14] ^ W[t-16] already. This works because
                                    // the words W[t-8], W[t+1-8], W[t+2-8], and W[t+3-8] all exist on the same vector
                                    // (`scheduled_words_8_to_11`) in order like this:
                                    //
                                    //      | W[t-8] | W[t+1-8] | W[t+2-8] | W[t+3-8] |
                                    //
                                    // To finalize this, we will give the xored vector to the `_mm_sha1msg2_epu32` with the last
                                    // four words of the original block (`scheduled_words_12_to_16).
                                    scheduled_words_17_to_20 = _mm_sha1msg1_epu32(scheduled_words_0_to_3, scheduled_words_4_to_7);
                                    scheduled_words_17_to_20 = _mm_xor_si128(scheduled_words_17_to_20, scheduled_words_8_to_11);
                                    scheduled_words_17_to_20 = _mm_sha1msg2_epu32(scheduled_words_17_to_20, scheduled_words_12_to_16);

                                    // Finally save the value to `next_scheduled_words` (Remember: we are in a let block)
                                    scheduled_words_17_to_20
                                }
                            }

                        // ..and the following if we are dealing with the extended words
                        } else {
                            // We move the current word schedule to the left and calculate the next scheduled words.
                            // This approach isn’t as memory-efficient, since we’re copying vectors around purely for
                            // code clarity. The alternative would be fully unrolled code or using match arms to handle
                            // five different permutations of word scheduling — both more complex and still only slightly
                            // more efficient than this. Realistically, moving 128-bit vectors around isn’t that
                            // performance-impactful in practice.
                            scheduled_words_0_to_3 = scheduled_words_4_to_7; // Leftmost words aren't kept so they fall off 'the edge'
                            scheduled_words_4_to_7 = scheduled_words_8_to_11;
                            scheduled_words_8_to_11 = scheduled_words_12_to_16;
                            scheduled_words_12_to_16 = scheduled_words_17_to_20; // `scheduled_words_17_to_20` is now 'free'

                            // Next we calculate the new scheduled words like in the if block's match arm earlier
                            scheduled_words_17_to_20 = _mm_sha1msg1_epu32(scheduled_words_0_to_3, scheduled_words_4_to_7);
                            scheduled_words_17_to_20 = _mm_xor_si128(scheduled_words_17_to_20, scheduled_words_8_to_11);
                            scheduled_words_17_to_20 = _mm_sha1msg2_epu32(scheduled_words_17_to_20, scheduled_words_12_to_16);

                            // Again, return the `next_scheduled_words`
                            scheduled_words_17_to_20
                        }
                    };

                    // Now on we handle all the rounds similarly.

                    // We went through this function's explanation earlier. But, as a short reminder, it calculates the next
                    // four SHA-1 rounds for a, b, c, and d. Unfortunately this has to be dealt by unrolling, because somehow
                    // known iteration values aren't known at compile time
                    match round_function_and_constant {
                        0 => intermediate_hash_2 = _mm_sha1rnds4_epu32(intermediate_hash_1, intermediate_hash_2, 0),
                        1 => intermediate_hash_2 = _mm_sha1rnds4_epu32(intermediate_hash_1, intermediate_hash_2, 1),
                        2 => intermediate_hash_2 = _mm_sha1rnds4_epu32(intermediate_hash_1, intermediate_hash_2, 2),
                        3 => intermediate_hash_2 = _mm_sha1rnds4_epu32(intermediate_hash_1, intermediate_hash_2, 3),
                        _ => unreachable!(),
                    }

                    // Next we calculate the next e value, because `_mm_sha1rnds4_epu32` only returns the changed
                    // intermediate working variables a, b, c, and d. `_mm_sha1nexte_epu32` takes current working state
                    // (saved on intermediate_hash_1) and the next four scheduled words as arguments. What `_mm_sha1nexte_epu32`
                    // does, is rotate the current working variable a left 30 bits and adds it to `next_scheduled_word`'s first element,
                    // just like we did before entering these loops, but we didn't rotate.
                    let temporary_hash: __m128i = match round_function_and_constant * scheduled_4_word_chunk {
                        12 => _mm_sha1nexte_epu32(intermediate_hash_1, working_variable_e),
                        _  => _mm_sha1nexte_epu32(intermediate_hash_1, next_scheduled_words),
                    };

                    intermediate_hash_1 = intermediate_hash_2;
                    intermediate_hash_2 = temporary_hash;
                }
            }
            
            // Final step of the SHA-1 is the compression round: Add the intermediate working variables back into the hash state.
            // `e` will contain the last words.
            // (SHS, p. 19, step 4)
            working_variables_abcd = _mm_add_epi32(working_variables_abcd, intermediate_hash_1);
            // working_variable_e = _mm_add_epi32(working_variable_e, intermediate_hash_2);
            working_variable_e = intermediate_hash_2;
        }

        // Now we have digested the whole message and it is time to extract the hash:
        // First write the a, b, c, and d variables to the current hash by using a mask just in case:
        _mm_storeu_si128(
            sha.hash_state.as_mut_ptr().cast(),
            _mm_shuffle_epi32(working_variables_abcd, VECTOR_WORD_MASK)
        );

        sha.hash_state[4] = _mm_extract_epi32(working_variable_e, 3) as u32;

        // Return the hash
        sha
    }

    pub fn verify(&self, comp_hash: [u32; 5]) -> bool {
        comp_hash == self.hash_state
    }
}


/// A way to implement methods for all datatypes that can be viewed as bytes
pub trait Sha1sum
where
    Self: AsRef<[u8]>,
{
    fn sha1(&self) -> [u8; 20];
}
