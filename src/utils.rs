// This function takes the bytes of the message and pads it such that it contains a multiple of 512 many bits
pub fn pad(data: &[u8]) -> Option<Vec<u8>> {
    // These are the counts of the additional bits we need to append onto the message

    // The current length of the message in bits
    let num_bits = data.len() * 8;

    // zero_bits is the smallest non-zero integer satisfying num_bits + 1 + zero_bits \equiv 448 (mod 512)
    let zero_bits = ((447 - num_bits as i32) % 512 + 512) % 512;

    // Initialize the vector which will contain the message bits along with the padding
    let mut bit_vec = Vec::with_capacity(num_bits + 1 + zero_bits as usize + 64);
    
    // Populate the first section of bit_vector with the bits of the message
    for &byte in data {
        // For each byte we use a moving mask to isolate each bit, in each byte
        for i in 0..8 {
            // We are checking if performing 'AND' with the byte and the mask
            // which results itself in a byte is 0 or not. If it is, then the isolated
            // bit is 0. Otherwise, the isolated bit is 1. 
            let bit = byte & (1 << (7 - i)) != 0;
            bit_vec.push(bit);
        }
    }

    // Append a '1' to the end of the message
    bit_vec.push(true);

    // Append zero_bits of '0'
    for _ in 0..zero_bits {
        bit_vec.push(false);
    }

    // We need to get the length of the original message and encode it in 64 bits
    let length_bits = (num_bits as u64).to_be_bytes();
    for &byte in &length_bits {
        for i in 0..8 {
            let bit = byte & (1 << (7 - i)) != 0;
            bit_vec.push(bit);
        }
    }

    // Confirm the resultant bit_vec is a multiple 512
    if bit_vec.len() % 512 != 0 {
        println!("Error: Number of bits is not multiple of 512");
        return None;
    }

    // Create new vector of bytes to hold the padded message
    let num_bytes = bit_vec.len() / 8;
    let mut padded_message: Vec<u8> = Vec::with_capacity(num_bytes);

    // Interate over each block (chunk) of 8 bits in bit_vec
    for chunk in bit_vec.chunks(8) {
        // This byte will be constructed bit by bit
        let mut byte = 0_u8;

        // enumerate() provides both an index and the value at the index
        for (i, &bit) in chunk.iter().enumerate() {
            // If the bit is 1 (true), then we set that bit 
            if bit {
                // Using the bitwise OR assignment operator
                byte |= 1 << (7 - i);
            }
        }
        padded_message.push(byte);
    }
    
    Some(padded_message)
}

// Parses the padded message into 512-bit blocks represented as a vector of arrays (blocks) each containing 16 u32's
pub fn parse(data: &[u8]) -> Vec<[u32; 16]> {
    // Initialize the vector to hold the blocks
    let num_blocks = (data.len() * 8) / 512;
    let mut message_blocks: Vec<[u32; 16]> = Vec::with_capacity(num_blocks);

    // Break data into chunks of 64 bytes (16 u32s)
    for outer_chunk in data.chunks(64) {
        let mut block: [u32; 16] = [0_u32; 16];

        // Iterate over each group of 4 bytes (inner chunk) with in the 64-byte outer chunk
        for (i, inner_chunk) in outer_chunk.chunks(4).enumerate() {
            // Create u32 out of the 4 bytes in inner_chunk
            block[i] = u32::from_be_bytes([inner_chunk[0], inner_chunk[1], inner_chunk[2], inner_chunk[3]]);
        }
        message_blocks.push(block);
    }

    message_blocks
}

// ============== Operations on Words ================== //
fn rotr(x: u32, n: usize) -> u32 {
    (x >> n) | (x << (32 - n))
}

fn shr(x: u32, n: usize) -> u32 {
    x >> n
}

pub fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

pub fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

pub fn Sigma_256_0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

pub fn Sigma_256_1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

pub fn sigma_256_0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)
}

pub fn sigma_256_1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)
}