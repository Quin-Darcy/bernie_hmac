#![allow(non_snake_case)]
mod utils;
mod constants;

use crate::utils::{pad, parse, sigma_256_1, sigma_256_0, Sigma_256_0, Sigma_256_1, ch, maj};
use crate::constants::{INITIAL_HASH, PRIME_CUBES, BLOCKSIZE};


// This function normalizes the key length to assure it contains exactly BLOCKSIZE many bytes
fn normalize(key: &[u8]) -> Vec<u8> {
    let mut normalized_key: Vec<u8> = Vec::with_capacity(64);
    if key.len() > BLOCKSIZE {
        // If the key length is greater than the blocklength, we hash it first
        let hashed_key = hash(key);
        normalized_key.extend(hashed_key);
    } else {
        normalized_key.extend_from_slice(key);
    }

    // Add padding to the key to assure it has a total of blocksize many bytes
    let pad = vec![0_u8; BLOCKSIZE - normalized_key.len()];
    normalized_key.extend(pad);
    normalized_key
}

pub fn hash(data: &[u8]) -> Vec<u8> {
    // Preprocess
    let padded_message = pad(data).unwrap();
    let message_blocks = parse(&padded_message);
    let mut hash_value: [u32; 8] = INITIAL_HASH;

    // Process each message block
    let num_blocks = message_blocks.len();
    for i in 0..num_blocks {
        // Initialize the message schedule
        let mut message_schedule: [u32; 64] = [0_u32; 64];
        for t in 0..64 {
            if t < 16 {
                message_schedule[t] = message_blocks[i][t];
            } else {
                message_schedule[t] = sigma_256_1(message_schedule[t - 2])
                                                .wrapping_add(message_schedule[t - 7])
                                                .wrapping_add(sigma_256_0(message_schedule[t - 15]))
                                                .wrapping_add(message_schedule[t - 16]);
            }
        }

        // Initialize the eight working variables with the last hash value
        let mut a = hash_value[0];
        let mut b = hash_value[1];
        let mut c = hash_value[2];
        let mut d = hash_value[3];
        let mut e = hash_value[4];
        let mut f = hash_value[5];
        let mut g = hash_value[6];
        let mut h = hash_value[7];

        // Compute the two temporary words and update the working variables
        let mut t1: u32;
        let mut t2: u32;
        for t in 0..64 {
            t1 = h.wrapping_add(Sigma_256_1(e))
                    .wrapping_add(ch(e, f, g))
                    .wrapping_add(PRIME_CUBES[t])
                    .wrapping_add(message_schedule[t]);

            t2 = Sigma_256_0(a).wrapping_add(maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        // Update the hash value
        let temp_values = [a, b, c, d, e, f, g, h];
        for (i, temp_value) in temp_values.iter().enumerate() {
            hash_value[i] = temp_value.wrapping_add(hash_value[i]);
        }
    }

    // Construct the final hash by concatenating the bytes of hash_value
    let mut final_hash: Vec<u8> = Vec::with_capacity(32);
    for word in hash_value {
        final_hash.extend(word.to_be_bytes());
    }

    final_hash
}

pub fn hmac(data: &[u8], key: &[u8]) -> Vec<u8> {
    // Normalize the key
    let normalized_key = normalize(key);

    // Initialize values for inner padding and outer padding
    let ipad = vec![0x36; BLOCKSIZE];
    let opad = vec![0x5c; BLOCKSIZE];

    // XOR the normalized key with ipad and opad
    let inner_key: Vec<u8> = normalized_key.iter().zip(ipad.iter()).map(|(&k, &i)| k ^ i).collect();
    let outer_key: Vec<u8> = normalized_key.iter().zip(opad.iter()).map(|(&k, &o)| k ^ o).collect();

    // Append the data to the inner key and hash
    let inner_hash = {
        let mut inner = inner_key.clone();
        inner.extend_from_slice(data);
        hash(&inner)
    };

    // Append the inner hash to the outer key and hash
    let outer_hash = {
        let mut outer = outer_key;
        outer.extend_from_slice(&inner_hash);
        hash(&outer)
    };

    outer_hash
}

pub fn verify_hmac(data: &[u8], received_mac_tag: &[u8], key: &[u8]) -> bool {
    let computed_mac_tag = hmac(data, key);

    // Perform a constant-time comparison to mitigate timing attacks
    use subtle::ConstantTimeEq;
    computed_mac_tag.ct_eq(received_mac_tag).unwrap_u8() == 1
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let message: &str = "This is a test message.";
        let message_bytes: Vec<u8> = message.as_bytes().to_vec();
        let hash_value = hash(&message_bytes);

        let hex_string = to_hex_string(&hash_value);
        let target_hex_string: String= "0668b515bfc41b90b6a90a6ae8600256e1c76a67d17c78a26127ddeb9b324435".to_string();

        assert_eq!(hex_string, target_hex_string);
    }

    #[test]
    fn test_hmac() {
        let key = vec![0x0b; 32];
        let message: &str = "Hi There";
        let message_bytes = message.as_bytes().to_vec();
        let hmac_value = hmac(&message_bytes, &key);

        let hex_string = to_hex_string(&hmac_value);
        let target_hex_string: String = "198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7".to_string();

        assert_eq!(hex_string, target_hex_string);
    }

    #[test]
    fn test_verify_hmac() {
        let key = vec![0xa; 32];
        let message: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddd";
        let message_bytes = message.as_bytes().to_vec();
        let hmac_value = hmac(&message_bytes, &key);
        let mut modified_hmac_value = hmac_value.clone();
        modified_hmac_value[0] = 0xff;

        assert_eq!(verify_hmac(&message_bytes, &hmac_value, &key), true);
        assert_eq!(verify_hmac(&message_bytes, &modified_hmac_value, &key), false);
    }

    fn to_hex_string(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
    }
}