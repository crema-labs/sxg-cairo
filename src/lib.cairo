use core::sha256::compute_sha256_byte_array;
use starknet::secp256_trait::{Secp256Trait, Signature};
use starknet::secp256r1::{Secp256r1Point};
use starknet::{SyscallResultTrait};

fn sha256_as_u256(input: ByteArray) -> u256 {
    let hash_result = compute_sha256_byte_array(@input);
    let mut value: u256 = 0;
    for word in hash_result.span() {
        value *= 0x100000000;
        value = value + (*word).into();
    };
    value
}

fn sha256_as_bytes(input: ByteArray) -> [u32; 8] {
    compute_sha256_byte_array(@input)
}
fn get_message_and_signature() -> (u256, Signature, u256, u256, Secp256r1Point) {
    let msg_hash = 0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855;
    let r = 0xb292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d8770b34a;
    let s = 0x177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2;

    let (public_key_x, public_key_y) = (
        0x04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5,
        0x0087d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d
    );

    let public_key = Secp256Trait::<
        Secp256r1Point
    >::secp256_ec_new_syscall(public_key_x, public_key_y)
        .unwrap_syscall()
        .unwrap();

    (msg_hash, Signature { r, s, y_parity: true }, public_key_x, public_key_y, public_key)
}

fn array_u8_to_byte_array(arr: Array<u8>) -> ByteArray {
    let mut byte_array = "";
    let mut i = 0;
    loop {
        if i == arr.len() {
            break;
        }
        byte_array.append_byte(*arr.at(i));
        i += 1;
    };
    byte_array
}

// Convert ByteArray to Array<u8>
fn byte_array_to_array_u8(byte_array: ByteArray) -> Array<u8> {
    let mut arr = ArrayTrait::new();
    let mut i = 0;
    loop {
        if i == byte_array.len() {
            break;
        }
        arr.append(byte_array.at(i).unwrap());
        i += 1;
    };
    arr
}
fn calculate(input: Span<u8>, record_size: usize) -> (u256, Array<u8>) {
    // Check if input is empty
    if input.is_empty() {
        let empty_array = ArrayTrait::new();
        return (sha256_as_u256(array_u8_to_byte_array(empty_array)), ArrayTrait::new());
    }

    // Determine the actual record size
    let actual_record_size = if record_size < input.len() {
        record_size
    } else {
        input.len()
    };

    // Create records
    let mut records: Array<Span<u8>> = ArrayTrait::new();
    let mut i = 0;

    println!("actual record size {:?}", actual_record_size);
    while i < input.len() {
        let chunk_size = if i + actual_record_size > input.len() {
            input.len() - i // Remaining part of the input
        } else {
            actual_record_size
        };
        
        records.append(input.slice(i, chunk_size)); // Use `chunk_size` as the second argument
        i += actual_record_size;
    };

    // Calculate proofs
    let mut proofs: Array<u256> = ArrayTrait::new();
    let mut j = records.len();
    loop {
        if j == 0 {
            break;
        }
        j -= 1;
        let record = *records.at(j);
        let mut to_hash = ArrayTrait::new();
        to_hash.append_span(record);
        
        if !proofs.is_empty() {
            // Convert u256 to bytes and append
            let proof_bytes = u256_to_bytes(*proofs.at(0));
            to_hash.append_span(proof_bytes.span());
            to_hash.append(1);
        } else {
            to_hash.append(0);
        }

        let hash_result = sha256_as_u256(array_u8_to_byte_array(to_hash));
        let old_proofs = proofs;
        proofs = ArrayTrait::new();
        proofs.append(hash_result);
        proofs.append_span(old_proofs.span());

        println!("{:?}", proofs);
    };

    let mut message: Array<u8> = ArrayTrait::new();
    let record_size_bytes = u64_to_be_bytes(actual_record_size.into());
    message.append_span(record_size_bytes.span());

    let mut k = 0;
    loop {
        if k >= records.len() {
            break;
        }
        if k > 0 {
            let proof_bytes = u256_to_bytes(*proofs.at(k));
            message.append_span(proof_bytes.span());
        }
        message.append_span(*records.at(k));
        k += 1;
    };

    let integrity = *proofs.at(0);

    println!("message {:?}", message);
    (integrity, message)
}

// Helper function to convert u256 to bytes
fn u256_to_bytes(value: u256) -> Array<u8> {
    let mut bytes: Array<u8> = ArrayTrait::new();
    let mut temp = value;
    let mut i = 32;
    loop {
        if i == 0 {
            break;
        }
        i -= 1;
        // bytes.append((temp & 0xFF).try_into().unwrap());
        let old_bytes = bytes;
        bytes = ArrayTrait::new();
        bytes.append((temp & 0xFF).try_into().unwrap());
        bytes.append_span(old_bytes.span());

        temp /= 256;
    };
    bytes
}

fn u64_to_be_bytes(value: u64) -> Array<u8> {
    let mut bytes: Array<u8> = ArrayTrait::new();
    let mut temp = value;
    let mut i = 8;
    loop {
        if i == 0 {
            break;
        }
        i -= 1;
        let old_bytes = bytes;
        bytes = ArrayTrait::new();
        bytes.append((temp & 0xFF).try_into().unwrap());
        bytes.append_span(old_bytes.span());

        temp /= 256;
    };
    bytes
}

#[cfg(test)]
mod tests {
    use starknet::secp256_trait::{
        recover_public_key, Secp256Trait, Secp256PointTrait, Signature, is_valid_signature,
    };
    use starknet::secp256r1::{Secp256r1Point};
    use starknet::{SyscallResultTrait};
    use super::{sha256_as_u256, get_message_and_signature, calculate, byte_array_to_array_u8};

    #[test]
    fn test_sha256() {
            assert_eq!(
                sha256_as_u256("suisuisui"),
                0x8cbe956652cfdba2236bca7ff03e4c9939bca3d66df2411ad5585ce9205b5cf5
            );
    }
    #[test]
    fn test_secp256r1_recover_public_key() {
        let (msg_hash, signature, expected_public_key_x, expected_public_key_y, _) =
            get_message_and_signature();
        let public_key = recover_public_key::<Secp256r1Point>(msg_hash, signature).unwrap();
        let (x, y) = public_key.get_coordinates().unwrap_syscall();
        assert(expected_public_key_x == x, 'recover failed 1');
        assert(expected_public_key_y == y, 'recover failed 2');
    }

    #[test]
    fn it_works() {
        let input = byte_array_to_array_u8("When I grow up, I want to be a watermelon");
        println!("{:?}", input);

        let mut result = calculate(input.span(), 16);

        println!("result {:?}", result);
    }
}