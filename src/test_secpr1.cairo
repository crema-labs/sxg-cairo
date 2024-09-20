#[cfg(test)]
mod tests {
    use starknet::secp256_trait::{
        recover_public_key, Secp256Trait, Secp256PointTrait, Signature, is_valid_signature,
    };
    use starknet::secp256r1::{Secp256r1Point};
    use starknet::{SyscallResultTrait};

    #[test]
    fn test_secp256r1_recover_public_key() {
        let (msg_hash, signature, expected_public_key_x, expected_public_key_y, _) =
            get_message_and_signature();
        let public_key = recover_public_key::<Secp256r1Point>(msg_hash, signature).unwrap();
        let (x, y) = public_key.get_coordinates().unwrap_syscall();
        assert(expected_public_key_x == x, 'recover failed 1');
        assert(expected_public_key_y == y, 'recover failed 2');
    }


    /// Returns a golden valid message hash and its signature, for testing.
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
}
