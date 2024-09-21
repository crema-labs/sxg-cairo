use core::starknet::eth_address::EthAddress;
use starknet::secp256_trait::{Signature};
use super::sxg;

#[starknet::interface]
trait IVerifySignature<TContractState> {
    fn get_signature(self: @TContractState, r: u256, s: u256, v: u32,) -> Signature;

    fn verify_eth_signature(
        self: @TContractState, eth_address: EthAddress, msg_hash: u256, r: u256, s: u256, v: u32,
    );
    fn recover_public_key(
        self: @TContractState, eth_address: EthAddress, msg_hash: u256, r: u256, s: u256, v: u32
    );

    fn sxg_verifier(
        self: @TContractState,
        finalPayload: Array<u8>,
        dataToVerify: Array<u8>,
        dataToVerifyStartIndex: usize,
        integrityStartIndex: usize,
        payload: Array<u8>,
        parity: bool,
        r: u256,
        s: u256,
        px: u256,
        py: u256,
    ) -> bool;
}

#[starknet::contract]
mod verifySignature {
    use super::IVerifySignature;
    use core::starknet::eth_address::EthAddress;
    use starknet::secp256k1::Secp256k1Point;
    use starknet::secp256_trait::{Signature, signature_from_vrs, recover_public_key,};
    use starknet::eth_signature::{verify_eth_signature, public_key_point_to_eth_address};
    use super::sxg;

    #[storage]
    struct Storage {
        msg_hash: u256,
        signature: Signature,
        eth_address: EthAddress,
    }

    #[abi(embed_v0)]
    impl VerifySignature of IVerifySignature<ContractState> {
       
        fn get_signature(self: @ContractState, r: u256, s: u256, v: u32,) -> Signature {
            let signature: Signature = signature_from_vrs(v, r, s);
            signature
        }

        fn verify_eth_signature(
            self: @ContractState, eth_address: EthAddress, msg_hash: u256, r: u256, s: u256, v: u32
        ) {
            let signature = self.get_signature(r, s, v);
            verify_eth_signature(:msg_hash, :signature, :eth_address);
        }

        fn sxg_verifier(
            self: @ContractState,
            finalPayload: Array<u8>,
            dataToVerify: Array<u8>,
            dataToVerifyStartIndex: usize,
            integrityStartIndex: usize,
            payload: Array<u8>,
            parity: bool,
            r: u256,
            s: u256,
            px: u256,
            py: u256,
        ) -> bool {
              
              sxg(
                finalPayload,
                dataToVerify,
                dataToVerifyStartIndex,
                integrityStartIndex,
                payload,
                parity,
                r,
                s,
                px,
                py,
            )
        }

        fn recover_public_key(
            self: @ContractState, eth_address: EthAddress, msg_hash: u256, r: u256, s: u256, v: u32
        ) {
            let signature = self.get_signature(r, s, v);
            let public_key_point = recover_public_key::<Secp256k1Point>(msg_hash, signature)
                .unwrap();
            let calculated_eth_address = public_key_point_to_eth_address(:public_key_point);
            assert(calculated_eth_address == eth_address, 'Invalid Address');
        }
    }
}

#[cfg(test)]
mod tests {
    use starknet::secp256_trait::{Signature, signature_from_vrs, recover_public_key,};
    use starknet::EthAddress;
    use starknet::secp256k1::{Secp256k1Point};
    use starknet::eth_signature::{verify_eth_signature, public_key_point_to_eth_address};

    fn get_message_and_signature() -> (u256, Signature, EthAddress) {
        let msg_hash = 0x546ec3fa4f7d3308931816fafd47fa297afe9ac9a09651f77acc13c05a84734f;
        let r = 0xc0f30bcef72974dedaf165cf7848a83b0b9eb6a65167a14643df96698d753efb;
        let s = 0x7f189e3cb5eb992d8cd26e287a13e900326b87f58da2b7fb48fbd3977e3cab1c;
        let v = 27;

        let eth_address = 0x5F04693482cfC121FF244cB3c3733aF712F9df02_u256.into();
        let signature: Signature = signature_from_vrs(v, r, s);

        (msg_hash, signature, eth_address)
    }

    #[test]
    fn test_verify_eth_signature() {
        let (msg_hash, signature, eth_address) = get_message_and_signature();
        verify_eth_signature(msg_hash, signature, eth_address);
    }

    #[test]
    fn test_secp256k1_recover_public_key() {
        let (msg_hash, signature, eth_address) = get_message_and_signature();
        let public_key_point = recover_public_key::<Secp256k1Point>(msg_hash, signature).unwrap();
        let calculated_eth_address = public_key_point_to_eth_address(public_key_point);
        assert_eq!(calculated_eth_address, eth_address);
    }
}
