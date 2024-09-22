use super::sxg;
use starknet::ContractAddress;

#[starknet::contract]
mod MyToken {
    use openzeppelin::token::erc20::{ERC20Component, ERC20HooksEmptyImpl};
    use starknet::ContractAddress;
    use super::IVerifySignature;
    use super::sxg;

    component!(path: ERC20Component, storage: erc20, event: ERC20Event);

    #[abi(embed_v0)]
    impl ERC20MixinImpl = ERC20Component::ERC20MixinImpl<ContractState>;
    impl ERC20InternalImpl = ERC20Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        erc20: ERC20Component::Storage
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        ERC20Event: ERC20Component::Event
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        initial_supply: u256,
        recipient: ContractAddress
    ) {
        let name = "MyToken";
        let symbol = "MTK";

        self.erc20.initializer(name, symbol);
        self.erc20.mint(recipient, initial_supply);
    }

    #[external(v0)]
    impl VerifySignature of IVerifySignature<ContractState> {
        fn sxg_verifier(
            ref self: ContractState,
            recipient: ContractAddress,
            amount: u256,
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
              
            let is_valid = sxg(
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
            );

            if is_valid {
                self.erc20.mint(recipient, amount);
            }
            is_valid
        }
    }
}

#[starknet::interface]
trait IVerifySignature<TContractState> {
    fn sxg_verifier(
        ref self: TContractState,
        recipient: ContractAddress,
        amount: u256,
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