import fs from 'fs';
import { Contract, RpcProvider } from 'starknet';
import {
    dataToVerify,
    dataToVerifyStartIndex,
    finalPayload,
    integrityStartIndex,
    parity,
    payload,
    r,
    s
} from './testcases';

const CONTRACT_ADDRESS = "0x03f31b28b57947f14817755194cfe9e9fd2d83f27b0bb0d00c6033334923d67e";
const RPC_URL = 'https://free-rpc.nethermind.io/sepolia-juno/v0_7';
const ABI_FILE_PATH = './SxgAbi.json';

const provider = new RpcProvider({ nodeUrl: RPC_URL });

async function getContractABI() {
    try {
        const compressedContract = await provider.getClassAt(CONTRACT_ADDRESS);
        fs.writeFileSync(ABI_FILE_PATH, JSON.stringify(compressedContract.abi, null, 2));
        return JSON.parse(fs.readFileSync(ABI_FILE_PATH, 'utf-8'));
    } catch (error) {
        console.error('Error getting or writing contract ABI:', error);
        throw error;
    }
}

async function verifySXG(contract: Contract) {
    try {
        const result = await contract.sxg_verifier(
            finalPayload,
            dataToVerify,
            dataToVerifyStartIndex,
            integrityStartIndex,
            payload,
            parity,
            r,
            s
        );
        console.log('Verification Result:', result);
        return result;
    } catch (error) {
        console.error('Error verifying SXG:', error);
        throw error;
    }
}

async function main() {
    try {
        const contractABI = await getContractABI();
        const sxgContract = new Contract(contractABI, CONTRACT_ADDRESS, provider);
        await verifySXG(sxgContract);
        console.log('SXG verification completed successfully for crema.sh!!!!!!!');
    } catch (error) {
        console.error('An error occurred during execution:', error);
    }
}

main();