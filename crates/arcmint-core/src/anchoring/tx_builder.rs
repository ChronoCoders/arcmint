use super::bitcoin_rpc::Utxo;
use super::{encode_anchor_payload, AnchorPayload};
use anyhow::{anyhow, Result};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::{Builder as ScriptBuilder, PushBytes};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, OutPoint, PrivateKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use std::env;
use std::str::FromStr;

pub struct AnchorTxBuilder;

impl AnchorTxBuilder {
    pub fn build_anchor_tx(
        utxo: &Utxo,
        anchor_payload: &AnchorPayload,
        fee_rate_sat_vbyte: f64,
        change_address: &str,
    ) -> Result<String> {
        let wif =
            env::var("ANCHOR_WALLET_WIF").map_err(|_| anyhow!("ANCHOR_WALLET_WIF not set"))?;
        let priv_key = PrivateKey::from_wif(&wif)?;
        let secp = Secp256k1::new();
        let pub_key = priv_key.public_key(&secp);
        let network = priv_key.network;

        // Verify the private key matches the network if implied, but here we just use it.
        // We assume the UTXO is P2PKH controllable by this private key.

        let payload_bytes = encode_anchor_payload(anchor_payload);
        if payload_bytes.len() > 80 {
            return Err(anyhow!("payload too long"));
        }

        let estimated_vbytes = 10 + 148 + 34 + 9 + payload_bytes.len();
        let fee_sat = (estimated_vbytes as f64 * fee_rate_sat_vbyte).ceil() as u64;
        let fee_sat = fee_sat.max(1000);

        let total_in = utxo.amount_sat;
        let change_sat = total_in
            .checked_sub(fee_sat)
            .ok_or_else(|| anyhow!("insufficient funds for fee"))?;

        let mut outputs = Vec::with_capacity(2);

        let payload_push: &PushBytes = payload_bytes
            .as_slice()
            .try_into()
            .map_err(|e| anyhow!("payload too long for push: {}", e))?;

        // Output 1: OP_RETURN
        let script_op_return = ScriptBuilder::new()
            .push_opcode(OP_RETURN)
            .push_slice(payload_push)
            .into_script();
        outputs.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: script_op_return,
        });

        // Output 2: Change
        if change_sat >= 546 {
            let change_addr = Address::from_str(change_address)?.require_network(network)?;
            outputs.push(TxOut {
                value: Amount::from_sat(change_sat),
                script_pubkey: change_addr.script_pubkey(),
            });
        } else {
            // Dust: add to fee (implicitly by not creating change output)
        }

        let outpoint = OutPoint::new(Txid::from_str(&utxo.txid)?, utxo.vout);
        let txin = TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(), // Will be signed below
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        };

        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![txin],
            output: outputs,
        };

        // Sign the input (assuming P2PKH Legacy)
        // We need the script_pubkey of the input UTXO.
        // Since we don't have it, we derive it from the private key assuming P2PKH.
        let input_addr = Address::p2pkh(&pub_key, network);
        let input_script_pubkey = input_addr.script_pubkey();

        let sighash_type = EcdsaSighashType::All;
        let sighasher = SighashCache::new(&tx);
        let sighash =
            sighasher.legacy_signature_hash(0, &input_script_pubkey, sighash_type.to_u32())?;

        let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
        let signature = secp.sign_ecdsa(&msg, &priv_key.inner);

        let sig = bitcoin::ecdsa::Signature {
            sig: signature,
            hash_ty: sighash_type,
        };

        let script_sig = ScriptBuilder::new()
            .push_slice(sig.serialize())
            .push_key(&pub_key)
            .into_script();

        tx.input[0].script_sig = script_sig;

        // Return hex
        Ok(bitcoin::consensus::encode::serialize_hex(&tx))
    }

    pub fn estimate_anchor_fee(payload_len: usize, fee_rate_sat_vbyte: f64) -> u64 {
        let estimated_vbytes = 10 + 148 + 34 + 9 + payload_len;
        let fee_sat = (estimated_vbytes as f64 * fee_rate_sat_vbyte).ceil() as u64;
        fee_sat.max(1000)
    }
}
