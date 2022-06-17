// adapted from https://github.com/dfinity/icx-proxy/blob/0cd1a22f717b56ac550a3554a25a845878bfb4e8/src/main.rs#L611
// TODO: certificate validation should be it's own library

use candid::types::ic_types::hash_tree::LookupResult;
use flate2::read::GzDecoder;
use ic_agent::agent::http_transport::ReqwestHttpReplicaV2Transport;
use ic_agent::agent::AgentConfig;
use ic_agent::hash_tree::HashTree;
use ic_agent::{lookup_value, Agent, Certificate};
use ic_crypto_utils_threshold_sig_der::public_key_to_der;
use ic_state_machine_tests::CanisterId;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use sha2::{Digest, Sha256};
use std::io::Read;

// The limit of a buffer we should decompress ~10mb.
const MAX_CHUNK_SIZE_TO_DECOMPRESS: usize = 1024;
const MAX_CHUNKS_TO_DECOMPRESS: u64 = 10_240;

pub fn validate_certification(
    certificate_blob: &Vec<u8>,
    tree_blob: &Vec<u8>,
    canister_id: CanisterId,
    uri_path: &str,
    body: &[u8],
    encoding: Option<String>,
    root_key: ThresholdSigPublicKey,
) -> bool {
    let cert: Certificate = serde_cbor::from_slice(certificate_blob).unwrap();
    let tree: HashTree = serde_cbor::from_slice(tree_blob).unwrap();

    let agent = Agent::builder()
        .with_transport(ReqwestHttpReplicaV2Transport::create("https://identity.ic0.app").unwrap())
        .build()
        .unwrap();
    agent
        .set_root_key(public_key_to_der(&root_key.into_bytes()).unwrap())
        .expect("setting root key failed");
    println!("canister id {:?}", canister_id.get().0);
    if let Err(err) = agent.verify(&cert, canister_id.get().0, false) {
        println!("agent verify {:?}", err);
        return false;
    }

    let certified_data_path = vec![
        "canister".into(),
        canister_id.into(),
        "certified_data".into(),
    ];
    let witness = match lookup_value(&cert, certified_data_path) {
        Ok(witness) => witness,
        Err(_) => {
            return false;
        }
    };
    let digest = tree.digest();

    println!("witness: {:?}", (*witness).to_vec());
    println!("digest: {:?}", digest);
    if *witness != digest {
        return false;
    }

    let asset_path = ["http_assets".into(), uri_path.into()];
    let tree_sha = match tree.lookup_path(&asset_path) {
        LookupResult::Found(v) => v,
        _ => match tree.lookup_path(&["http_assets".into(), "/index.html".into()]) {
            LookupResult::Found(v) => v,
            _ => {
                return false;
            }
        },
    };

    let body_sha = decode_body_to_sha256(body, encoding).unwrap();
    body_sha == tree_sha
}

fn decode_body_to_sha256(body: &[u8], encoding: Option<String>) -> Option<[u8; 32]> {
    let mut sha256 = Sha256::new();
    let mut decoded = [0u8; MAX_CHUNK_SIZE_TO_DECOMPRESS];
    match encoding.as_deref() {
        Some("gzip") => {
            let mut decoder = GzDecoder::new(body);
            for _ in 0..MAX_CHUNKS_TO_DECOMPRESS {
                let bytes = decoder.read(&mut decoded).ok()?;
                if bytes == 0 {
                    return Some(sha256.finalize().into());
                }
                sha256.update(&decoded[0..bytes]);
            }
            if decoder.bytes().next().is_some() {
                return None;
            }
        }
        _ => sha256.update(body),
    };
    Some(sha256.finalize().into())
}
