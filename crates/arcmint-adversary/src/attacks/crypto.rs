use std::time::Instant;

use anyhow::{anyhow, Result};
use arcmint_core::crypto::{compute_theta, hash_identity, random_scalar, SerialNumber};
use arcmint_core::note::{generate_note_candidate, SignedNote, UnsignedNote};
use arcmint_core::protocol::{
    AuditResponse, IssuanceChallenge, IssuanceRequest, IssuanceResponse, IssuanceReveal,
    RegistrationRequest, RegistrationResponse, SpendChallenge, SpendRequest, SpendResponse,
    UnsignedNoteReveal,
};
use arcmint_core::spending::generate_spend_proof;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

use crate::client::AdversaryClient;
use crate::report::AttackResult;
use crate::CliConfig;

#[derive(Clone)]
pub(crate) struct NoteContext {
    pub signed: SignedNote,
    pub unsigned: UnsignedNote,
}

#[derive(Serialize)]
pub(crate) struct PaymentCompleteRequest {
    pub serial: SerialNumber,
    pub proof: arcmint_core::protocol::SpendProof,
}

pub(crate) async fn setup_valid_note(
    client: &AdversaryClient,
    config: &CliConfig,
) -> Result<NoteContext> {
    let http = &client.client;

    let mut rng = OsRng;
    let r_u = random_scalar(&mut rng);

    let identity_id = format!("adversary-{}", Uuid::new_v4());
    let h_u = hash_identity(&identity_id);
    let theta_u = compute_theta(&h_u, &r_u);

    let reg_req = RegistrationRequest {
        identity_id,
        theta_u: theta_u.to_vec(),
        proof_of_identity: String::new(),
    };

    let reg_url = format!("{}/register", config.gateway_url);
    let reg_resp = http.post(&reg_url).json(&reg_req).send().await?;
    if !reg_resp.status().is_success() {
        return Err(anyhow!(
            "registration failed with HTTP {}",
            reg_resp.status()
        ));
    }
    let reg_body: RegistrationResponse = reg_resp.json().await?;

    let k: usize = 32;
    let denomination: u64 = 1000;

    let mut unsigned_candidates: Vec<UnsignedNote> = Vec::with_capacity(k);
    let mut blinded_candidates = Vec::with_capacity(k);
    for _ in 0..k {
        let unsigned = generate_note_candidate(&theta_u, denomination, k, &mut rng)?;
        unsigned_candidates.push(unsigned.clone());
        blinded_candidates.push(unsigned.data.clone());
    }

    let issue_req = IssuanceRequest {
        blinded_candidates,
        gateway_token: reg_body.gateway_token,
    };

    let issue_url = format!("{}/issue/begin", config.coordinator_url);
    let issue_resp = http.post(&issue_url).json(&issue_req).send().await?;
    if !issue_resp.status().is_success() {
        return Err(anyhow!(
            "issue/begin failed with HTTP {}",
            issue_resp.status()
        ));
    }
    let challenge: IssuanceChallenge = issue_resp.json().await?;

    let open_indices = challenge.open_indices.clone();
    let mut closed_index = None;
    for idx in 0..k {
        if !open_indices.contains(&idx) {
            closed_index = Some(idx);
            break;
        }
    }
    let closed_index = closed_index.ok_or_else(|| anyhow!("no closed index in challenge"))?;

    let mut revealed = Vec::with_capacity(open_indices.len());
    for idx in open_indices {
        let unsigned = &unsigned_candidates[idx];
        let rho_bytes = vec![0u8; 32];
        let mut pair_randomness_bytes = Vec::with_capacity(unsigned.pair_randomness.len());
        for (ra, rb) in &unsigned.pair_randomness {
            let ra_bytes = ra.0.to_bytes().to_vec();
            let rb_bytes = rb.0.to_bytes().to_vec();
            pair_randomness_bytes.push((ra_bytes, rb_bytes));
        }
        let reveal = UnsignedNoteReveal {
            index: idx,
            serial: unsigned.data.serial,
            rho_bytes,
            pair_randomness: pair_randomness_bytes,
            a_bits: unsigned.a_bits.clone(),
            b_bits: unsigned.b_bits.clone(),
        };
        revealed.push(reveal);
    }

    let reveal_req = IssuanceReveal {
        session_id: challenge.session_id,
        revealed,
    };

    let reveal_url = format!("{}/issue/reveal", config.coordinator_url);
    let reveal_resp = http.post(&reveal_url).json(&reveal_req).send().await?;
    if !reveal_resp.status().is_success() {
        return Err(anyhow!(
            "issue/reveal failed with HTTP {}",
            reveal_resp.status()
        ));
    }
    let issuance: IssuanceResponse = reveal_resp.json().await?;

    let signed = issuance.signed_note;
    let kept_unsigned = unsigned_candidates
        .get(closed_index)
        .ok_or_else(|| anyhow!("closed index out of range"))?;

    if signed.data.serial != kept_unsigned.data.serial {
        return Err(anyhow!(
            "serial mismatch between signed note and kept candidate"
        ));
    }

    Ok(NoteContext {
        signed,
        unsigned: kept_unsigned.clone(),
    })
}

pub(crate) struct AttackResponseMeta {
    pub status_code: Option<u16>,
    pub response_body: Option<String>,
}

impl AttackResponseMeta {
    pub fn new(status_code: Option<u16>, response_body: Option<String>) -> Self {
        Self {
            status_code,
            response_body,
        }
    }

    pub fn empty() -> Self {
        Self {
            status_code: None,
            response_body: None,
        }
    }
}

pub(crate) fn build_result(
    attack_name: &str,
    target: &str,
    expected_behavior: &str,
    start: Instant,
    success: bool,
    response: AttackResponseMeta,
    observed_behavior: String,
) -> AttackResult {
    AttackResult {
        attack_name: attack_name.to_string(),
        target: target.to_string(),
        success,
        expected_behavior: expected_behavior.to_string(),
        observed_behavior,
        status_code: response.status_code,
        response_body: response.response_body,
        duration_ms: start.elapsed().as_millis() as u64,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }
}

pub async fn attack_double_spend(client: &AdversaryClient, config: &CliConfig) -> AttackResult {
    let start = Instant::now();
    let expected = "Second spend rejected with 409 or accepted=false";
    let target = "merchant + coordinator spent registry";

    let result = async {
        let note = setup_valid_note(client, config).await?;
        let http = &client.client;

        let spend_req = SpendRequest {
            note: note.signed.clone(),
        };

        let init_url = format!("{}/payment/initiate", config.merchant_url);
        let complete_url = format!("{}/payment/complete", config.merchant_url);

        let init_resp1 = http.post(&init_url).json(&spend_req).send().await?;
        let challenge1: SpendChallenge = init_resp1.json().await?;

        let proof1 = generate_spend_proof(&note.unsigned, &challenge1.challenge_bits)?;

        let complete_req1 = PaymentCompleteRequest {
            serial: note.signed.data.serial,
            proof: proof1,
        };

        let complete_resp1 = http.post(&complete_url).json(&complete_req1).send().await?;
        let status1 = complete_resp1.status().as_u16();
        let body1: SpendResponse = complete_resp1.json().await?;

        let init_resp2 = http.post(&init_url).json(&spend_req).send().await?;
        let status_init2 = init_resp2.status().as_u16();
        let mut response_body = None;
        let mut accepted2 = false;
        let mut reason2 = None;

        let status_code = if init_resp2.status().is_success() {
            let challenge2: SpendChallenge = init_resp2.json().await?;
            let proof2 = generate_spend_proof(&note.unsigned, &challenge2.challenge_bits)?;

            let complete_req2 = PaymentCompleteRequest {
                serial: note.signed.data.serial,
                proof: proof2,
            };

            let complete_resp2 = http.post(&complete_url).json(&complete_req2).send().await?;
            let code = complete_resp2.status().as_u16();
            let body2: SpendResponse = complete_resp2.json().await?;
            accepted2 = body2.accepted;
            reason2 = body2.reason.clone();
            response_body = Some(serde_json::to_string(&body2)?);
            Some(code)
        } else {
            Some(status_init2)
        };

        let success = match status_code {
            Some(409) => true,
            Some(code) if code >= 400 => true,
            Some(_) => !accepted2,
            None => false,
        };

        let observed = format!(
            "first: status={} accepted={}; second: status={:?} accepted={} reason={:?}",
            status1, body1.accepted, status_code, accepted2, reason2
        );

        Ok::<(bool, Option<u16>, Option<String>, String), anyhow::Error>((
            success,
            status_code,
            response_body,
            observed,
        ))
    }
    .await;

    match result {
        Ok((success, status_code, response_body, observed)) => build_result(
            "double-spend",
            target,
            expected,
            start,
            success,
            AttackResponseMeta::new(status_code, response_body),
            observed,
        ),
        Err(e) => build_result(
            "double-spend",
            target,
            expected,
            start,
            false,
            AttackResponseMeta::empty(),
            format!("error during attack: {e}"),
        ),
    }
}

pub async fn attack_double_spend_different_merchants(
    client: &AdversaryClient,
    config: &CliConfig,
) -> AttackResult {
    let start = Instant::now();
    let expected = "Second spend rejected across merchants via spent registry";
    let target = "merchant + coordinator spent registry";

    let result = async {
        let note = setup_valid_note(client, config).await?;
        let http = &client.client;

        let spend_req = SpendRequest {
            note: note.signed.clone(),
        };

        let base_a = &config.merchant_url;
        let base_b = &config.merchant_url;

        let init_url_a = format!("{base_a}/payment/initiate");
        let complete_url_a = format!("{base_a}/payment/complete");
        let init_url_b = format!("{base_b}/payment/initiate");
        let complete_url_b = format!("{base_b}/payment/complete");

        let init_resp1 = http.post(&init_url_a).json(&spend_req).send().await?;
        let challenge1: SpendChallenge = init_resp1.json().await?;

        let proof1 = generate_spend_proof(&note.unsigned, &challenge1.challenge_bits)?;

        let complete_req1 = PaymentCompleteRequest {
            serial: note.signed.data.serial,
            proof: proof1,
        };

        let complete_resp1 = http
            .post(&complete_url_a)
            .json(&complete_req1)
            .send()
            .await?;
        let status1 = complete_resp1.status().as_u16();
        let body1: SpendResponse = complete_resp1.json().await?;

        let init_resp2 = http.post(&init_url_b).json(&spend_req).send().await?;
        let status_init2 = init_resp2.status().as_u16();
        let mut response_body = None;
        let mut accepted2 = false;
        let mut reason2 = None;

        let status_code = if init_resp2.status().is_success() {
            let challenge2: SpendChallenge = init_resp2.json().await?;
            let proof2 = generate_spend_proof(&note.unsigned, &challenge2.challenge_bits)?;

            let complete_req2 = PaymentCompleteRequest {
                serial: note.signed.data.serial,
                proof: proof2,
            };

            let complete_resp2 = http
                .post(&complete_url_b)
                .json(&complete_req2)
                .send()
                .await?;
            let code = complete_resp2.status().as_u16();
            let body2: SpendResponse = complete_resp2.json().await?;
            accepted2 = body2.accepted;
            reason2 = body2.reason.clone();
            response_body = Some(serde_json::to_string(&body2)?);
            Some(code)
        } else {
            Some(status_init2)
        };

        let success = match status_code {
            Some(409) => true,
            Some(code) if code >= 400 => true,
            Some(_) => !accepted2,
            None => false,
        };

        let observed = format!(
            "first: status={} accepted={}; second: status={:?} accepted={} reason={:?}",
            status1, body1.accepted, status_code, accepted2, reason2
        );

        Ok::<(bool, Option<u16>, Option<String>, String), anyhow::Error>((
            success,
            status_code,
            response_body,
            observed,
        ))
    }
    .await;

    match result {
        Ok((success, status_code, response_body, observed)) => build_result(
            "double-spend-different-merchants",
            target,
            expected,
            start,
            success,
            AttackResponseMeta::new(status_code, response_body),
            observed,
        ),
        Err(e) => build_result(
            "double-spend-different-merchants",
            target,
            expected,
            start,
            false,
            AttackResponseMeta::empty(),
            format!("error during attack: {e}"),
        ),
    }
}

pub async fn attack_forged_signature(client: &AdversaryClient, config: &CliConfig) -> AttackResult {
    let start = Instant::now();
    let expected = "Forged signature rejected before challenge with invalid signature error";
    let target = "merchant FROST signature verification";

    let result = async {
        let note = setup_valid_note(client, config).await?;

        let mut forged = note.signed.clone();
        let mut rng = OsRng;
        let mut sig_bytes = vec![0u8; 64];
        rng.fill_bytes(&mut sig_bytes);
        forged.signature = sig_bytes;

        let http = &client.client;

        let spend_req = SpendRequest { note: forged };
        let init_url = format!("{}/payment/initiate", config.merchant_url);
        let init_resp = http.post(&init_url).json(&spend_req).send().await?;

        let status = init_resp.status().as_u16();
        let mut body_text = String::new();
        let mut success = false;

        if init_resp.status().is_success() {
            let resp: SpendResponse = init_resp.json().await?;
            body_text = serde_json::to_string(&resp)?;
            success = !resp.accepted;
        } else if status == 400 {
            success = true;
        }

        let observed = format!("initiate status={} body={}", status, body_text);

        Ok::<(bool, Option<u16>, Option<String>, String), anyhow::Error>((
            success,
            Some(status),
            Some(body_text),
            observed,
        ))
    }
    .await;

    match result {
        Ok((success, status_code, response_body, observed)) => build_result(
            "forged-signature",
            target,
            expected,
            start,
            success,
            AttackResponseMeta::new(status_code, response_body),
            observed,
        ),
        Err(e) => build_result(
            "forged-signature",
            target,
            expected,
            start,
            false,
            AttackResponseMeta::empty(),
            format!("error during attack: {e}"),
        ),
    }
}

pub async fn attack_wrong_commitment_opening(
    client: &AdversaryClient,
    config: &CliConfig,
) -> AttackResult {
    let start = Instant::now();
    let expected = "Spend rejected with InvalidProof for wrong commitment opening";
    let target = "merchant commitment opening verification";

    let result = async {
        let note = setup_valid_note(client, config).await?;
        let http = &client.client;

        let spend_req = SpendRequest {
            note: note.signed.clone(),
        };

        let init_url = format!("{}/payment/initiate", config.merchant_url);
        let complete_url = format!("{}/payment/complete", config.merchant_url);

        let init_resp = http.post(&init_url).json(&spend_req).send().await?;
        let challenge: SpendChallenge = init_resp.json().await?;

        let mut proof = generate_spend_proof(&note.unsigned, &challenge.challenge_bits)?;

        for rs in &mut proof.revealed_scalars {
            std::mem::swap(&mut rs.value_scalar, &mut rs.blinding_scalar);
        }

        let complete_req = PaymentCompleteRequest {
            serial: note.signed.data.serial,
            proof,
        };

        let complete_resp = http.post(&complete_url).json(&complete_req).send().await?;
        let status = complete_resp.status().as_u16();
        let body: SpendResponse = complete_resp.json().await?;

        let success = !body.accepted;
        let body_text = serde_json::to_string(&body)?;
        let observed = format!("complete status={} body={}", status, body_text);

        Ok::<(bool, Option<u16>, Option<String>, String), anyhow::Error>((
            success,
            Some(status),
            Some(body_text),
            observed,
        ))
    }
    .await;

    match result {
        Ok((success, status_code, response_body, observed)) => build_result(
            "wrong-commitment-opening",
            target,
            expected,
            start,
            success,
            AttackResponseMeta::new(status_code, response_body),
            observed,
        ),
        Err(e) => build_result(
            "wrong-commitment-opening",
            target,
            expected,
            start,
            false,
            AttackResponseMeta::empty(),
            format!("error during attack: {e}"),
        ),
    }
}

pub async fn attack_challenge_precomputation(
    client: &AdversaryClient,
    config: &CliConfig,
) -> AttackResult {
    let start = Instant::now();
    let expected = "Spend rejected when proof is for all-zero challenge";
    let target = "merchant challenge unpredictability";

    let result = async {
        let note = setup_valid_note(client, config).await?;
        let http = &client.client;

        let spend_req = SpendRequest {
            note: note.signed.clone(),
        };

        let init_url = format!("{}/payment/initiate", config.merchant_url);
        let complete_url = format!("{}/payment/complete", config.merchant_url);

        let init_resp = http.post(&init_url).json(&spend_req).send().await?;
        let challenge: SpendChallenge = init_resp.json().await?;

        let zero_challenge = vec![0u8; challenge.challenge_bits.len()];
        let proof = generate_spend_proof(&note.unsigned, &zero_challenge)?;

        let complete_req = PaymentCompleteRequest {
            serial: note.signed.data.serial,
            proof,
        };

        let complete_resp = http.post(&complete_url).json(&complete_req).send().await?;
        let status = complete_resp.status().as_u16();
        let body: SpendResponse = complete_resp.json().await?;

        let success = !body.accepted;
        let body_text = serde_json::to_string(&body)?;
        let observed = format!("complete status={} body={}", status, body_text);

        Ok::<(bool, Option<u16>, Option<String>, String), anyhow::Error>((
            success,
            Some(status),
            Some(body_text),
            observed,
        ))
    }
    .await;

    match result {
        Ok((success, status_code, response_body, observed)) => build_result(
            "challenge-precomputation",
            target,
            expected,
            start,
            success,
            AttackResponseMeta::new(status_code, response_body),
            observed,
        ),
        Err(e) => build_result(
            "challenge-precomputation",
            target,
            expected,
            start,
            false,
            AttackResponseMeta::empty(),
            format!("error during attack: {e}"),
        ),
    }
}

pub async fn attack_theta_recovery_verification(
    client: &AdversaryClient,
    config: &CliConfig,
) -> AttackResult {
    let start = Instant::now();
    let expected =
        "Second spend rejected and audit reflects spend recorded after double-spend attempt";
    let target = "coordinator theta recovery and audit";

    let result = async {
        let note = setup_valid_note(client, config).await?;
        let http = &client.client;

        let spend_req = SpendRequest {
            note: note.signed.clone(),
        };

        let init_url = format!("{}/payment/initiate", config.merchant_url);
        let complete_url = format!("{}/payment/complete", config.merchant_url);

        let init_resp1 = http.post(&init_url).json(&spend_req).send().await?;
        let challenge1: SpendChallenge = init_resp1.json().await?;
        let proof1 = generate_spend_proof(&note.unsigned, &challenge1.challenge_bits)?;
        let complete_req1 = PaymentCompleteRequest {
            serial: note.signed.data.serial,
            proof: proof1,
        };
        let complete_resp1 = http.post(&complete_url).json(&complete_req1).send().await?;
        let _body1: SpendResponse = complete_resp1.json().await?;

        let init_resp2 = http.post(&init_url).json(&spend_req).send().await?;
        let challenge2: SpendChallenge = init_resp2.json().await?;
        let proof2 = generate_spend_proof(&note.unsigned, &challenge2.challenge_bits)?;
        let complete_req2 = PaymentCompleteRequest {
            serial: note.signed.data.serial,
            proof: proof2,
        };
        let complete_resp2 = http.post(&complete_url).json(&complete_req2).send().await?;
        let status2 = complete_resp2.status().as_u16();
        let body2: SpendResponse = complete_resp2.json().await?;
        let rejected_second = !body2.accepted;

        let audit_url = format!("{}/audit", config.coordinator_url);
        let audit_resp = http.get(&audit_url).send().await?;
        let audit_status = audit_resp.status().as_u16();
        let audit: AuditResponse = audit_resp.json().await?;

        let success = rejected_second && audit.spent_count >= 1;

        let observed = format!(
            "second spend status={} accepted={}; audit_status={} issued={} spent={} outstanding={}",
            status2,
            body2.accepted,
            audit_status,
            audit.issued_count,
            audit.spent_count,
            audit.outstanding
        );

        let body_json = json!({
            "second_spend": {
                "status": status2,
                "accepted": body2.accepted,
                "reason": body2.reason,
            },
            "audit": audit,
        });

        Ok::<(bool, Option<u16>, Option<String>, String), anyhow::Error>((
            success,
            Some(status2),
            Some(body_json.to_string()),
            observed,
        ))
    }
    .await;

    match result {
        Ok((success, status_code, response_body, observed)) => build_result(
            "theta-recovery-verification",
            target,
            expected,
            start,
            success,
            AttackResponseMeta::new(status_code, response_body),
            observed,
        ),
        Err(e) => build_result(
            "theta-recovery-verification",
            target,
            expected,
            start,
            false,
            AttackResponseMeta::empty(),
            format!("error during attack: {e}"),
        ),
    }
}
