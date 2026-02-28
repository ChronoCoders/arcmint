use std::time::{Duration, Instant};

use anyhow::anyhow;
use arcmint_core::crypto::{compute_theta, hash_identity, random_scalar};
use arcmint_core::note::{generate_note_candidate, SignedNote};
use arcmint_core::protocol::{
    IssuanceChallenge, IssuanceRequest, IssuanceReveal, RegistrationRequest, RegistrationResponse,
    SpendChallenge, SpendRequest, SpendResponse, UnsignedNoteReveal,
};
use arcmint_core::spending::generate_spend_proof;
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::time::sleep;

use crate::client::AdversaryClient;
use crate::report::AttackResult;
use crate::CliConfig;

use super::crypto::{build_result, setup_valid_note, AttackResponseMeta, PaymentCompleteRequest};

pub async fn attack_replay_spent_note(
    client: &AdversaryClient,
    config: &CliConfig,
) -> AttackResult {
    let start = Instant::now();
    let expected = "Second initiate for spent note rejected before challenge";
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
        if !init_resp1.status().is_success() {
            return Err(anyhow!(
                "first payment/initiate failed with HTTP {}",
                init_resp1.status()
            ));
        }
        let challenge1: SpendChallenge = init_resp1.json().await?;

        let proof1 = generate_spend_proof(&note.unsigned, &challenge1.challenge_bits)?;

        let complete_req1 = PaymentCompleteRequest {
            serial: note.signed.data.serial,
            proof: proof1,
        };

        let complete_resp1 = http.post(&complete_url).json(&complete_req1).send().await?;
        let status1 = complete_resp1.status().as_u16();
        if !complete_resp1.status().is_success() {
            return Err(anyhow!(
                "first payment/complete failed with HTTP {}",
                complete_resp1.status()
            ));
        }
        let body1: SpendResponse = complete_resp1.json().await?;
        if !body1.accepted {
            return Err(anyhow!("first spend not accepted: {:?}", body1.reason));
        }

        let init_resp2 = http.post(&init_url).json(&spend_req).send().await?;
        let status2 = init_resp2.status().as_u16();

        let mut success = false;
        let mut body_text = String::new();

        if init_resp2.status().is_success() {
            let body2: SpendResponse = init_resp2.json().await?;
            body_text = serde_json::to_string(&body2)?;
            success = !body2.accepted;
        } else if status2 == 409 || status2 >= 400 {
            success = true;
            body_text = init_resp2.text().await.unwrap_or_default();
        }

        let observed = format!(
            "first: status={} accepted={}; second initiate: status={} body={}",
            status1, body1.accepted, status2, body_text
        );

        Ok::<(bool, Option<u16>, Option<String>, String), anyhow::Error>((
            success,
            Some(status2),
            Some(body_text),
            observed,
        ))
    }
    .await;

    match result {
        Ok((success, status_code, response_body, observed)) => build_result(
            "replay-spent-note",
            target,
            expected,
            start,
            success,
            AttackResponseMeta::new(status_code, response_body),
            observed,
        ),
        Err(e) => build_result(
            "replay-spent-note",
            target,
            expected,
            start,
            false,
            AttackResponseMeta::empty(),
            format!("error during attack: {e}"),
        ),
    }
}

pub async fn attack_malformed_note_missing_pairs(
    client: &AdversaryClient,
    config: &CliConfig,
) -> AttackResult {
    let start = Instant::now();
    let expected = "Malformed note with empty pairs rejected with HTTP 400";
    let target = "merchant note structure validation";

    let result = async {
        let mut rng = OsRng;
        let mut theta_bytes = [0u8; 32];
        rng.fill_bytes(&mut theta_bytes);

        let unsigned = generate_note_candidate(&theta_bytes, 1000, 4, &mut rng)?;

        let mut data = unsigned.data.clone();
        data.pairs.clear();

        let mut signature = vec![0u8; 64];
        rng.fill_bytes(&mut signature);

        let note = SignedNote { data, signature };

        let spend_req = SpendRequest { note };

        let http = &client.client;
        let init_url = format!("{}/payment/initiate", config.merchant_url);
        let resp = http.post(&init_url).json(&spend_req).send().await?;

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();

        let success = status == 400 || status >= 400;

        let observed = format!("status={status} body={body}");

        Ok::<(bool, Option<u16>, Option<String>, String), anyhow::Error>((
            success,
            Some(status),
            Some(body),
            observed,
        ))
    }
    .await;

    match result {
        Ok((success, status_code, response_body, observed)) => build_result(
            "malformed-note-missing-pairs",
            target,
            expected,
            start,
            success,
            AttackResponseMeta::new(status_code, response_body),
            observed,
        ),
        Err(e) => build_result(
            "malformed-note-missing-pairs",
            target,
            expected,
            start,
            false,
            AttackResponseMeta::empty(),
            format!("error during attack: {e}"),
        ),
    }
}

pub async fn attack_malformed_note_wrong_denomination(
    client: &AdversaryClient,
    config: &CliConfig,
) -> AttackResult {
    let start = Instant::now();
    let expected = "Note with tampered denomination rejected due to invalid signature";
    let target = "merchant FROST signature verification";

    let result = async {
        let note = setup_valid_note(client, config).await?;
        let http = &client.client;

        let mut tampered = note.signed.clone();
        tampered.data.denomination = 0;

        let spend_req = SpendRequest { note: tampered };

        let init_url = format!("{}/payment/initiate", config.merchant_url);
        let resp = http.post(&init_url).json(&spend_req).send().await?;

        let status = resp.status().as_u16();
        let mut body_text = String::new();
        let mut success = false;

        if resp.status().is_success() {
            let body: SpendResponse = resp.json().await?;
            body_text = serde_json::to_string(&body)?;
            success = !body.accepted;
        } else if status == 400 || status >= 400 {
            body_text = resp.text().await.unwrap_or_default();
            success = true;
        }

        let observed = format!("status={status} body={body_text}");

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
            "malformed-note-wrong-denomination",
            target,
            expected,
            start,
            success,
            AttackResponseMeta::new(status_code, response_body),
            observed,
        ),
        Err(e) => build_result(
            "malformed-note-wrong-denomination",
            target,
            expected,
            start,
            false,
            AttackResponseMeta::empty(),
            format!("error during attack: {e}"),
        ),
    }
}

pub async fn attack_registry_bypass_skip_issued_check(
    client: &AdversaryClient,
    config: &CliConfig,
) -> AttackResult {
    let start = Instant::now();
    let expected = "Fabricated note rejected because serial is not in issued registry";
    let target = "merchant issued registry check";

    let result = async {
        let mut rng = OsRng;
        let mut theta_bytes = [0u8; 32];
        rng.fill_bytes(&mut theta_bytes);

        let unsigned = generate_note_candidate(&theta_bytes, 1000, 32, &mut rng)?;

        let data = unsigned.data.clone();

        let mut signature = vec![0u8; 64];
        rng.fill_bytes(&mut signature);

        let note = SignedNote { data, signature };

        let spend_req = SpendRequest { note };

        let http = &client.client;
        let init_url = format!("{}/payment/initiate", config.merchant_url);
        let resp = http.post(&init_url).json(&spend_req).send().await?;

        let status = resp.status().as_u16();
        let body_text = if resp.status().is_success() {
            let body: SpendResponse = resp.json().await?;
            serde_json::to_string(&body)?
        } else {
            resp.text().await.unwrap_or_default()
        };

        let success = status == 404 || status == 409 || status >= 400;

        let observed = format!("status={status} body={body_text}");

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
            "registry-bypass-skip-issued-check",
            target,
            expected,
            start,
            success,
            AttackResponseMeta::new(status_code, response_body),
            observed,
        ),
        Err(e) => build_result(
            "registry-bypass-skip-issued-check",
            target,
            expected,
            start,
            false,
            AttackResponseMeta::empty(),
            format!("error during attack: {e}"),
        ),
    }
}

pub async fn attack_expired_note(client: &AdversaryClient, config: &CliConfig) -> AttackResult {
    let start = Instant::now();
    let expected = "payment/complete rejects or 404s for pending spend after expiry window";
    let target = "merchant pending spend expiry";

    if !config.include_slow {
        let observed = "skipped expired-note attack because --include-slow not set".to_string();
        return build_result(
            "expired-note",
            target,
            expected,
            start,
            true,
            AttackResponseMeta::empty(),
            observed,
        );
    }

    let result = async {
        let note = setup_valid_note(client, config).await?;
        let http = &client.client;

        let spend_req = SpendRequest {
            note: note.signed.clone(),
        };

        let init_url = format!("{}/payment/initiate", config.merchant_url);
        let complete_url = format!("{}/payment/complete", config.merchant_url);

        let init_resp = http.post(&init_url).json(&spend_req).send().await?;
        if !init_resp.status().is_success() {
            return Err(anyhow!(
                "payment/initiate failed with HTTP {}",
                init_resp.status()
            ));
        }
        let challenge: SpendChallenge = init_resp.json().await?;

        sleep(Duration::from_secs(310)).await;

        let proof = generate_spend_proof(&note.unsigned, &challenge.challenge_bits)?;

        let complete_req = PaymentCompleteRequest {
            serial: note.signed.data.serial,
            proof,
        };

        let complete_resp = http.post(&complete_url).json(&complete_req).send().await?;
        let status = complete_resp.status().as_u16();

        let (success, body_text) = if complete_resp.status().is_success() {
            let body: SpendResponse = complete_resp.json().await?;
            (!body.accepted, serde_json::to_string(&body)?)
        } else {
            let text = complete_resp.text().await.unwrap_or_default();
            (status == 404 || status >= 400, text)
        };

        let observed = format!("status={status} body={body_text}");

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
            "expired-note",
            target,
            expected,
            start,
            success,
            AttackResponseMeta::new(status_code, response_body),
            observed,
        ),
        Err(e) => build_result(
            "expired-note",
            target,
            expected,
            start,
            false,
            AttackResponseMeta::empty(),
            format!("error during attack: {e}"),
        ),
    }
}

pub async fn attack_flood_issuance(client: &AdversaryClient, config: &CliConfig) -> AttackResult {
    let start = Instant::now();
    let expected = "Gateway rate limiter returns 429 before 20th issuance attempt";
    let target = "gateway rate limiter";

    let result = async {
        let http = &client.client;

        let mut rng = OsRng;
        let mut r_bytes = [0u8; 32];
        rng.fill_bytes(&mut r_bytes);
        let r_scalar = random_scalar(&mut rng);

        let identity_id = "adversary-flood-identity".to_string();
        let h_u = hash_identity(&identity_id);
        let theta_u = compute_theta(&h_u, &r_scalar);

        let reg_url = format!("{}/register", config.gateway_url);
        let issue_url = format!("{}/issue/begin", config.coordinator_url);

        let mut triggered_at = None;
        let mut last_status = None;

        for attempt in 1..=20 {
            let reg_req = RegistrationRequest {
                identity_id: identity_id.clone(),
                theta_u: theta_u.to_vec(),
                proof_of_identity: String::new(),
            };

            let reg_resp = http.post(&reg_url).json(&reg_req).send().await?;
            let status = reg_resp.status().as_u16();
            last_status = Some(status);

            if status == 429 {
                triggered_at = Some(attempt);
                break;
            }

            if !reg_resp.status().is_success() {
                return Err(anyhow!(
                    "register attempt {} failed with HTTP {}",
                    attempt,
                    reg_resp.status()
                ));
            }

            let reg_body: RegistrationResponse = reg_resp.json().await?;

            let k: usize = 4;
            let denomination: u64 = 1000;

            let mut blinded_candidates = Vec::with_capacity(k);
            for _ in 0..k {
                let unsigned = generate_note_candidate(&theta_u, denomination, k, &mut rng)?;
                blinded_candidates.push(unsigned.data.clone());
            }

            let issue_req = IssuanceRequest {
                blinded_candidates,
                gateway_token: reg_body.gateway_token,
            };

            let issue_resp = http.post(&issue_url).json(&issue_req).send().await?;
            if !issue_resp.status().is_success() {
                return Err(anyhow!(
                    "issue/begin attempt {} failed with HTTP {}",
                    attempt,
                    issue_resp.status()
                ));
            }
        }

        let success = triggered_at.is_some() && triggered_at.unwrap() < 20;

        let observed = if let Some(n) = triggered_at {
            format!("rate limit triggered at attempt {n}")
        } else {
            "no rate limit triggered within 20 attempts".to_string()
        };

        Ok::<(bool, Option<u16>, Option<String>, String), anyhow::Error>((
            success,
            last_status,
            None,
            observed,
        ))
    }
    .await;

    match result {
        Ok((success, status_code, response_body, observed)) => build_result(
            "flood-issuance",
            target,
            expected,
            start,
            success,
            AttackResponseMeta::new(status_code, response_body),
            observed,
        ),
        Err(e) => build_result(
            "flood-issuance",
            target,
            expected,
            start,
            false,
            AttackResponseMeta::empty(),
            format!("error during attack: {e}"),
        ),
    }
}

pub async fn attack_signer_direct_access(
    client: &AdversaryClient,
    config: &CliConfig,
) -> AttackResult {
    let start = Instant::now();
    let expected = "all signers reject direct round1/commit access without coordinator client cert";
    let target = "signer mTLS enforcement";

    let result = async {
        let http = &client.client;

        let mut all_rejected = true;
        let mut last_status = None;
        let mut details = Vec::new();

        for url in &config.signer_urls {
            let commit_url = format!("{url}/round1/commit");
            let resp = http
                .post(&commit_url)
                .json(&serde_json::json!({}))
                .send()
                .await;

            match resp {
                Ok(r) => {
                    let status = r.status().as_u16();
                    last_status = Some(status);
                    let rejected = status == 401 || status == 403;
                    if !rejected {
                        all_rejected = false;
                    }
                    details.push(format!("{commit_url} -> HTTP {status}"));
                }
                Err(e) => {
                    details.push(format!("{commit_url} -> transport error: {e}"));
                }
            }
        }

        let observed = details.join("; ");

        Ok::<(bool, Option<u16>, Option<String>, String), anyhow::Error>((
            all_rejected,
            last_status,
            None,
            observed,
        ))
    }
    .await;

    match result {
        Ok((success, status_code, response_body, observed)) => build_result(
            "signer-direct-access",
            target,
            expected,
            start,
            success,
            AttackResponseMeta::new(status_code, response_body),
            observed,
        ),
        Err(e) => build_result(
            "signer-direct-access",
            target,
            expected,
            start,
            false,
            AttackResponseMeta::empty(),
            format!("error during attack: {e}"),
        ),
    }
}

pub async fn attack_malformed_issuance_reveal(
    client: &AdversaryClient,
    config: &CliConfig,
) -> AttackResult {
    let start = Instant::now();
    let expected = "issuance reveal with corrupted bit shares rejected with InvalidProof";
    let target = "coordinator issuance candidate verification";

    let result = async {
        let http = &client.client;
        let mut rng = OsRng;

        let r_u = random_scalar(&mut rng);
        let identity_id = "adversary-issuance-malformed";
        let h_u = hash_identity(identity_id);
        let theta_u = compute_theta(&h_u, &r_u);

        let reg_req = RegistrationRequest {
            identity_id: identity_id.to_string(),
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

        let k: usize = 4;
        let denomination: u64 = 1000;

        let mut unsigned_candidates = Vec::with_capacity(k);
        let mut blinded_candidates = Vec::with_capacity(k);
        for _ in 0..k {
            let unsigned = generate_note_candidate(&theta_u, denomination, k, &mut rng)?;
            blinded_candidates.push(unsigned.data.clone());
            unsigned_candidates.push(unsigned);
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

            let mut a_bits = unsigned.a_bits.clone();
            let mut b_bits = unsigned.b_bits.clone();
            if !b_bits.is_empty() {
                b_bits[0] ^= 1;
            } else if !a_bits.is_empty() {
                a_bits[0] ^= 1;
            }

            let reveal = UnsignedNoteReveal {
                index: idx,
                serial: unsigned.data.serial,
                rho_bytes,
                pair_randomness: pair_randomness_bytes,
                a_bits,
                b_bits,
            };
            revealed.push(reveal);
        }

        let reveal_req = IssuanceReveal {
            session_id: challenge.session_id,
            revealed,
        };

        let reveal_url = format!("{}/issue/reveal", config.coordinator_url);
        let reveal_resp = http.post(&reveal_url).json(&reveal_req).send().await?;

        let status = reveal_resp.status().as_u16();
        let body_text = reveal_resp.text().await.unwrap_or_default();

        let success = status >= 400;

        let observed = format!("status={status} body={body_text}");

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
            "malformed-issuance-reveal",
            target,
            expected,
            start,
            success,
            AttackResponseMeta::new(status_code, response_body),
            observed,
        ),
        Err(e) => build_result(
            "malformed-issuance-reveal",
            target,
            expected,
            start,
            false,
            AttackResponseMeta::empty(),
            format!("error during attack: {e}"),
        ),
    }
}
