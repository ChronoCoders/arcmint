Overview
========

ArcMint is a federated anonymous e-cash prototype. It implements a cut-and-choose issuance protocol, threshold FROST signing over Ristretto, and privacy-preserving spending with selective opening proofs. The codebase is organized as a Rust workspace with separate binaries for the federation signers, coordinator, gateway, wallet, and merchant.

Architecture
============

Participants and roles
----------------------

- Signers: Maintain the canonical issued and spent note registries, participate in FROST signing, and enforce double-spend protection. Each signer stores its own SQLite-backed registry and uses a shared FROST key package.
- Coordinator: Orchestrates multi-signer FROST signing for note issuance and manages anchoring of registry Merkle roots into an external consensus system (for example, Bitcoin). It exposes HTTP APIs for issuance, spending, and audit.
- Gateway: Fronts user registration and rate limiting. It issues HMAC-based gateway tokens that authorize note issuance, and later resolves de-anonymized identities in the event of a double spend.
- Wallet: Client-side tool that manages user identity secrets, note issuance via cut-and-choose, and spend proof generation. It stores secrets and notes locally in a wallet file with strict filesystem permissions.
- Merchant: Verifies signed notes, interacts with the coordinator for registry checks and spend verification, and records accepted payments in its own SQLite database.

Separation invariants
---------------------

- Signers do not interact directly with end users or merchants; they only trust requests authenticated by the coordinator’s secret.
- The coordinator never sees user identities directly; it only observes blinded commitments, serial numbers, and spend proofs.
- The gateway never sees note serials or spend proofs; it only manages identity registration, rate limiting, and double-spend resolution requests.
- The wallet never shares long-term secrets (such as r_u or the wallet file contents); it only talks to the gateway, coordinator, and merchants via their HTTP APIs.
- The merchant is untrusted by the federation; it must prove note validity through the coordinator’s spend verification APIs.

Quick Start (Docker)
====================

Prerequisites
-------------

- Docker
- Docker Compose v2

Steps
-----

1. Copy `.env.example` to `.env` and adjust values if needed:

   cp .env.example .env

2. Build the images and start the stack:

   docker compose up --build

3. The following endpoints are available by default (host-side ports can be changed via `.env`):

- Coordinator: http://localhost:7000
- Signer 1: http://localhost:7001
- Signer 2: http://localhost:7002
- Signer 3: http://localhost:7003
- Gateway: http://localhost:7002
- Merchant: http://localhost:7003

All services expose `/health` for basic liveness checks, which are wired into Docker health checks.

Monitoring (Prometheus & Grafana)
=================================

- To start the core stack plus the monitoring profile (Prometheus and Grafana), run:

  docker compose --profile monitoring up

- Prometheus UI: http://localhost:9090
- Grafana UI: http://localhost:3000 (admin / GRAFANA_PASSWORD from your `.env`, default `arcmint-dev`)
- Dashboards are auto-provisioned from `monitoring/grafana/dashboards`:
  - `arcmint-federation.json` – federation health (issuance, sessions, DB latency, anchor status)
  - `arcmint-lightning.json` – channel balances, LN payment latency, mint-in/mint-out
  - `arcmint-security.json` – double-spend attempts, verification failures, rate limiting, key validation
- The security dashboard is configured as the default Grafana home dashboard so double-spend and verification failures are immediately visible.
- Note: `/metrics` endpoints are only exposed on the internal Docker network and are not intended to be reachable from the public internet.

Manual Run
==========

Environment files
-----------------

For manual runs outside Docker, you can reuse `.env.example` as a starting point. The following environment variables are particularly important:

- FEDERATION_DB, GATEWAY_DB, MERCHANT_DB
- FROST_KEY_FILE, FROST_PUBKEY_FILE, INIT_DEV_KEYS, SIGNER_ID
- COORDINATOR_PORT, GATEWAY_PORT, MERCHANT_PORT
- GATEWAY_SECRET, FEDERATION_SECRET, COORDINATOR_SECRET, OPERATOR_SECRET
- SIGNER_URLS, GATEWAY_RESOLVE_URL
- TLS_CERT_FILE, TLS_KEY_FILE, TLS_CA_FILE, INTERNAL_CA_FILE
- COORDINATOR_TLS_CERT, COORDINATOR_TLS_KEY, GATEWAY_CLIENT_CA
- COORDINATOR_URL, GATEWAY_URL
- ACME_DOMAIN, ACME_EMAIL, ACME_CACHE_DIR, ACME_STAGING

Suggested startup order
-----------------------

1. Signer(s)

   - Ensure FEDERATION_DB, FROST_KEY_FILE, and FROST_PUBKEY_FILE are set.
   - For single-signer development, set:

     INIT_DEV_KEYS=true
     SIGNER_ID=1

   - Run:

     cargo run -p arcmint-federation

2. Coordinator

   - Ensure SIGNER_URLS points at the running signer(s) over HTTPS, for example:

     SIGNER_URLS=https://127.0.0.1:7001

   - Configure FROST_PUBKEY_FILE to match the key file used by the signer.
   - Set GATEWAY_SECRET, COORDINATOR_SECRET, GATEWAY_RESOLVE_URL, optional anchoring parameters, and OPERATOR_SECRET (optional).
   - Run:

     cargo run -p arcmint-federation --bin coordinator

3. Gateway

   - Configure GATEWAY_DB, GATEWAY_SECRET, FEDERATION_SECRET, and TLS/ACME variables (TLS_CERT_FILE/TLS_KEY_FILE or ACME_DOMAIN and related settings).
   - Run:

     cargo run -p arcmint-gateway

4. Merchant

   - Configure MERCHANT_DB, COORDINATOR_URL, and FROST_PUBKEY_FILE.
   - Run:

     cargo run -p arcmint-merchant

5. Wallet CLI

   - Configure COORDINATOR_URL, GATEWAY_URL, and WALLET_DIR (or use defaults).
   - Example flows:

     arcmint-wallet register --identity-id alice
     arcmint-wallet generate-note --denomination 1000 --k 32
     arcmint-wallet list-notes
     arcmint-wallet spend --serial <note-serial-hex> --merchant-url http://localhost:7003

6. Adversary CLI

   - Configure COORDINATOR_URL, GATEWAY_URL, MERCHANT_URL, SIGNER_URLS, and TLS_CA_FILE.
   - To run the full adversary suite against a running deployment:

     cargo run -p arcmint-adversary -- run-all --coordinator-url https://localhost:7000 --gateway-url https://localhost:7002 --merchant-url http://localhost:7003 --signer-urls https://localhost:7001 --output report.json

   - Each attack in the suite exercises a specific property:
     - attack_forged_signature: attempts to submit a note with a forged FROST signature.
     - attack_malformed_note_missing_pairs: submits a note with an empty commitment pair list.
     - attack_malformed_note_wrong_denomination: tampers with the note denomination after signing.
     - attack_registry_bypass_skip_issued_check: forges a note whose serial is not in the issued registry.
     - attack_wrong_commitment_opening: uses incorrect commitment openings in the spend proof.
     - attack_challenge_precomputation: reuses a proof generated for an all-zero challenge.
     - attack_double_spend: attempts to spend the same note twice at a single merchant.
     - attack_double_spend_different_merchants: attempts to spend the same note at two merchants.
     - attack_theta_recovery_verification: checks that identity secrets cannot be recovered from notes.
     - attack_replay_spent_note: replays a spend of an already spent note.
     - attack_flood_issuance: floods the gateway with issuance attempts to exercise rate limiting.
     - attack_signer_direct_access: calls signer round1 endpoints directly without a coordinator client certificate.
     - attack_malformed_issuance_reveal: corrupts issuance reveal bit shares to trigger InvalidProof.
     - attack_expired_note: attempts to complete a payment after the pending spend expiry window.

   - The adversary JSON report (written with --output) contains:
     - A top-level run identifier, timestamps, and coordinator URL.
     - A list of per-attack results with fields:
       - attack_name, target, success, expected_behavior, observed_behavior
       - status_code, response_body, duration_ms, timestamp
   - All adversary attacks expect the system to reject the malicious request. A PASS means the system rejected the attack as expected. A FAIL means the system accepted an attack that should have been rejected and indicates a potential vulnerability.

Key Management
==============

Development mode
----------------

- In development, FROST keys are generated by the keygen binary, which uses a trusted dealer to generate per-signer key packages and a shared public key package. Keys are written into a shared volume and mounted read-only into signers, the coordinator, and the merchant.
- Development keys are intended only for local testing; they are not suitable for production.

Production / DKG
----------------

- In a production deployment, FROST keys must be established using a proper distributed key generation (DKG) protocol, and INIT_DEV_KEYS must be disabled.
- Each signer should persist its own key package, and the public key package must be distributed to the coordinator and any services that need to verify signatures (such as merchants).
- Secrets such as GATEWAY_SECRET, FEDERATION_SECRET, COORDINATOR_SECRET, and OPERATOR_SECRET must be generated with high entropy and managed via a secure secret management system, not via static environment files.

Production Key Generation
-------------------------

This section describes the recommended DKG-based key generation process for production deployments using the dkg_coordinator and dkg_participant binaries.

1. Prerequisites

- There are n federation operators, each running on a separate machine in a separate jurisdiction.
- An internal CA certificate and key have been generated, and the CA certificate has been distributed to all operators out-of-band.
- Each operator has been assigned a unique participant-id and a unique operator-token.
- A coordinator server is running the DKG coordinator binary and is reachable by all operators over mTLS.

2. Ceremony procedure

- Operator 1 starts the ceremony by running dkg_participant with the --create-ceremony flag and the agreed threshold t and number of signers n.
- All operators run dkg_participant with their own participant-id, operator-token, coordinator URL, and output directory.
- Each operator monitors their terminal; the tool will indicate when rounds progress (Round1, Round2, output).
- When the ceremony completes, each operator notes the final transcript hash printed by their local tool.
- Operators communicate the transcript hash out-of-band (for example, via a voice call or Signal group) and confirm that all hashes are identical.
- If any operator observes a different transcript hash, the ceremony is considered compromised and must be aborted and restarted from scratch.

3. Post-ceremony handling

- Each operator ends the ceremony with a signer_{id}_key.json file in their chosen output directory. This file must be stored with filesystem permissions equivalent to mode 0600 and must never be transmitted or copied off the operator’s machine.
- All operators obtain an identical public_key.json file, which contains the shared FROST public key package and is safe to distribute.
- The public_key.json file is copied to the coordinator, gateway, and merchant deployments so that all services verify signatures against the same key.
- On each service, FROST_PUBKEY_FILE is updated to point to the new public_key.json.
- A rolling restart of the coordinator, gateway, and merchant services is performed so that the new public key takes effect everywhere without a global outage.

4. Key rotation

- Rotating FROST keys in production requires a full DKG ceremony; there is no supported partial rotation.
- Existing keys remain active until the new ceremony has completed successfully, transcript hashes have been verified, and all services have been restarted with the new public key.
- Only once the new key is confirmed live across all services should the old key material be retired.

5. Operator token security

- Operator tokens are used to derive encryption keys for DKG share exchange. Compromise of a token can weaken share confidentiality.
- Tokens must be high-entropy secrets, with at least 32 random bytes encoded as hex.
- Operator tokens must never be reused across ceremonies; generate new tokens for each DKG run.
- Tokens should be distributed to operators out-of-band and stored securely for the duration of the ceremony.
- After the ceremony completes and key material has been confirmed, operator tokens should be destroyed and not retained.

TLS and Certificates
====================

Development (Docker)
--------------------

- The provided `docker-compose.yml` starts a one-shot `certgen` service that generates an internal CA, signer server certificates, a coordinator server certificate, a gateway server certificate, and mTLS client certificates for the coordinator and gateway.
- All services mount the generated `/certs` volume and are wired for TLS by default:
  - Signers use `TLS_CERT_FILE`, `TLS_KEY_FILE`, `TLS_CA_FILE`, and `COORDINATOR_CN`.
  - The coordinator uses `COORDINATOR_TLS_CERT`, `COORDINATOR_TLS_KEY`, `COORDINATOR_CLIENT_CERT`, `COORDINATOR_CLIENT_KEY`, `INTERNAL_CA_FILE`, `GATEWAY_CLIENT_CA`, and `GATEWAY_CN`.
  - The gateway uses `TLS_CERT_FILE`, `TLS_KEY_FILE`, `GATEWAY_CLIENT_CERT`, `GATEWAY_CLIENT_KEY`, and `INTERNAL_CA_FILE`.
- In this setup, `ACME_DOMAIN` is left empty so the gateway terminates TLS using the internal CA certificate.

Production gateway TLS
----------------------

- For a public-facing deployment, configure the gateway with `ACME_DOMAIN` set to the externally reachable hostname (for example, `gateway.example.com`).
- Optionally set `ACME_EMAIL` for Let's Encrypt account notifications and `ACME_CACHE_DIR` for storing account and certificate material; `ACME_STAGING=true` can be used when testing against the Let's Encrypt staging environment.
- In production, the gateway should use Let's Encrypt for its public TLS certificate while the internal mesh (signers and coordinator) continues to rely on the internal CA and the corresponding `*_TLS_*` and `INTERNAL_CA_FILE` variables.

Certificate rotation
--------------------

- For Docker-based development, rotate internal certificates by re-running the `certgen` service to regenerate the CA and all dependent certificates, then restart the signers, coordinator, and gateway so they pick up the new files.
- In production, when rotating the internal CA and service certificates, ensure that:
  - New certificates are generated and written to the appropriate locations.
  - Dependent services are restarted in a rolling fashion so that at least one valid instance remains available during the transition.
  - Any long-lived clients refresh their TLS configuration to trust the new CA before old certificates are revoked.

Anchoring
=========

The coordinator anchors the federation's state to the Bitcoin blockchain to provide an immutable timestamp and prevent long-range attacks.

Wallet Setup
------------

The coordinator requires a Bitcoin wallet to pay for anchor transactions.

1.  Create a wallet and generate an address:

    ```bash
    bitcoin-cli createwallet anchor
    bitcoin-cli -rpcwallet=anchor getnewaddress
    ```

2.  Fund the address with at least 0.001 BTC.
3.  Export the WIF private key:

    ```bash
    bitcoin-cli -rpcwallet=anchor dumpprivkey <address>
    ```

4.  Set `ANCHOR_WALLET_WIF` and `ANCHOR_CHANGE_ADDRESS` in `.env`.

Cost Estimates
--------------

-   **Minimum UTXO**: 0.001 BTC (to avoid "insufficient funds" errors during fee spikes).
-   **Cost per anchor**: ~500-2000 satoshis at normal fee rates (assuming 1 input, 2 outputs, OP_RETURN).
-   **Confirmation target**: 6 blocks (~1 hour).

Known Limitations
=================

The following limitations are summarized from Section 10 of the whitepaper:

- Trust assumptions: The protocol assumes an honest majority of federation signers and a correct implementation of FROST. Collusion of a sufficient number of signers can break unlinkability and potentially forge notes.
- Anonymity set size: The effective anonymity set is limited by the issuance volume, denomination structure, and wallet behavior. Small or highly distinctive denominations may lead to smaller anonymity sets.
- Denial-of-service: Malicious clients, merchants, or signers can attempt to trigger denial-of-service conditions by flooding the system with malformed requests or by refusing to participate in signing rounds.
- Side channels: The implementation does not attempt to mitigate all possible side channels (such as precise timing, cache attacks, or network-level metadata leakage). Deployments should consider additional hardening where required.
- Non-persistence of anchors: Anchoring into an external consensus system (for example, Bitcoin) does not by itself guarantee long-term availability of historical data; operators remain responsible for archiving and monitoring anchor status.
 - Blind threshold Schnorr security gap: The implementation uses the blind threshold Schnorr construction described in the whitepaper. A complete security proof for this exact variant is still an open item; deployments should treat this as an engineering assumption rather than a fully proven primitive.

For continuous integration, note that the end-to-end integration tests in tests/integration/tests/full_flow.rs are marked #[ignore]. CI pipelines should run them explicitly with:

    cargo test -p arcmint-integration --test full_flow -- --ignored

in addition to:

    cargo test --workspace

Lightning Testing
=================

The Lightning-enabled integration tests depend on a running regtest environment with bitcoind and LND. The recommended setup is:

1. Start the Docker-based regtest stack:

       docker compose up bitcoind lnd lnd-init miner

   This launches:

   - bitcoind on regtest with RPC exposed on localhost:18443
   - lnd on regtest with gRPC on 10009 and REST on 8080
   - lnd-init to fund the LND wallet
   - miner to auto-mine blocks and keep the chain moving

2. Export the LND and Bitcoin RPC environment variables for the integration tests:

       export LND_HOST=localhost
       export LND_PORT=10009
       export LND_REST_PORT=8080
       export LND_TLS_CERT=/path/to/tls.cert
       export LND_MACAROON=/path/to/admin.macaroon

       export BITCOIN_RPC_URL=http://localhost:18443
       export BITCOIN_RPC_USER=arcmint
       export BITCOIN_RPC_PASS=arcmintpass

   The TLS certificate and macaroon paths must point to files readable from the host running the tests.

3. Run the Lightning integration tests explicitly:

       cargo test -p arcmint-integration --test full_flow -- --ignored --nocapture

Load Testing
============

Smoke (CI):

    cargo run -p arcmint-loadtest -- run-all --config loadtest/smoke.toml --output report.json

Standard (pre-release):

    cargo run -p arcmint-loadtest -- run-all --config loadtest/standard.toml

Stress:

    cargo run -p arcmint-loadtest -- run-all --config loadtest/stress.toml

Docker:

    docker compose --profile loadtest up arcmint-loadtest

Spend race only:

    cargo run -p arcmint-loadtest -- run-spend-race --config loadtest/standard.toml

Service-level objectives (SLOs):

Metric                          Smoke threshold     Standard threshold  Stress threshold
------------------------------  ------------------  ------------------  ----------------
issuance_p99_max_ms             5000 ms             2000 ms             10000 ms
spend_p99_max_ms                3000 ms             1000 ms             5000 ms
signer_rpc_p99_max_ms           1000 ms             500 ms              2000 ms
lightning_settlement_p99_max_ms 10000 ms            5000 ms             30000 ms
signing_failure_rate_max        0.01                0.001               0.05
lightning_failure_rate_max      0.05                0.01                0.05
spend_false_negatives_allowed   0                   0                   0

Note: spend_false_negatives_allowed = 0 is never relaxed regardless of config.

Environment Variable Reference
==============================

Variable                  Default                 Description
------------------------  ----------------------  -----------------------------------------------
COORDINATOR_PORT          7000                    Coordinator HTTP listen port
SIGNER1_PORT              7001                    Host port mapped to signer-1 HTTP port
SIGNER2_PORT              7002                    Host port mapped to signer-2 HTTP port
SIGNER3_PORT              7003                    Host port mapped to signer-3 HTTP port
GATEWAY_PORT              7002                    Host port mapped to gateway HTTP port
MERCHANT_PORT             7003                    Host port mapped to merchant HTTP port
FEDERATION_DB             federation.db           SQLite path for signer registry (non-Docker)
GATEWAY_DB                gateway.db              SQLite path for gateway DB (non-Docker)
MERCHANT_DB               merchant.db             SQLite path for merchant DB (non-Docker)
FROST_KEY_FILE            frost_key.json          FROST key package file for signers
FROST_PUBKEY_FILE         frost_pubkey.json       FROST public key package file
SIGNER_ID                 1                       Signer identifier (unique per signer)
GATEWAY_SECRET            dev-gateway-secret      Shared HMAC secret for gateway tokens
FEDERATION_SECRET         dev-federation-secret   Shared secret for gateway <-> federation resolve
COORDINATOR_SECRET        dev-coordinator-secret  Shared secret for coordinator <-> signers
GATEWAY_RESOLVE_URL       https://localhost:7002/resolve  Coordinator callback URL into gateway (TLS)
SIGNER_URLS               https://localhost:7001  Comma-separated signer URLs for coordinator (mTLS)
ANCHOR_INTERVAL_SECS      600                     Anchoring interval in seconds
BITCOIN_RPC_URL           (empty)                 Optional Bitcoin Core RPC endpoint
BITCOIN_RPC_USER          (empty)                 Optional RPC username for Bitcoin Core
BITCOIN_RPC_PASS          (empty)                 Optional RPC password for Bitcoin Core
COORDINATOR_URL           https://localhost:7000  Base URL for coordinator APIs
GATEWAY_URL               https://localhost:7002  Base URL for gateway APIs
WALLET_DIR                ~/.arcmint              Default wallet directory for arcmint-wallet
TLS_CERT_FILE             (none)                  TLS certificate for gateway/signers (dev/internal CA)
TLS_KEY_FILE              (none)                  TLS private key for gateway/signers (dev/internal CA)
TLS_CA_FILE               (none)                  CA certificate for signer mTLS
INTERNAL_CA_FILE          (none)                  Internal CA certificate for mTLS clients
COORDINATOR_TLS_CERT      (none)                  Coordinator TLS server certificate (internal CA)
COORDINATOR_TLS_KEY       (none)                  Coordinator TLS private key
GATEWAY_CLIENT_CA         (none)                  CA verifying gateway client certificate
COORDINATOR_CLIENT_CERT   (none)                  Coordinator client cert for mTLS to signers
COORDINATOR_CLIENT_KEY    (none)                  Coordinator client key for mTLS to signers
COORDINATOR_CN            arcmint-coordinator     Expected coordinator client certificate CN
GATEWAY_CN                arcmint-gateway         Expected gateway client certificate CN
GATEWAY_CLIENT_CERT       (none)                  Gateway client cert for mTLS to coordinator
GATEWAY_CLIENT_KEY        (none)                  Gateway client key for mTLS to coordinator
ACME_DOMAIN               (empty)                 Public domain for gateway Let's Encrypt TLS
ACME_EMAIL                (empty)                 Contact email for Let's Encrypt (mailto:address)
ACME_CACHE_DIR            /var/lib/arcmint/acme   Cache directory for ACME account and certs
ACME_STAGING              false                   Use Let's Encrypt staging directory when true
OPERATOR_SECRET           (empty)                 Shared secret for operator-only APIs
