# QBIND Architecture Diagrams

Technical diagrams for the QBIND post-quantum Layer-1 blockchain protocol.

---

## 1. High-Level System Overview

### 1.1 QBIND Ecosystem

```mermaid
flowchart TB
    subgraph Users["Users & Applications"]
        W[Wallets]
        D[DApps]
        SDK[SDKs]
    end

    subgraph Network["QBIND Network"]
        subgraph Validators["Validator Nodes"]
            V1[Validator 1]
            V2[Validator 2]
            V3[Validator 3]
            Vn[Validator N]
        end

        subgraph FullNodes["Full Nodes"]
            FN1[Full Node 1]
            FN2[Full Node 2]
        end
    end

    subgraph Infra["Infrastructure"]
        EXP[Block Explorers]
        RPC[RPC Providers]
        ARCH[Archival Nodes]
    end

    subgraph External["External Systems"]
        EC[External Chains]
        BRIDGE[Bridges - Future]
        L2[L2 Hub - Future]
    end

    W -->|JSON-RPC| RPC
    D -->|JSON-RPC| RPC
    SDK -->|JSON-RPC| RPC

    RPC --> FN1
    RPC --> FN2

    FN1 <-->|P2P KEMTLS| V1
    FN2 <-->|P2P KEMTLS| V2

    V1 <-->|P2P KEMTLS| V2
    V2 <-->|P2P KEMTLS| V3
    V3 <-->|P2P KEMTLS| Vn
    Vn <-->|P2P KEMTLS| V1

    FN1 --> EXP
    FN2 --> ARCH

    L2 -.->|Validity Proofs| V1
    BRIDGE -.->|zk State Proofs| L2
    EC -.->|Cross-Chain| BRIDGE
```

**Caption:** The QBIND ecosystem comprises user-facing clients (wallets, dApps, SDKs) that submit transactions via JSON-RPC to full nodes. Full nodes relay transactions to the validator network, which runs HotStuff BFT consensus. All validator-to-validator and node-to-node communication is secured via KEMTLS (ML-KEM-768). Block explorers and archival nodes index chain data for queries. Future L2 and bridge components (dashed lines) will connect external chains via zk validity proofs.

---

### 1.2 Validator Node Internals

```mermaid
flowchart TB
    subgraph Node["QBIND Validator Node"]
        subgraph P2P["P2P Network Layer"]
            KEMTLS[KEMTLS Transport<br/>ML-KEM-768]
            DISC[Peer Discovery]
            ECLIPSE[Anti-Eclipse<br/>Protections]
            LIVE[Liveness Detection]
        end

        subgraph DAG["DAG Mempool Layer"]
            BATCH[Batch Formation]
            ACK[Ack Collection]
            CERT[Batch Certificates<br/>2f+1]
            DOS[DoS Protections]
        end

        subgraph CONS["Consensus Layer (HotStuff BFT)"]
            PROP[Proposals<br/>Leader]
            VOTE[Votes<br/>3-chain]
            QC[Quorum<br/>Certificates]
            PACE[Pacemaker]
        end

        subgraph EXEC["Execution Layer"]
            VM[VM v0<br/>Transfer-Only]
            STAGE[Stage A/B<br/>Parallel Exec]
            STATE[State<br/>RocksDB]
            SNAP[Snapshots]
        end

        subgraph SIGNER["Signer Subsystem"]
            ENC[EncryptedFs<br/>Keystore]
            REMOTE[Remote<br/>Signer]
            HSM[HSM/PKCS#11]
        end

        subgraph METRICS["Observability"]
            PROM[Prometheus<br/>Metrics]
            LOG[Structured<br/>Logging]
        end
    end

    P2P --> DAG
    DAG --> CONS
    CONS --> EXEC
    SIGNER --> CONS
    SIGNER --> DAG
    EXEC --> STATE
    STATE --> SNAP

    PROM --> P2P
    PROM --> DAG
    PROM --> CONS
    PROM --> EXEC
```

**Caption:** A QBIND validator node is organized into layered subsystems. The **P2P layer** handles KEMTLS-secured transport, peer discovery, and anti-eclipse protections. The **DAG mempool** forms transaction batches, collects 2f+1 acknowledgments, and produces batch certificates. The **consensus layer** runs HotStuff BFT with proposals, votes, quorum certificates, and view-change pacemaker. The **execution layer** applies committed blocks via the VM v0 transfer engine with optional Stage B parallel execution, persisting state to RocksDB. The **signer subsystem** supports multiple key backends (encrypted filesystem, remote signer, HSM/PKCS#11). Prometheus metrics and structured logging provide observability across all layers.

---

## 2. Transaction Lifecycle "Circuit"

```mermaid
sequenceDiagram
    participant W as User Wallet
    participant RPC as RPC Node
    participant MP as Node Mempool
    participant DAG as DAG Layer
    participant CONS as Consensus
    participant EXEC as Execution
    participant STATE as State DB

    Note over W: User signs tx with<br/>ML-DSA-44

    W->>RPC: Submit Tx (PQC signed)
    RPC->>RPC: Verify ML-DSA-44 signature
    RPC->>MP: Add to local mempool

    Note over MP,DAG: Validator forms batch

    MP->>DAG: Batch formation
    DAG->>DAG: Sign batch (ML-DSA-44)
    DAG-->>DAG: Broadcast to peers<br/>(KEMTLS encrypted)

    Note over DAG: Collect 2f+1 acks

    loop Each peer validator
        DAG->>DAG: Peer verifies batch
        DAG->>DAG: Peer sends BatchAck<br/>(ML-DSA-44 signed)
    end

    DAG->>DAG: Form BatchCertificate<br/>(2f+1 acks)

    Note over CONS: Leader proposes block

    DAG->>CONS: Certified batches → proposal
    CONS->>CONS: Leader signs proposal<br/>(ML-DSA-44)
    CONS-->>CONS: Broadcast proposal<br/>(KEMTLS)

    Note over CONS: HotStuff 3-chain commit

    loop Prepare → Pre-commit → Commit
        CONS->>CONS: Validators vote<br/>(ML-DSA-44)
        CONS->>CONS: Collect QC (2f+1 votes)
    end

    CONS->>EXEC: Commit block
    EXEC->>EXEC: Execute txs<br/>(Stage A or B)
    EXEC->>STATE: Update state root
    STATE->>STATE: Persist to RocksDB

    Note over STATE: Finality achieved
```

**Caption:** A transaction's lifecycle begins when a user wallet signs it with ML-DSA-44 and submits to an RPC node. The node verifies the signature and adds it to the local mempool. Periodically, validators form batches of pending transactions, sign them with ML-DSA-44, and broadcast to peers via KEMTLS-encrypted channels. Upon receiving a batch, peer validators verify and return signed BatchAck messages. Once 2f+1 acks are collected, a BatchCertificate is formed, proving data availability. The HotStuff leader includes certified batch references in its proposal, signs with ML-DSA-44, and broadcasts. Validators vote through the 3-chain commit rule (prepare → pre-commit → commit), each phase requiring a quorum certificate. Upon commit, the execution layer processes transactions and updates the state root in RocksDB.

---

## 3. DAG + Consensus Coupling

```mermaid
flowchart TB
    subgraph Mempool["Transaction Mempool"]
        TX1[Tx 1]
        TX2[Tx 2]
        TX3[Tx 3]
        TXn[Tx N]
    end

    subgraph DAG["DAG Layer"]
        subgraph Batching["Batch Formation"]
            B1[Batch A<br/>signed by V1]
            B2[Batch B<br/>signed by V2]
            B3[Batch C<br/>signed by V3]
        end

        subgraph Acks["Acknowledgment Collection"]
            A1["BatchAck from V1<br/>(ML-DSA-44)"]
            A2["BatchAck from V2<br/>(ML-DSA-44)"]
            A3["BatchAck from V3<br/>(ML-DSA-44)"]
            An["BatchAck from Vn<br/>(ML-DSA-44)"]
        end

        subgraph Certs["Batch Certificates (2f+1)"]
            C1[Cert for Batch A]
            C2[Cert for Batch B]
            C3[Cert for Batch C]
        end
    end

    subgraph Consensus["Consensus Layer"]
        subgraph Proposal["Block Proposal"]
            PROP[Leader Proposal<br/>batch_commitment field]
        end

        subgraph Voting["Voter Verification"]
            CHECK["Verify:<br/>1. All batch refs have valid certs<br/>2. Certs have 2f+1 valid sigs<br/>3. Batch data is available"]
        end

        subgraph Commit["Commit"]
            QC[Quorum Certificate]
            FINAL[Finalized Block]
        end
    end

    TX1 --> B1
    TX2 --> B1
    TX3 --> B2
    TXn --> B3

    B1 --> A1
    B1 --> A2
    B1 --> A3
    B2 --> A1
    B2 --> A2
    B2 --> An

    A1 --> C1
    A2 --> C1
    A3 --> C1
    A1 --> C2
    A2 --> C2
    An --> C2

    C1 --> PROP
    C2 --> PROP
    C3 --> PROP

    PROP --> CHECK
    CHECK -->|Valid| QC
    CHECK -->|Invalid: reject| PROP
    QC --> FINAL

    style CHECK fill:#e6f3ff,stroke:#0066cc
```

**Caption:** The DAG–consensus coupling mechanism prevents data-withholding attacks. Transactions are grouped into batches, each signed by the creating validator. Batches are disseminated to all validators, who return ML-DSA-44-signed BatchAck messages. Once a batch accumulates 2f+1 acknowledgments, a BatchCertificate is formed, cryptographically proving that a supermajority of validators have received the batch data. The HotStuff leader includes only certified batch references (the "DAG frontier") in its `batch_commitment` field. Before voting, each voter verifies: (1) all referenced batches have valid certificates, (2) each certificate contains 2f+1 valid ML-DSA-44 signatures, and (3) the voter possesses the actual batch data. If verification fails, the voter rejects the proposal. This coupling ensures committed blocks only reference provably-available data.

---

## 4. Networking / KEMTLS Handshake

```mermaid
sequenceDiagram
    participant A as Validator A
    participant B as Validator B

    Note over A,B: KEMTLS Handshake<br/>(ML-KEM-768)

    A->>A: Generate ephemeral<br/>KEM keypair

    A->>B: ClientHello<br/>+ A's ephemeral public key<br/>+ A's static P2P identity key

    B->>B: Encapsulate shared secret<br/>using A's ephemeral pubkey

    B->>A: ServerHello<br/>+ B's static P2P identity key<br/>+ KEM ciphertext

    A->>A: Decapsulate to get<br/>shared secret

    Note over A,B: Both derive session key<br/>via HKDF

    A->>A: session_key = HKDF(<br/>shared_secret,<br/>"QBIND-P2P-Session")

    B->>B: session_key = HKDF(<br/>shared_secret,<br/>"QBIND-P2P-Session")

    Note over A,B: Mutual authentication<br/>via identity keys

    A->>B: Auth message<br/>(encrypted with session key)
    B->>A: Auth message<br/>(encrypted with session key)

    Note over A,B: Encrypted P2P Stream<br/>Established

    rect rgb(230, 243, 255)
        A->>B: DAG batches, acks<br/>(encrypted)
        B->>A: Consensus votes, proposals<br/>(encrypted)
        A->>B: Heartbeats<br/>(encrypted)
    end
```

**Caption:** KEMTLS provides post-quantum authenticated key exchange between validators. Validator A initiates by generating an ephemeral ML-KEM-768 keypair and sending its ephemeral public key plus static P2P identity key in ClientHello. Validator B encapsulates a shared secret using A's ephemeral public key and returns the ciphertext in ServerHello along with B's static identity key. A decapsulates to recover the shared secret. Both parties derive symmetric session keys using HKDF with domain separation ("QBIND-P2P-Session"). Mutual authentication is performed using the registered P2P identity keys. Once the handshake completes, all subsequent P2P traffic—DAG batches, acknowledgments, consensus messages, and heartbeats—flows over the encrypted channel. This provides quantum-resistant confidentiality and authentication for all validator communication.

---

## 5. Monetary Engine & Token Flows (Skeleton)

```mermaid
flowchart TB
    subgraph Inflation["Inflation Source"]
        MINT[New Token<br/>Minting]
        PHASE[Phase Parameters<br/>Bootstrap → Transition → Mature]
        PQC_ADJ[PQC Cost<br/>Adjustment Factor]
    end

    subgraph Distribution["Seigniorage Distribution"]
        VAL_POOL[Validator<br/>Reward Pool]
        TREASURY[Protocol<br/>Treasury]
        INSURANCE[Insurance<br/>Reserve]
    end

    subgraph Validators["Validator Rewards"]
        V1[Validator 1]
        V2[Validator 2]
        Vn[Validator N]
    end

    subgraph Fees["Fee Circuit"]
        USER[User Fees<br/>per transaction]
        FEE_SPLIT{Fee Split<br/>50/50}
        BURN[Burn<br/>50%]
        PROPOSER[Block Proposer<br/>50%]
    end

    subgraph FeeOffset["Fee-Based Inflation Offset"]
        EMA[EMA Fee<br/>Smoothing]
        OFFSET[Inflation<br/>Reduction]
    end

    MINT --> VAL_POOL
    MINT --> TREASURY
    MINT --> INSURANCE

    PHASE --> MINT
    PQC_ADJ --> MINT

    VAL_POOL --> V1
    VAL_POOL --> V2
    VAL_POOL --> Vn

    USER --> FEE_SPLIT
    FEE_SPLIT --> BURN
    FEE_SPLIT --> PROPOSER

    USER --> EMA
    EMA --> OFFSET
    OFFSET --> MINT

    style BURN fill:#ffcccc,stroke:#cc0000
    style MINT fill:#ccffcc,stroke:#00cc00
```

**Caption:** The QBIND monetary engine operates as a value circuit balancing inflation and fees. **Inflation** mints new tokens based on phase parameters (Bootstrap: ~8–9%, Transition: ~6–7%, Mature: ~4–5%), adjusted upward by PQC computational cost factors (β_compute, β_bandwidth, β_storage). Newly minted tokens flow to the validator reward pool (primary), protocol treasury (secondary), and insurance reserve. **Transaction fees** are split 50/50: half is burned (reducing supply), half goes to the block proposer. Fee revenue feeds into an EMA-smoothed offset mechanism that progressively reduces inflation as network usage grows. This creates a self-balancing system where security funding transitions from inflation-dominated (early) to fee-dominated (mature).

---

## 6. Governance & Upgrade Envelope

```mermaid
sequenceDiagram
    participant GOV as Governance Forum
    participant COUNCIL as Protocol Council<br/>(M-of-N Multi-sig)
    participant ENV as Upgrade Envelope
    participant OPS as Node Operators
    participant NET as MainNet

    Note over GOV,COUNCIL: Off-chain deliberation

    GOV->>GOV: Proposal discussion
    GOV->>GOV: Technical review
    GOV->>COUNCIL: Formal proposal

    Note over COUNCIL: M-of-N approval<br/>(M=5, N=7 typical)

    loop Council Members Sign
        COUNCIL->>COUNCIL: Member reviews
        COUNCIL->>ENV: ML-DSA-44 signature
    end

    Note over ENV: Envelope formation<br/>when M signatures collected

    ENV->>ENV: Assemble envelope:<br/>- protocol_version<br/>- activation_height<br/>- binary_hashes<br/>- council_approvals[]

    ENV->>OPS: Publish envelope to<br/>governance repo

    Note over OPS: Operator verification

    OPS->>OPS: qbind-envelope verify<br/>- Check M-of-N sigs<br/>- Verify binary hashes<br/>- Confirm activation_height

    alt Class A/B Upgrade
        OPS->>NET: Rolling deployment
    else Class C Hard Fork
        Note over OPS,NET: Coordinated activation
        OPS->>OPS: Upgrade binary
        OPS->>OPS: Wait for activation_height
        NET->>NET: Protocol activates<br/>at specified height
    end

    Note over NET: Upgrade complete
```

**Caption:** QBIND's governance flow uses off-chain deliberation with cryptographic accountability. Proposals are discussed in the governance forum and submitted to the Protocol Council for approval. Council members (N=7, threshold M=5) independently review and sign the proposal using ML-DSA-44. Once M signatures are collected, an Upgrade Envelope is assembled containing: protocol version, activation height, binary hashes (SHA3-256), and the array of council signatures. The envelope is published to the governance repository. Node operators verify the envelope using the `qbind-envelope verify` command, which checks signature validity, binary authenticity, and activation parameters. For Class A/B upgrades, operators deploy via rolling restart. For Class C hard forks, all operators upgrade their binaries before the coordinated activation height, at which point the network simultaneously activates the new protocol rules.

---

*End of Diagrams Document*