---
title: "Kerberos Authentication — The Primary Authentication Protocol"
doc_type: "foundation"
phase: 0
phase_name: "00-Foundations"
topic: "Authentication"
core_primitives: ["KDC", "AS-REQ", "AS-REP", "TGS-REQ", "TGS-REP", "TGT", "TGS", "PAC", "SPN", "krbtgt", "Pre-Authentication", "Delegation", "S4U2Self", "S4U2Proxy", "PKINIT"]
applies_to: ["Active Directory", "Kerberos KDC", "Windows Kernel"]
status: "verified"
tags: [foundation, internals, kerberos, kdc, tgt, tgs, pac, spn, krbtgt, delegation, golden-ticket, silver-ticket, kerberoasting]
---

# Kerberos Authentication — The Primary Authentication Protocol

> **Architectural Mission:** Master the internal mechanics of Kerberos Version 5 (RFC 4120) and Microsoft's enterprise extensions (MS-KILE, MS-PAC, MS-SFU). Understand how symmetric cryptography, ephemeral session keys, and privilege containers interact so that every downstream attack—from offline ticket cracking to cross-forest delegation abuse—becomes an obvious, mathematically inevitable consequence of protocol design.

---

## 1. Architectural Foundations & The Core Dilemma

### 1.1 The Fundamental Dilemma: Why Direct Authentication Fails
Consider a typical morning in an enterprise environment running Active Directory (AD):
An employee named **Ahmed** sits down at his assigned workstation `WKSTN01.corp.local` and logs in with his corporate credentials. Thirty minutes later, Ahmed needs to open an engineering specification spreadsheet stored on a network file server at `\\FS01.corp.local\engineering\specifications.xlsx`.

To access that file, the file server `FS01` must answer two fundamental questions:
1. **Authentication:** Who is attempting to connect? (Is this genuinely Ahmed?)
2. **Authorization:** What is this caller permitted to do? (Does Ahmed have read access to the engineering folder?)

In a naive network architecture, Ahmed’s workstation would simply transmit his username and password (or password hash) directly over the wire to `FS01`. In an enterprise with thousands of servers and tens of thousands of users, this direct credential transmission model immediately collapses under three fatal architectural vulnerabilities:

1. **Credential Exposure to Untrusted Service Endpoints (The Rogue Server Problem):**
   If `WKSTN01` transmits Ahmed’s password or reusable cryptographic hash directly to `FS01`, the integrity of Ahmed’s credentials is only as secure as `FS01`’s least trustworthy administrator. If `FS01` is compromised by an adversary, or if the service administrator is untrustworthy, the rogue server can harvest Ahmed’s plaintext password or hash and reuse it across every other system in the enterprise—including Domain Controllers (DCs) and human resources systems.
2. **Plaintext Sniffing and Session Hijacking:**
   Even if encrypted at the transport layer, transmitting reusable credentials across arbitrary network segments exposes raw authenticators to wire-sniffing, man-in-the-middle interception, and replay attacks.
3. **Secret Proliferation and $N \times M$ Cryptographic Overhead:**
   If every workstation needed to authenticate directly with every service server without sending credentials over the network, every user would need to share a unique pre-shared secret with every single application server in the forest. In a domain of 10,000 users and 500 servers, this would require managing $5,000,000$ distinct shared cryptographic keys across workstations and endpoints—an administrative impossibility.

### 1.2 The Kerberos Solution: Cryptographic Envelopes and the Trusted Third Party
To solve this dilemma, Active Directory relies on **Kerberos Version 5**, an open standard protocol originally engineered at MIT (Project Athena) under **RFC 4120**, heavily enhanced by Microsoft through proprietary extensions (**MS-KILE**, **MS-PAC**, **MS-SFU**).

The design philosophy of Kerberos is built upon two immutable pillars:
1. **The Shared Secret Never Leaves the Owner:** Neither the user's password nor their long-term cryptographic key is ever transmitted across the network wire. Long-term keys are used solely as local encryption and decryption keys to seal and unseal temporary cryptographic envelopes.
2. **The Trusted Third Party (TTP):** All entities in the domain—human users, workstation computer accounts, service accounts, and domain controllers—mutually trust a single centralized authority: the **Key Distribution Center (KDC)**. The KDC holds a master database of long-term secrets for every principal in the domain.

When Ahmed wants to access `FS01`, he does not present his password to `FS01`. Instead:
- Ahmed proves his identity once to the KDC.
- The KDC hands Ahmed an encrypted, time-stamped credential called a **Ticket Granting Ticket (TGT)**.
- When Ahmed wants to talk to `FS01`, he presents his TGT back to the KDC and asks for an encrypted **Service Ticket** specifically addressed to `FS01`.
- The KDC issues a Service Ticket encrypted with `FS01`'s private long-term key, which Ahmed cannot open or tamper with.
- Ahmed presents this Service Ticket to `FS01`. Because only `FS01` and the KDC know `FS01`'s long-term key, `FS01` can decrypt the ticket, verify the KDC’s digital signature, read Ahmed’s identity and group memberships, and grant access—all without `FS01` ever knowing Ahmed’s password.

### 1.3 Terminology & Core Primitives (Zero-Acronym Onboarding)
Before tracing the wire packets, every component and acronym must be crystal clear:

- **Principal:** Any uniquely identifiable entity in the Kerberos realm that can request authentication or host a service. Principals take two forms:
  - *User Principals:* Represent human users or machine accounts (e.g., `ahmed@CORP.LOCAL` or `WKSTN01$@CORP.LOCAL`).
  - *Service Principals:* Represent network services running on hosts (e.g., `cifs/FS01.corp.local`).
- **Realm:** The administrative domain of authentication authority, represented in uppercase (e.g., `CORP.LOCAL`). In Active Directory, the Kerberos Realm maps directly to the Active Directory Domain Name.
- **KDC (Key Distribution Center):** The centralized authentication server running on every Active Directory Domain Controller (listening on UDP/TCP port 88). The KDC is logically split into two sub-services:
  - **AS (Authentication Service):** Issues initial Ticket Granting Tickets (TGTs) to verify principal identities.
  - **TGS (Ticket Granting Service):** Issues Service Tickets to authenticated clients presenting valid TGTs.
- **TGT (Ticket Granting Ticket):** An encrypted, time-bounded identity token issued by the Authentication Service (AS). It proves that the client has successfully authenticated to the domain. It is encrypted exclusively using the secret key of the domain's root Kerberos service account (`krbtgt`). The client cannot read or modify its TGT.
- **TGS (Ticket Granting Service) Ticket / Service Ticket:** An encrypted ticket issued by the Ticket Granting Service (TGS) allowing a client to authenticate to a specific application or service (such as SMB file sharing, MSSQL, or HTTP). It is encrypted with the long-term secret key of the target service account.
- **SPN (Service Principal Name):** A unique, forest-wide string registered on an Active Directory user or computer account that maps a network service to the specific Active Directory account whose cryptographic keys will be used to encrypt tickets for that service (e.g., `cifs/FS01.corp.local` or `MSSQLSvc/sql01.corp.local:1433`).
- **PAC (Privilege Attribute Certificate):** A proprietary Microsoft extension data structure appended to Kerberos tickets. It contains the user's complete Windows security context—Security Identifiers (SIDs), group memberships, user account control flags, and cryptographic signatures.
- **Session Key:** An ephemeral, short-lived symmetric cryptographic key generated on the fly by the KDC. A session key is shared exclusively between two parties (either Client $\leftrightarrow$ KDC, or Client $\leftrightarrow$ Service Server) to encrypt and sign communication for a single session without exposing long-term keys.
- **Authenticator:** A small data structure generated locally by a client containing the client's principal name and a microsecond-accurate timestamp, encrypted with the relevant ephemeral Session Key. It proves that the client genuinely possesses the Session Key without transmitting the key itself.
- **Pre-Authentication (PA-DATA):** A mechanism where the client must prove knowledge of its secret key (typically by encrypting the current timestamp) *before* the KDC will issue an AS-REP response containing a TGT.
- **FAST (Flexible Authentication Secure Tunneling):** An RFC 6113 Kerberos extension (often termed Kerberos Armoring) that encapsulates initial Kerberos exchanges inside an armored, encrypted tunnel derived from the computer account's keys, protecting pre-authentication exchanges against offline cracking.

---

## 2. Scenario Walkthrough: From Workstation to File Share

### 2.1 The Scenario Setup
To anchor every packet, timestamp, and key transformation in reality, follow this exact enterprise scenario:
- **Client User:** `ahmed` (Domain user account `CORP\ahmed`, Long-Term Key: $K_{ahmed}$).
- **Client Machine:** `WKSTN01.corp.local` (Windows 11 Enterprise).
- **Domain Controller / KDC:** `DC01.corp.local` (Active Directory Domain Services on `CORP.LOCAL`, holding root account `krbtgt` with Long-Term Key: $K_{krbtgt}$).
- **Target File Server:** `FS01.corp.local` (Windows Server hosting SMB share `\\FS01.corp.local\engineering`, running as computer account `CORP\FS01$` with Long-Term Key: $K_{FS01}$).
- **Target SPN:** `cifs/FS01.corp.local`.

---

### 2.2 Diagram 1: The Enterprise Kerberos Triad & Packet Flow

```text
  +----------------------------------------------------------------------------------------------------+
  |                           ENTERPRISE KERBEROS TRIAD & PACKET FLOW                                  |
  +----------------------------------------------------------------------------------------------------+

     CLIENT WORKSTATION                                 DOMAIN CONTROLLER                                 TARGET SERVICE
    [ ahmed @ WKSTN01 ]                                [ KDC on DC01 ]                                   [ cifs/FS01 ]
             |                                                 |                                                |
             |                                                 |                                                |
             | ====== PHASE 1: AS EXCHANGE (Initial Authentication) =========================================   |
             |                                                 |                                                |
             |  1. AS-REQ (UDP/TCP 88)                         |                                                |
             |  ---------------------------------------------> |                                                |
             |     - Client: ahmed@CORP.LOCAL                  |                                                |
             |     - Service: krbtgt/CORP.LOCAL                |                                                |
             |     - PA-ENC-TIMESTAMP: Encrypted with K_ahmed  |                                                |
             |                                                 |                                                |
             |                                  [KDC verifies timestamp with K_ahmed]                           |
             |                                  [KDC generates Logon Session Key: K_session_AS]                 |
             |                                  [KDC mints TGT and encrypts it with K_krbtgt]                   |
             |                                                 |                                                |
             |  2. AS-REP (UDP/TCP 88)                         |                                                |
             |  <--------------------------------------------- |                                                |
             |     - Encrypted with K_ahmed:                   |                                                |
             |         * Logon Session Key: K_session_AS       |                                                |
             |         * Ticket Expiration / Timestamps        |                                                |
             |     - Encrypted with K_krbtgt:                  |                                                |
             |         * TGT (Contains K_session_AS + PAC)     |                                                |
             |                                                 |                                                |
             | [ahmed unseals K_session_AS]                    |                                                |
             | [Stores TGT & K_session_AS in LSASS]            |                                                |
             |                                                 |                                                |
             | ====== PHASE 2: TGS EXCHANGE (Service Ticket Acquisition) =====================================  |
             |                                                 |                                                |
             |  3. TGS-REQ (UDP/TCP 88)                        |                                                |
             |  ---------------------------------------------> |                                                |
             |     - Requested SPN: cifs/FS01.corp.local       |                                                |
             |     - TGT (Encrypted with K_krbtgt)             |                                                |
             |     - Authenticator: Encrypted w/ K_session_AS  |                                                |
             |                                                 |                                                |
             |                                  [KDC unseals TGT with K_krbtgt]                                 |
             |                                  [KDC extracts K_session_AS, validates Authenticator]            |
             |                                  [KDC generates Service Session Key: K_session_FS]               |
             |                                  [KDC mints Service Ticket, encrypts with K_FS01]                |
             |                                                 |                                                |
             |  4. TGS-REP (UDP/TCP 88)                        |                                                |
             |  <--------------------------------------------- |                                                |
             |     - Encrypted with K_session_AS:              |                                                |
             |         * Service Session Key: K_session_FS     |                                                |
             |     - Encrypted with K_FS01:                    |                                                |
             |         * Service Ticket (K_session_FS + PAC)   |                                                |
             |                                                 |                                                |
             | [ahmed unseals K_session_FS]                    |                                                |
             | [Stores Service Ticket & K_session_FS in LSASS] |                                                |
             |                                                 |                                                |
             | ====== PHASE 3: AP EXCHANGE (Application Access & Mutual Auth) ================================ |
             |                                                 |                                                |
             |  5. AP-REQ (TCP 445 SMB Tree Connect)           |                                                |
             |  ----------------------------------------------------------------------------------------------> |
             |     - Service Ticket (Encrypted with K_FS01)    |                                                |
             |     - Authenticator: Encrypted w/ K_session_FS  |                                                |
             |                                                 |                                                |
             |                                                 |        [FS01 unseals ticket with K_FS01]       |
             |                                                 |        [FS01 extracts K_session_FS]            |
             |                                                 |        [FS01 validates Authenticator timestamp]|
             |                                                 |        [FS01 parses PAC, creates Access Token] |
             |                                                 |                                                |
             |  6. AP-REP (Mutual Authentication - Optional)   |                                                |
             |  <---------------------------------------------------------------------------------------------- |
             |     - Authenticator timestamp echoed back       |                                                |
             |       encrypted with K_session_FS               |                                                |
             |                                                 |                                                |
             | [ahmed verifies FS01 possessed K_FS01]          |                                                |
             | [SMB session encrypted/signed with K_session_FS]                                                 |
             | [ahmed reads \\FS01.corp.local\engineering\specifications.xlsx]                                  |
             +--------------------------------------------------------------------------------------------------+
```

---

### 2.3 Phase 1: The Authentication Service (AS) Exchange
When Ahmed boots `WKSTN01` and enters his domain credentials, the Local Security Authority Subsystem Service (LSASS) on `WKSTN01` initiates the **Authentication Service (AS) Exchange** to log Ahmed into the domain.

#### Step 1: AS-REQ (Client $\rightarrow$ KDC)
Ahmed's machine constructs a Kerberos Request (`AS-REQ`, Kerberos message type 10) and sends it over UDP (or TCP) port 88 to `DC01.corp.local`.

- **Plaintext Body (`KDC-REQ-BODY`):**
  - `cname` (Client Name): `ahmed`
  - `realm`: `CORP.LOCAL`
  - `sname` (Service Name): `krbtgt/CORP.LOCAL` (Ahmed is explicitly asking for a ticket to the Ticket Granting Service)
  - `till`: Requested ticket end time (typically current time + 10 hours)
  - `nonce`: A 32-bit cryptographically random integer generated by `WKSTN01` to detect replay attacks.
  - `etype`: The list of encryption types `WKSTN01` supports, ordered by preference (e.g., `AES256-CTS-HMAC-SHA1-96` [etype 18], `AES128-CTS-HMAC-SHA1-96` [etype 17], `RC4-HMAC` [etype 23]).
- **Pre-Authentication Data (`padata`):**
  - Type: `PA-ENC-TIMESTAMP` (padata type 2).
  - Data: The current system timestamp (accurate to microseconds), encrypted using Ahmed’s long-term symmetric key ($K_{ahmed}$).
  - *How $K_{ahmed}$ is derived:* When Ahmed typed his password, `WKSTN01` converted the password into an AES-256 key via PBKDF2 using the domain salt `CORP.LOCALahmed` (or directly into an NTLM hash for legacy RC4).

#### Step 2: KDC Processing & AS-REP (KDC $\rightarrow$ Client)
Upon receiving the packet, the KDC performs the following steps:
1. **Principal Lookup:** Queries the Active Directory database (`ntds.dit`) for `ahmed@CORP.LOCAL`. It retrieves Ahmed's stored password hash and encryption keys.
2. **Pre-Authentication Verification:** The KDC takes Ahmed's key ($K_{ahmed}$) and decrypts the `PA-ENC-TIMESTAMP`.
   - The KDC compares the decrypted timestamp against its own current domain controller clock.
   - If the clock skew between client and KDC is greater than 5 minutes (the default Kerberos tolerance window), the request is rejected with `KRB_AP_ERR_SKEW`.
   - If the timestamp decrypts cleanly and falls within the acceptable skew, the KDC is cryptographically certain that the caller knows Ahmed's password.
3. **Session Key Generation:** The KDC generates a cryptographically random, ephemeral 256-bit symmetric key: the **Logon Session Key** ($K_{session\_AS}$).
4. **PAC Assembly:** The KDC looks up Ahmed's user SID (`S-1-5-21-...-1105`), his primary group RID (`513` - Domain Users), and every global and universal security group Ahmed belongs to. It builds the Privilege Attribute Certificate (PAC) structure and signs it.
5. **Envelope Sealing:** The KDC crafts two encrypted envelopes:
   - **The Ticket Granting Ticket (TGT):** Encrypted using the domain's root `krbtgt` account key ($K_{krbtgt}$). Inside this ticket lies Ahmed's identity, validity timestamps, the PAC, and a copy of $K_{session\_AS}$.
   - **The Encrypted Response Part (`enc-part`):** Encrypted using Ahmed's key ($K_{ahmed}$). Inside this package lies the exact same copy of $K_{session\_AS}$, the ticket expiration timestamps, and the client nonce matching the AS-REQ.
6. **Transmission:** The KDC packages both envelopes into an `AS-REP` packet (message type 11) and transmits it back to `WKSTN01`.

#### Client Ingestion:
`WKSTN01` receives the `AS-REP`. Because it possesses $K_{ahmed}$, it unseals the `enc-part`. It verifies that the returned nonce matches what it sent, extracts the **Logon Session Key** ($K_{session\_AS}$), and caches both the unsealed $K_{session\_AS}$ and the opaque, still-encrypted TGT safely inside the memory of `lsass.exe`. Ahmed is now fully logged in.

---

### 2.4 Phase 2: The Ticket Granting Service (TGS) Exchange
Now, Ahmed clicks on `\\FS01.corp.local\engineering`. The Windows operating system detects that SMB needs to connect to the file share. The workstation checks its local Kerberos ticket cache in LSASS:
- *Do we have a Service Ticket for `cifs/FS01.corp.local`?* **No.**
- *Do we have a valid TGT?* **Yes.**

The workstation now initiates the **Ticket Granting Service (TGS) Exchange**.

#### Step 3: TGS-REQ (Client $\rightarrow$ KDC)
`WKSTN01` constructs a `TGS-REQ` packet (message type 12) and dispatches it to `DC01` on port 88.

- **Request Body (`KDC-REQ-BODY`):**
  - `sname`: `cifs/FS01.corp.local` (The Service Principal Name representing CIFS/SMB on `FS01`).
  - `realm`: `CORP.LOCAL`
  - `nonce`: A new random 32-bit integer.
- **Pre-Authentication (`padata`):**
  - Type: `PA-TGS-REQ` (padata type 1).
  - Payload 1: The **TGT** received during Phase 1 (opaque ciphertext encrypted with $K_{krbtgt}$).
  - Payload 2: An **Authenticator** generated by `WKSTN01`. The Authenticator contains Ahmed's client name and the current timestamp, encrypted using the **Logon Session Key** ($K_{session\_AS}$).

#### Step 4: KDC Processing & TGS-REP (KDC $\rightarrow$ Client)
The KDC receives the `TGS-REQ` and executes the following verification:
1. **TGT Decryption:** The KDC decrypts the TGT using its own long-term $K_{krbtgt}$ key. If decryption succeeds, the KDC knows this TGT was minted by an authorized Domain Controller and has not been modified.
2. **Authenticator Validation:** From inside the decrypted TGT, the KDC extracts the Logon Session Key ($K_{session\_AS}$). It uses $K_{session\_AS}$ to decrypt Ahmed's Authenticator.
   - It checks that the timestamp inside the Authenticator matches the current time within the 5-minute skew window.
   - It verifies that the client name inside the Authenticator matches the client name inside the TGT.
   - This proves that whoever sent this packet is the legitimate holder of the TGT and is not replaying an intercepted ticket.
3. **SPN Resolution:** The KDC looks up the requested SPN `cifs/FS01.corp.local` in Active Directory. It identifies that this SPN belongs to the computer account `FS01$` and retrieves `FS01$`'s long-term computer account key ($K_{FS01}$).
4. **Service Session Key Minting:** The KDC generates a brand-new ephemeral symmetric key: the **Service Session Key** ($K_{session\_FS}$).
5. **PAC Copying & Resigning:** The KDC extracts Ahmed's PAC from the TGT, verifies the KDC signature, checks if any resource-group filtering is required, and re-signs the PAC's Server Signature using $K_{FS01}$.
6. **Ticket Sealing:** The KDC crafts two new cryptographic envelopes:
   - **The Service Ticket (TGS Ticket):** Encrypted using the target service's long-term key ($K_{FS01}$). It contains Ahmed's identity, the PAC, validity timestamps, and a copy of the Service Session Key ($K_{session\_FS}$).
   - **The Response Wrapper (`enc-part`):** Encrypted using the client's Logon Session Key ($K_{session\_AS}$). It contains the other copy of the Service Session Key ($K_{session\_FS}$) and the request nonce.
7. **Transmission:** The KDC packages these into a `TGS-REP` packet (message type 13) and sends it to `WKSTN01`.

#### Client Ingestion:
`WKSTN01` unseals the `enc-part` using its cached $K_{session\_AS}$. It extracts the **Service Session Key** ($K_{session\_FS}$), associates it with the SPN `cifs/FS01.corp.local`, and stores both the Service Ticket (still encrypted with $K_{FS01}$) and $K_{session\_FS}$ in LSASS.

---

### 2.5 Phase 3: The Application (AP) Exchange
`WKSTN01` now possesses everything required to talk to `FS01.corp.local`. Notice that up to this exact moment, **`FS01` has not received a single packet and has no idea Ahmed exists.**

#### Step 5: AP-REQ (Client $\rightarrow$ Application Server)
`WKSTN01` opens a TCP connection to `FS01.corp.local` on port 445 (SMB) and initiates the SMB Tree Connect negotiation by attaching a Kerberos `AP-REQ` packet (message type 14).

- **Payload of AP-REQ:**
  1. **The Service Ticket:** The opaque blob received from the TGS-REP, encrypted with $K_{FS01}$.
  2. **The Authenticator:** A brand-new data structure created by `WKSTN01` containing:
     - Client Name: `ahmed`
     - Timestamp: Current workstation time.
     - Subkey (Optional): An optional client-proposed session subkey.
     - Sequence Number: For packet sequencing.
     - *Encrypted with:* The **Service Session Key** ($K_{session\_FS}$).
  3. **AP Options:** Flags specifying whether the client requests mutual authentication (`mutual-required`).

#### Step 6: Application Server Processing & AP-REP (Server $\rightarrow$ Client)
`FS01` receives the `AP-REQ` over port 445 and processes it completely offline from the KDC:
1. **Ticket Unsealing:** `FS01` uses its own long-term machine account key ($K_{FS01}$) to decrypt the incoming Service Ticket.
2. **Session Key Extraction:** From the decrypted ticket, `FS01` extracts the Service Session Key ($K_{session\_FS}$) and Ahmed’s identity.
3. **Authenticator Verification:** `FS01` uses $K_{session\_FS}$ to decrypt the incoming Authenticator.
   - It verifies that the timestamp is within 5 minutes.
   - It checks its local replay cache (a memory buffer of recently received authenticators) to ensure this exact authenticator hasn't been replayed within the skew window.
   - It confirms that the name inside the Authenticator matches the name inside the decrypted ticket.
4. **PAC Ingestion & Access Token Creation:** `FS01` extracts the PAC from the ticket, verifies the Server Signature with $K_{FS01}$, and passes the SIDs directly into the Windows Security Subsystem (LSA/Kernel). The Windows kernel constructs a primary security access token for Ahmed, listing his user SID and all his group SIDs.
5. **Mutual Authentication (`AP-REP`):** If `mutual-required` was requested, `FS01` constructs an `AP-REP` packet (message type 15). It takes the timestamp from Ahmed's Authenticator, encrypts it with $K_{session\_FS}$, and sends it back to `WKSTN01`.
   - When `WKSTN01` decrypts this timestamp with its copy of $K_{session\_FS}$ and sees its own timestamp mirrored back, it has mathematical proof that `FS01` successfully decrypted the Service Ticket. Ahmed is now guaranteed he is talking to the genuine `FS01` and not an impersonator.

#### File Access Granted:
Both sides now use $K_{session\_FS}$ (or a derived subkey) to digitally sign and optionally encrypt SMB traffic. The Windows I/O manager evaluates the Discretionary Access Control List (DACL) on `\\FS01\engineering\specifications.xlsx` against Ahmed’s newly created access token. The token contains the SID for `Engineering-Department-Global`, which has `Read/Execute` permissions. The file handle opens, and Ahmed begins reading the spreadsheet.

---

## 3. Deep-Dive: Anatomy of Tickets, Keys & The PAC

### 3.1 Diagram 2: Anatomical Breakdown of a Ticket & Session Key

```text
  +----------------------------------------------------------------------------------------------------+
  |                     ANATOMICAL BREAKDOWN OF A KERBEROS TICKET & SESSION KEY                        |
  +----------------------------------------------------------------------------------------------------+

     OUTER PROTOCOL WRAPPER (Plaintext Header - Inspected by Routers, Proxies, and Local OS)
     +------------------------------------------------------------------------------------------------+
     |  Ticket Version Number (tkt-vno) : 5                                                           |
     |  Realm Name                      : CORP.LOCAL                                                  |
     |  Server Name (sname / SPN)       : krbtgt/CORP.LOCAL (for TGT) OR cifs/FS01 (for Service Ticket)|
     +------------------------------------------------------------------------------------------------+
                                                     |
                                                     | Points to encrypted payload below
                                                     v
     ENCRYPTED TICKET PART (EncTicketPart - Sealed with Target's Long-Term Key)
     [ Encrypted with K_krbtgt (for TGT)  OR  Encrypted with K_service (for Service Ticket) ]
     +------------------------------------------------------------------------------------------------+
     |                                                                                                |
     |  [1] EPHEMERAL SESSION KEY                                                                     |
     |      - For TGT: Logon Session Key (K_session_AS)                                               |
     |      - For Service Ticket: Service Session Key (K_session_FS)                                  |
     |      (This key binds the Client securely to the Ticket Holder)                                 |
     |                                                                                                |
     |  [2] CLIENT IDENTITY & METADATA                                                                |
     |      - Client Name (cname)       : ahmed                                                       |
     |      - Client Realm (crealm)     : CORP.LOCAL                                                  |
     |      - Transited Realms Encoding : (Lists cross-realm trust transit paths)                     |
     |                                                                                                |
     |  [3] TEMPORAL VALIDITY WINDOW                                                                  |
     |      - authtime                  : Initial authentication timestamp                            |
     |      - starttime                 : Valid start time                                            |
     |      - endtime                   : Expiration time (typically +10 hours)                       |
     |      - renew-till                : Maximum renewable window (typically +7 days)                |
     |                                                                                                |
     |  [4] TICKET BEHAVIORAL FLAGS                                                                   |
     |      - forwardable (0x40000000)  - renewable (0x00800000)                                      |
     |      - proxiable   (0x10000000)  - initial   (0x00400000)                                      |
     |                                                                                                |
     |  [5] AUTHORIZATION DATA: THE PRIVILEGE ATTRIBUTE CERTIFICATE (PAC)                             |
     |      +------------------------------------------------------------------------------------+    |
     |      | PACTYPE Header (Buffer count, version)                                             |    |
     |      +------------------------------------------------------------------------------------+    |
     |      | KERB_VALIDATION_INFO                                                               |    |
     |      |  - User SID & Relative ID (RID)         : S-1-5-21-394...-1105 (ahmed)             |    |
     |      |  - Primary Group ID                     : 513 (Domain Users)                       |    |
     |      |  - Group Memberships (GroupCount + RIDs): [513, 1602 (Engineering), 1805 (Staff)]   |    |
     |      |  - Extra SIDs / SID History             : (Migrated legacy account SIDs)           |    |
     |      |  - UserAccountControl Flags             : 0x00000200 (NORMAL_ACCOUNT)              |    |
     |      +------------------------------------------------------------------------------------+    |
     |      | PAC_CLIENT_INFO                                                                    |    |
     |      |  - Client ID (Timestamp of ticket generation + UTF-16LE Client Name)               |    |
     |      +------------------------------------------------------------------------------------+    |
     |      | PAC_SERVER_SIGNATURE                                                               |    |
     |      |  - Cryptographic HMAC signed with Target Server Key (K_FS01)                       |    |
     |      +------------------------------------------------------------------------------------+    |
     |      | PAC_PRIVSVR_CHECKSUM (KDC Signature)                                               |    |
     |      |  - Cryptographic HMAC signed with Domain Controller Key (K_krbtgt)                 |    |
     |      +------------------------------------------------------------------------------------+    |
     |      | PAC_UPN_DNS_INFO                                                                   |    |
     |      |  - User Principal Name & Fully Qualified Domain Name                               |    |
     |      +------------------------------------------------------------------------------------+    |
     +------------------------------------------------------------------------------------------------+

     PARALLEL RESPONSE ENVELOPE (enc-part inside AS-REP / TGS-REP)
     [ Encrypted with Client's Key (K_ahmed) in AS-REP  OR  Logon Session Key (K_session_AS) in TGS-REP ]
     +------------------------------------------------------------------------------------------------+
     |  - Exact same Ephemeral Session Key (K_session_AS or K_session_FS)                             |
     |  - Request Nonce (Validates reply against replay)                                              |
     |  - Ticket Expiration & Renewal Timestamps                                                      |
     |  ==> Client decrypts THIS envelope to learn the Session Key that matches the Ticket!           |
     +------------------------------------------------------------------------------------------------+
```

---

### 3.2 The Envelope Model: Outer Wrapper vs Inner Ciphertext
A Kerberos ticket functions exactly like an armored, tamper-evident security pouch:
- **The Outer Wrapper (Plaintext):** Contains metadata that any network hop, firewall, or endpoint operating system can inspect without breaking encryption. This includes the Kerberos protocol version (`5`), the domain realm (`CORP.LOCAL`), and the target service principal name (`krbtgt/CORP.LOCAL` or `cifs/FS01.corp.local`).
- **The Encrypted Ticket Part (`EncTicketPart`):** The actual payload inside the pouch is encrypted with a symmetric key known *only* to the issuing KDC and the recipient service.
  - In a **TGT**, the `EncTicketPart` is sealed with $K_{krbtgt}$.
  - In a **Service Ticket**, the `EncTicketPart` is sealed with the target service account's secret key ($K_{service}$).
- **The Client Ingestion Mechanism:** When the KDC returns an `AS-REP` or `TGS-REP`, the client receives the encrypted ticket blob, which it cannot open. Alongside that blob, the KDC includes a parallel encrypted data block (`enc-part`) encrypted with a key the client *does* possess. By decrypting this parallel block, the client extracts the **Session Key**. Now, both the client and the eventual destination server possess the identical Session Key, while no eavesdropper on the wire has seen it.

---

### 3.3 The Heart of Active Directory: Privilege Attribute Certificate (PAC)
To truly understand Active Directory internals, one must understand why MIT Kerberos and Microsoft Kerberos fundamentally diverge.

#### Why MIT Kerberos Did Not Have a PAC:
When MIT designed Kerberos v5 for UNIX workstations in Project Athena, Kerberos had exactly one operational responsibility: **Authentication** ("Are you truly Ahmed?").
Once an authenticated UNIX workstation verified Ahmed's Kerberos identity, the workstation consulted its own local configuration files (`/etc/passwd`, `/etc/group`, or local LDAP/NIS) to determine what groups Ahmed belonged to and what files he could read. Authorization was completely decoupled from Kerberos tickets.

#### Why Microsoft Had to Invent the PAC:
In Active Directory, identity is not defined by a simple username string. Windows access control is based entirely on **Security Identifiers (SIDs)** and centralized group tokens. When a user accesses an object in Windows, the operating system kernel compares the SIDs embedded in the caller's access token against the Discretionary Access Control List (DACL) attached to the securable object.

If Microsoft had implemented RFC 4120 Kerberos without modification, an architectural nightmare would have ensued:
Every time Ahmed tried to open a file on `FS01`, execute a query on `SQL01`, or browse an internal website on `WEB01`, that target server would have to pause the thread, open a network connection back to a Domain Controller over LDAP, and query:
> *"Hey DC, user ahmed just presented a valid Kerberos ticket. What groups is ahmed a member of? What is his primary group RID? Does he have any SID History from legacy domain migrations?"*

In an enterprise with 50,000 employees, hundreds of servers, and millions of daily file, database, and web requests, the Domain Controllers would instantly collapse under catastrophic **LDAP connection storms**. The network would suffer massive latency overhead on every single user action.

#### The Microsoft Solution:
Microsoft invented the **Privilege Attribute Certificate (PAC)**, formalized under specification **[MS-PAC]**.
Instead of forcing every service server to query the DC on every connection, the KDC queries the Active Directory database *once* during initial ticket issuance. The KDC compiles Ahmed’s entire security profile—his user SID, his primary group RID, all domain global and universal security group SIDs, and any historical SIDs—and packages them directly inside the encrypted authorization-data field of the Kerberos ticket.

When `FS01` receives Ahmed's Service Ticket, `FS01` simply decrypts the ticket, reads the pre-compiled PAC, and directly builds a complete Windows Security Access Token in kernel memory. **Zero LDAP calls to the Domain Controller are needed.**

---

### 3.4 Cryptographic Signatures & The Dual-Signature Trust Model
If the PAC travels inside a ticket and carries absolute authority regarding what security groups a user belongs to, what stops a malicious user or an attacker from tampering with the PAC to add the Domain Admins SID (`S-1-5-21-...-512`)?

To guarantee integrity, Microsoft implemented a strict **Dual-Signature Model** within the PAC structure:

1. **The Server Signature (`PAC_SERVER_SIGNATURE`):**
   - **Signed With:** The target service account's long-term key ($K_{service}$ for a Service Ticket; $K_{krbtgt}$ for a TGT).
   - **Purpose:** Cryptographically seals the PAC data buffers. When the target service (`FS01`) receives the ticket, it decrypts the ticket using $K_{FS01}$, locates the Server Signature, and verifies the cryptographic hash against the PAC contents using $K_{FS01}$. This guarantees to `FS01` that the PAC has not been tampered with since the ticket was generated.
2. **The KDC Signature (`PAC_PRIVSVR_CHECKSUM`):**
   - **Signed With:** The domain's root `krbtgt` key ($K_{krbtgt}$).
   - **Purpose:** Cryptographically signs the Server Signature itself using the Domain Controller's master key.
   - **Why this is architecturally vital:** Without the KDC Signature, a compromised service server (e.g., an untrusted web application running with its own service account) could decrypt a legitimate ticket sent by Ahmed, modify Ahmed's PAC to insert Enterprise Admins rights, re-sign the PAC using its *own* service key, and forward the forged ticket to another backend server. Because the KDC signature is sealed with $K_{krbtgt}$—a key known *only* to Domain Controllers—a service cannot tamper with a ticket or elevate its own privileges without invalidating the KDC signature.
3. **Ticket Checksum & PAC Attributes (Modern Hardening):**
   - Under security updates addressing PAC elevation vulnerabilities (e.g., CVE-2021-42287 and CVE-2022-37967), modern KDCs append additional cryptographic checksums:
     - `PAC_ATTRIBUTES_INFO`: Contains bit flags specifying how the PAC was requested.
     - `PAC_REQUESTOR`: Contains the SID of the account that requested the ticket.
     - `Ticket Checksum`: A cryptographic hash of the entire outer ticket payload signed with $K_{krbtgt}$, binding the PAC immutably to that specific ticket instance and preventing PAC replay across different tickets.

---

### 3.5 Structural Breakdown: PAC Buffers Demystified
The PAC is structured as an array of variable-length buffers preceded by a header (`PACTYPE`). Below is the exact architectural breakdown of the validation buffers:

```text
PACTYPE Header:
├── cBuffers  : Total count of validation buffers inside the PAC (typically 5 to 7)
├── Version   : PAC structure version (0)
└── Buffers[] : Array of directory pointers (BufferType, BufferSize, Offset)

Buffer 1: KERB_VALIDATION_INFO (Buffer Type 0x00000001)
├── LogonTime / LogoffTime / KickOffTime : Account lifecycle timestamps
├── PasswordLastSet / PasswordMustChange : Password management timestamps
├── EffectiveName / FullName             : Account display strings
├── LogonScript / ProfilePath / HomeDir  : User profile environmental paths
├── UserId (User RID)                    : The account's relative identifier (e.g., 1105)
├── PrimaryGroupId                       : Primary group RID (e.g., 513)
├── GroupCount & GroupIds[]              : Array of group RIDs and attributes in the local domain
├── UserFlags / UserAccountControl       : Account state flags (e.g., NORMAL_ACCOUNT)
├── UserSessionKey                       : 128-bit session key for SMB signing fallback
├── LogonServer                          : Name of the DC that authenticated the user
├── LogonDomainName & LogonDomainId      : Domain NetBIOS name and Domain Security Identifier (Domain SID)
└── ExtraSids[] (SID History)            : Array of full SIDs representing cross-domain migration history

Buffer 2: PAC_CLIENT_INFO (Buffer Type 0x0000000A)
├── ClientId  : Windows FILETIME timestamp indicating when the ticket was generated by the KDC
└── Name      : UTF-16LE encoded client username string (used to verify ticket ownership)

Buffer 3: PAC_SERVER_SIGNATURE (Buffer Type 0x00000006)
├── SignatureType : Cryptographic algorithm (HMAC-SHA1-96-AES256 [etype 18] or HMAC-MD5 [etype 23])
└── Signature     : Cryptographic digest computed over all PAC data buffers using the Target Service Key

Buffer 4: PAC_PRIVSVR_CHECKSUM (KDC Signature, Buffer Type 0x00000007)
├── SignatureType : Cryptographic algorithm
└── Signature     : Cryptographic digest computed over the Server Signature using the Domain KDC Key (K_krbtgt)

Buffer 5: PAC_UPN_DNS_INFO (Buffer Type 0x0000000C)
├── UpnLength & UpnOffset               : User Principal Name (e.g., ahmed@corp.local)
├── DnsDomainNameLength & Offset        : FQDN of the domain (e.g., corp.local)
└── SamAccountNameLength & Offset       : sAMAccountName string

Buffer 6 & 7: Modern Hardening Buffers (CVE-2021-42287 / CVE-2022-37967)
├── PAC_ATTRIBUTES_INFO (0x00000011)    : Flags indicating whether PAC signatures were enforced
└── PAC_REQUESTOR (0x00000012)          : SID of the ticket requester to prevent identity spoofing
```

Because this entire structure is cryptographically signed and encrypted inside the ticket, `FS01` simply executes `KerbValidatePacSignature` locally. If valid, `FS01` passes `KERB_VALIDATION_INFO` directly to the Windows Security Reference Monitor (SRM) to create Ahmed's local Windows token without contacting Active Directory.

---

## 4. Cryptographic Engines, Key Derivation & Ticket Storage

### 4.1 Supported Encryption Types
Kerberos negotiates cryptographic algorithms via integer identifiers called **Encryption Types (etypes)** defined in RFC standards and Microsoft specifications:

| Etype ID | Standard Name | Cryptographic Primitive | Key Size | Modern Security Assessment |
|:---:|:---|:---|:---:|:---|
| **18** | `AES256-CTS-HMAC-SHA1-96` | AES-256 Cipher Text Stealing + HMAC-SHA1 | 256 bits | **Gold Standard.** Strongly recommended for all domain accounts and services. |
| **17** | `AES128-CTS-HMAC-SHA1-96` | AES-128 Cipher Text Stealing + HMAC-SHA1 | 128 bits | **Secure.** Standard AES performance tier. |
| **23** | `RC4-HMAC` (RFC 4757) | Rivest Cipher 4 + MD4/MD5 HMAC | 128 bits | **Architecturally Fragile.** Legacy suite. Vulnerable to fast offline brute-force cracking. |
| **16** | `DES3-CBC-SHA1` | Triple DES + SHA1 | 168 bits | **Deprecated.** Disabled by default in modern Windows Server releases. |
| **1 / 3** | `DES-CBC-CRC / MD5` | Single DES (56-bit) | 56 bits | **Broken.** Deprecated and blocked by default since Windows Server 2008 R2. |

---

### 4.2 Key Derivation Mechanics
Kerberos never uses a user’s plaintext password directly as an encryption cipher key. It converts the human-readable password into a raw cryptographic key through deterministic derivation algorithms:

#### 1. AES Keys Derivation (RFC 3962):
For modern AES-128 and AES-256 encryption, Active Directory uses **PBKDF2 (Password-Based Key Derivation Function 2)** with HMAC-SHA1:
$$\text{Salt} = \text{UPPERCASE(Realm)} + \text{CaseSensitive}(sAMAccountName)$$
$$\text{Example Salt} = \text{"CORP.LOCALahmed"}$$
$$K_{AES256} = \text{PBKDF2}(\text{HMAC-SHA1}, \text{Password}, \text{Salt}, \text{Iterations}=4096, \text{KeyLength}=32 \text{ bytes})$$
Because the salt includes the full realm and username, two users in different domains with the exact same password produce completely distinct AES keys. Furthermore, the 4,096 iterations of PBKDF2 impose substantial computational resistance against offline dictionary attacks.

#### 2. The Legacy RC4 Trap (RFC 4757):
For `RC4-HMAC` (etype 23), the key derivation algorithm is dangerously simple:
$$K_{RC4} = \text{MD4}(\text{UTF-16LE}(\text{Password})) \equiv \text{NTLM Hash}$$
In the RC4 Kerberos cipher suite, **the Kerberos symmetric key is mathematically identical to the user's NTLM hash**. There is no salt. There are zero derivation iterations.
This cryptographic equivalence is one of the most critical architectural friction points in Active Directory:
- If an adversary captures an account's NTLM hash, they automatically hold that account's Kerberos RC4 key without needing the plaintext password.
- If an adversary captures an RC4 Kerberos response, cracking that Kerberos ticket is mathematically identical to cracking a raw NTLM hash offline.

---

### 4.3 Ticket Storage & In-Memory Formats
Once Kerberos tickets are minted, endpoints must cache them in memory to avoid requesting new tickets on every single network operation.

#### 1. Windows Operating System Storage:
- **LSASS Process Memory:** On Windows, all active Kerberos tickets are managed by the Kerberos Security Support Provider (`kerberos.dll`) running inside the **Local Security Authority Subsystem Service (`lsass.exe`)**.
- **Logon Sessions:** LSASS segregates tickets by Windows Logon Session (identified by a 64-bit Locally Unique Identifier, or LUID).
  - Ahmed’s interactive desktop runs in a specific Logon Session LUID (e.g., `0x3e7` for SYSTEM, `0x14a89b` for Ahmed).
  - Only processes executing within Ahmed’s logon session (or processes possessing elevated `SeDebugPrivilege` running as SYSTEM) can access Ahmed's cached TGT and Service Tickets.
- **The `.kirbi` File Format:** When tools extract tickets from Windows memory, they serialize the ASN.1 `KRB-CRED` structure (defined in RFC 4120 Section 5.8) into raw binary or Base64-encoded `.kirbi` files.

#### 2. Linux / macOS Storage:
- **Credential Caches (ccache):** POSIX environments running MIT Kerberos, Heimdal, or SSSD store tickets in Credential Cache files.
  - The active cache is pointed to by the environment variable `KRB5CCNAME`.
  - Typical location: `/tmp/krb5cc_<UID>` or in the Linux kernel keyring (`KEYRING:persistent:<UID>`).
- **Keytab Files (`.keytab`):** Unlike Windows computer accounts which rotate their own machine passwords automatically in the registry, Linux servers hosting Kerberos services store their long-term symmetric keys in **Keytab** files (typically `/etc/krb5.keytab`). A keytab is essentially a file containing principal names paired with their derived DES, RC4, or AES cryptographic keys.

---

## 5. Delegation Architecture & Cross-Tier Identity Transfer

### 5.1 The Architectural Need for Multi-Tier Delegation
In modern enterprise applications, services rarely exist in isolation. Consider a classic three-tier enterprise web application:
1. **Tier 1 (User Desktop):** Ahmed browses to an internal HR portal at `https://hr.corp.local`.
2. **Tier 2 (Front-End Web Server):** `WEB01.corp.local` hosts the web application.
3. **Tier 3 (Back-End Database):** `SQL01.corp.local` stores the employee salary records.

If Ahmed queries his personal payroll record, `WEB01` must query `SQL01`. But how should `WEB01` authenticate to `SQL01`?
- *Option A:* `WEB01` connects to `SQL01` using a static generic service account (`svc_web`).
  - *Failure:* `SQL01` has no idea which human user initiated the query. The database cannot enforce database-level row permissions or maintain an audit log of who viewed what salary record.
- *Option B:* Ahmed allows `WEB01` to impersonate him against `SQL01`.
  - *The Architectural Challenge:* Ahmed only gave `WEB01` a Service Ticket for `http/hr.corp.local`. `WEB01` cannot use that ticket to authenticate to `mssql/SQL01.corp.local` because that ticket is encrypted with `WEB01`'s key, not `SQL01`'s key!

To solve this, Microsoft introduced **Kerberos Delegation**—mechanisms that allow a service to impersonate an authenticated user when contacting downstream backend services.

---

### 5.2 Diagram 3: Delegation Architectures Compared

```text
  +----------------------------------------------------------------------------------------------------+
  |                               KERBEROS DELEGATION ARCHITECTURES                                    |
  +----------------------------------------------------------------------------------------------------+

  1. UNCONSTRAINED DELEGATION (Full TGT Handover)
  ======================================================================================================
  Configuration : Target host has the TRUSTED_FOR_DELEGATION flag set in UserAccountControl.

     CLIENT (ahmed)               FRONT-END SERVER (WEB01)             BACK-END SERVICE (SQL01)
          |                                  |                                     |
          |  AP-REQ [Service Ticket +        |                                     |
          |          COPY OF ahmed's TGT]    |                                     |
          | -------------------------------> |                                     |
          |                                  | [WEB01 extracts ahmed's TGT!]       |
          |                                  | [Caches TGT in LSASS memory]        |
          |                                  |                                     |
          |                                  |  TGS-REQ using ahmed's TGT          |
          |                                  | ----------------------------------> |
          |                                  |  (WEB01 can impersonate ahmed to   |
          |                                  |   ANY service across the forest!)   |

  ------------------------------------------------------------------------------------------------------
  2. CLASSIC CONSTRAINED DELEGATION (Front-End Whitelist & S4U Extensions)
  ======================================================================================================
  Configuration : Configured on WEB01:
                  msDS-AllowedToDelegateTo = [ mssql/sql01.corp.local ]
                  TRUSTED_TO_AUTH_FOR_DELEGATION flag set for Protocol Transition.

     CLIENT (ahmed)               FRONT-END SERVER (WEB01)             DOMAIN CONTROLLER (KDC)
          |                                  |                                     |
          |  Authenticates via ANY method    |                                     |
          |  (Kerberos, NTLM, Form, etc.)    |                                     |
          | -------------------------------> |                                     |
          |                                  | 1. S4U2Self (TGS-REQ)               |
          |                                  |    "Give me a ticket to MYSELF as   |
          |                                  |     ahmed"                          |
          |                                  | ----------------------------------> |
          |                                  | <---------------------------------- |
          |                                  |    Returns Ticket for ahmed -> WEB01|
          |                                  |                                     |
          |                                  | 2. S4U2Proxy (TGS-REQ)              |
          |                                  |    "Exchange S4U2Self ticket for    |
          |                                  |     ticket to mssql/sql01"          |
          |                                  | ----------------------------------> |
          |                                  | <---------------------------------- |
          |                                  |    KDC verifies whitelist, returns  |
          |                                  |    Ticket for ahmed -> SQL01        |
          |                                  |                                     |
          |                                  | Connects to SQL01 as ahmed =======> |

  ------------------------------------------------------------------------------------------------------
  3. RESOURCE-BASED CONSTRAINED DELEGATION (RBCD - Target-Driven Access Control)
  ======================================================================================================
  Configuration : Configured on the TARGET (SQL01), NOT the front-end!
                  SQL01.msDS-AllowedToActOnBehalfOfOtherIdentity = [ SID of WEB01 ]

     CLIENT                       FRONT-END (WEB01)                    DOMAIN CONTROLLER (KDC)
          |                              |                                     |
          |                              | 1. S4U2Self (TGS-REQ)               |
          |                              |    Gets ticket for ahmed to WEB01   |
          |                              | ----------------------------------> |
          |                              | <---------------------------------- |
          |                              |                                     |
          |                              | 2. S4U2Proxy (TGS-REQ)              |
          |                              |    Requests ticket to SQL01         |
          |                              | ----------------------------------> |
          |                              |                                     |
          |                              |    [KDC checks TARGET SQL01's       |
          |                              |     msDS-AllowedToActOnBehalf...]   |
          |                              |    [KDC sees WEB01 is permitted!]   |
          |                              | <---------------------------------- |
          |                              |    Returns Ticket for ahmed -> SQL01|
          |                              |                                     |
          |                              | Connects to SQL01 as ahmed =======> |
  +----------------------------------------------------------------------------------------------------+
```

---

### 5.3 Unconstrained Delegation: The Complete TGT Handover
Introduced in Windows 2000, **Unconstrained Delegation** was the original delegation model.
- **The Configuration:** An Active Directory administrator marks a computer or service account with the `TRUSTED_FOR_DELEGATION` bitmask in its `userAccountControl` attribute.
- **The Mechanism:** When Ahmed connects to `WEB01` over Kerberos, Ahmed’s workstation inspects `WEB01`'s Active Directory object. Seeing that `WEB01` has Unconstrained Delegation enabled, `WKSTN01` automatically extracts Ahmed’s TGT from LSASS, marks it as forwardable, and embeds a **full copy of Ahmed’s TGT** directly inside the Authenticator of the `AP-REQ` packet!
- **The Execution:** When `WEB01` decrypts the `AP-REQ`, it extracts Ahmed’s full TGT and injects it directly into `WEB01`'s own local LSASS ticket cache.
- **The Architectural Hazard:** `WEB01` now possesses Ahmed's TGT. Because the TGT is unconstrained, `WEB01` can present that TGT to the KDC to request Service Tickets for **any service in the entire Active Directory forest** as Ahmed. If an adversary compromises `WEB01`, any user who subsequently connects to `WEB01` (including a Domain Administrator) has their full TGT dumped from LSASS, resulting in complete forest compromise.

---

### 5.4 Constrained Delegation: S4U2Self & S4U2Proxy
To remediate the catastrophic blast radius of Unconstrained Delegation, Microsoft introduced **Constrained Delegation** in Windows Server 2003, backed by two proprietary Kerberos protocol extensions: **Service for User to Self (S4U2Self)** and **Service for User to Proxy (S4U2Proxy)** (specified in **[MS-SFU]**).

#### Core Concepts:
- **Whitelist Enforcement:** Delegation is locked down to a strictly defined list of SPNs populated in the front-end account’s `msDS-AllowedToDelegateTo` attribute (e.g., `mssql/SQL01.corp.local`). The front-end cannot impersonate the user to arbitrary services.
- **No Client TGT Delivery:** The client does not transmit their TGT to the front-end server.
- **Protocol Transition (S4U2Self):** What if Ahmed authenticated to `WEB01` via an HTTP basic form, a client certificate, or NTLM instead of Kerberos? The front-end server doesn't even have a Kerberos ticket from Ahmed!
  - Under S4U2Self, if `WEB01` has the `TRUSTED_TO_AUTH_FOR_DELEGATION` flag set, `WEB01` can send a `TGS-REQ` to the KDC requesting a Service Ticket **to itself** representing Ahmed, without requiring Ahmed to provide a password.
- **Impersonating Downstream (S4U2Proxy):**
  - Once `WEB01` has a Service Ticket for Ahmed (either from a real Kerberos AP-REQ or generated via S4U2Self), `WEB01` sends a `TGS-REQ` containing that ticket to the KDC, asking for a ticket to `mssql/SQL01.corp.local`.
  - The KDC verifies that `mssql/SQL01.corp.local` is listed in `WEB01`’s `msDS-AllowedToDelegateTo` attribute.
  - If verified, the KDC issues a Service Ticket for Ahmed to access `SQL01`.

---

### 5.5 Resource-Based Constrained Delegation (RBCD)
While Constrained Delegation solved the security flaws of Unconstrained Delegation, it introduced a significant administrative problem:
- **Centralized Administrative Friction:** To configure Classic Constrained Delegation, the front-end server's `msDS-AllowedToDelegateTo` attribute must be edited. Modifying this attribute requires elevated domain privileges (Domain Admins or delegated administrators of the front-end account). The administrators of the target backend service (`SQL01`) have zero control over who is allowed to delegate access to their own database.

In Windows Server 2012, Microsoft introduced **Resource-Based Constrained Delegation (RBCD)**:
- **Inverting the Trust Relationship:** Instead of configuring delegation permissions on the *caller* (`WEB01`), permissions are configured on the *resource target* (`SQL01`).
- **The Security Descriptor:** The resource target object in Active Directory possesses an attribute named `msDS-AllowedToActOnBehalfOfOtherIdentity`. This attribute contains a binary security descriptor (an Access Control List) specifying which machine or service accounts are permitted to impersonate users to this resource.
- **The Flow:**
  1. `WEB01` uses S4U2Self to obtain a ticket for Ahmed to itself.
  2. `WEB01` uses S4U2Proxy to ask the KDC for a ticket to `SQL01` as Ahmed.
  3. The KDC inspects `SQL01`'s `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute.
  4. If `WEB01`'s SID is present in that security descriptor, the KDC issues the ticket.
- **Architectural Shift:** Now, local server administrators can control their own delegation boundaries. However, as explored in Section 6, this creates a major architectural attack surface if an adversary obtains write permissions over any computer object's attributes.

---

## 6. Architectural Friction Points & Vulnerability Foundations

Security vulnerabilities in Active Directory are rarely software coding "bugs" in the Kerberos binary. Instead, they are the mathematically predictable consequences of **architectural trade-offs** between usability, distributed performance, backward compatibility, and cryptographic design.

---

### 6.1 Offline Cryptanalysis of Service Envelopes (The Architectural Origin of Kerberoasting)
- **The Design Decision:**
  To maintain enterprise performance, the KDC issues Service Tickets encrypted using the long-term secret key of the target service account ($K_{service}$). The target service decrypts the ticket locally without needing to verify the ticket with the KDC over the network.
- **The Protocol Rule:**
  Any valid domain user (even the least-privileged user in the forest) has legitimate rights to query the KDC and request a Service Ticket for *any* registered Service Principal Name (SPN) in Active Directory.
- **The Friction Point:**
  If an enterprise administrator configures a service (such as MSSQL or IIS) to execute under a standard Active Directory User Account rather than a built-in computer account or a Group Managed Service Account (gMSA), that service's long-term key ($K_{service}$) is derived from a human-created password.
- **The Architectural Consequence:**
  An adversary authenticated as Ahmed can query the KDC for a Service Ticket addressed to `MSSQLSvc/sql01.corp.local`. The KDC dutifully returns a `TGS-REP` containing a ciphertext block encrypted with that service account’s password key. The adversary does not need to send a single packet to `SQL01`. They extract the ciphertext from the `TGS-REP` packet, carry it to an offline GPU cracking cluster, and guess billions of candidate passwords against the ciphertext. If the service account has a weak or medium-complexity password, the adversary cracks the secret offline completely undetected by endpoint defenses on `SQL01`.

---

### 6.2 Pre-Authentication Bypass & Arbitrary AS-REP Harvesting (The Mechanism Behind AS-REP Roasting)
- **The Design Decision:**
  Pre-Authentication exists specifically to prevent offline guessing attacks against user passwords. If a client had to receive an `AS-REP` before proving knowledge of its key, an attacker could request an `AS-REP` for any username in the domain and receive ciphertext encrypted with that user's password hash.
- **The Backward-Compatibility Exception:**
  Active Directory includes a User Account Control flag named `DONT_REQ_PREAUTH` (`0x00400000`). This flag was created decades ago for legacy applications and Unix Kerberos implementations that did not support pre-authentication timestamps.
- **The Friction Point:**
  When `DONT_REQ_PREAUTH` is enabled on any user account, the KDC waives the requirement for `PA-ENC-TIMESTAMP`.
- **The Architectural Consequence:**
  An unauthenticated or low-privileged attacker on the network sends an `AS-REQ` naming that target account. The KDC immediately generates a standard `AS-REP` response containing a session key and metadata encrypted with the target user's password key ($K_{user}$). The attacker captures this packet and cracks the user's password offline, without ever knowing the password or generating a failed logon event (Event 4771).

---

### 6.3 Stateless KDC Trust & Cryptographic Omnipotence (The Structural Flaw of Golden Tickets)
- **The Design Decision:**
  The Kerberos protocol is **stateless**. Domain Controllers do not maintain a live database of all active, issued tickets. When a client presents a TGT to the KDC during a `TGS-REQ`, the KDC does not ask: *"Did I issue this ticket five minutes ago?"* Instead, the KDC simply decrypts the TGT using its root service key ($K_{krbtgt}$) and inspects the inner data structures.
- **The Friction Point:**
  All trust in the entire Active Directory domain is rooted in knowledge of the `krbtgt` account's long-term secret key.
- **The Architectural Consequence:**
  If an adversary compromises the `krbtgt` password hash (e.g., via directory synchronization or NTDS extraction), the adversary becomes an omnipotent offline KDC:
  - The adversary can locally manufacture a completely fabricated TGT out of thin air.
  - They can populate the PAC with arbitrary SIDs (such as Domain Admins RID `512` or Enterprise Admins RID `519`).
  - They can forge both the Server Signature and KDC Signature using the stolen $K_{krbtgt}$.
  - They can set the validity timestamp to 10 years in the future.
  - When this forged ticket is presented to *any* Domain Controller in the forest, the DC successfully decrypts it with $K_{krbtgt}$, verifies the signatures, trusts the PAC implicitly, and grants administrative access.

---

### 6.4 Decentralized Service Validation & Local PAC Acceptance (The Mechanism of Silver Tickets)
- **The Design Decision:**
  As established in Section 2.5, during the Application (AP) Exchange, the target service server (`FS01`) validates the client's Service Ticket completely offline from the KDC.
- **The Friction Point:**
  The Service Ticket is encrypted with the service account's secret key ($K_{service}$), and the PAC inside that ticket is signed with that exact same $K_{service}$. By default, the service does not contact the KDC to verify if the KDC signature is legitimate.
- **The Architectural Consequence:**
  If an adversary compromises the password hash of a specific computer account (e.g., `FS01$`) or a service account, the adversary can forge a valid **Service Ticket** directly for that service without ever contacting a Domain Controller:
  - The adversary crafts a Service Ticket, injects administrative SIDs into the PAC, signs the Server Signature with $K_{service}$, and encrypts the ticket with $K_{service}$.
  - When presented to `FS01`, the file server unseals the ticket, validates its own signature, and grants full local administrative access.
  - Because the KDC was completely bypassed, **zero Kerberos ticket generation events (Event 4769) are logged on the Domain Controllers.**

---

### 6.5 Legitimate Pre-Auth with Modified Authorization Data (The Mechanism of Diamond Tickets)
- **The Detection Problem:**
  Golden Tickets often generate noticeable detection anomalies: an `AP-REQ` or `TGS-REQ` appears without any preceding `AS-REQ` (Event 4768) occurring on the domain controllers, or the ticket uses encryption types or options inconsistent with the client workstation's OS.
- **The Architectural Workaround:**
  A "Diamond Ticket" operates by requesting a **genuine, legitimate TGT** from the KDC via standard AS-REQ (generating a valid Event 4768). Then, utilizing a compromised `krbtgt` key, the adversary unseals the legitimate TGT, modifies the PAC inside to append privileged SIDs, recalculates the PAC signatures with $K_{krbtgt}$, and re-encrypts the ticket.
- **The Architectural Consequence:**
  The resulting TGT possesses legitimate KDC-issued timestamps, correct realm metadata, and a real preceding AS-REQ event in the SIEM, while still conferring unauthorized administrative privileges.

---

### 6.6 Ephemeral Ticket Extraction & Identity Replay (Pass-the-Ticket & Overpass-the-Hash)
- **Credential Caching in OS Subsystems:**
  Because Kerberos requires continuous authentication across background processes, LSASS maintains active tickets in plain memory.
- **The Friction Point:**
  If an adversary gains local administrative execution on a workstation where a high-privileged user is logged in, the adversary can dump the raw ASN.1 ticket blobs (`.kirbi` or `ccache`) directly from memory.
- **Pass-the-Ticket:** The adversary imports the stolen TGT into their own logon session. Because the TGT is cryptographically valid and signed, the KDC honors it regardless of which physical network interface transmitted the packet.
- **Overpass-the-Hash (Pass-the-Key):** If an adversary only has an NTLM hash, they exploit the cryptographic property that the `RC4-HMAC` Kerberos key equals the NTLM hash (Section 4.2). The adversary presents the NTLM hash directly to the Kerberos subsystem to complete an `AS-REQ` pre-authentication exchange, receiving a fully valid Kerberos TGT and successfully transitioning from legacy NTLM authentication into the modern Kerberos ecosystem.

---

### 6.7 Public Key Cryptography Extensions (PKINIT & Shadow Credentials)
- **The Mechanism (RFC 4556):**
  **PKINIT (Public Key Cryptography for Initial Authentication)** allows clients to authenticate during the AS Exchange using an X.509 digital certificate instead of a symmetric password. The client signs the pre-authentication data using its private key, and the KDC validates the certificate against Active Directory Certificate Services (AD CS).
- **The Architectural Attribute (`msDS-KeyCredentialLink`):**
  Windows Server 2016 introduced "Shadow Credentials" to support Windows Hello for Business without full PKI rollouts. An account's public key can be written directly to its `msDS-KeyCredentialLink` attribute in Active Directory.
- **The Vulnerability Foundation:**
  If an adversary gains write access (`GenericWrite` or `WriteProperty`) over an Active Directory object (user or computer), the adversary does not need to reset the victim's password. They simply generate an arbitrary X.509 keypair, write the public key into the victim's `msDS-KeyCredentialLink` attribute, and execute an `AS-REQ` using PKINIT to obtain a full TGT for the victim account.

---

## 7. Active Directory Schema, Attributes & Directory Objects

### 7.1 Crucial Directory Attributes & Bitmasks
The following directory attributes in the Active Directory schema directly control Kerberos protocol behavior:

| Attribute Name | Syntax / Format | Operational Impact on Kerberos |
|:---|:---|:---|
| `servicePrincipalName` | Multi-valued String | Links a network service identity to the directory account whose long-term keys will encrypt its tickets. |
| `userAccountControl` | 32-bit Integer Bitmask | Contains operational flags controlling authentication and delegation: <br>• `DONT_REQ_PREAUTH` (`0x00400000`): Disables pre-auth.<br>• `TRUSTED_FOR_DELEGATION` (`0x00080000`): Enables Unconstrained Delegation.<br>• `TRUSTED_TO_AUTH_FOR_DELEGATION` (`0x01000000`): Enables Protocol Transition (S4U2Self).<br>• `ACCOUNTDISABLE` (`0x00000002`): Prevents ticket issuance. |
| `msDS-AllowedToDelegateTo` | Multi-valued String | Whitelist of SPNs that this account is permitted to impersonate users to under Classic Constrained Delegation. |
| `msDS-AllowedToActOnBehalfOfOtherIdentity` | Binary Security Descriptor | Access Control List on a resource object specifying which service principals are allowed to delegate to it via RBCD. |
| `msDS-KeyCredentialLink` | Multi-valued DN-Binary | Contains public key specifications for PKINIT authentication (Windows Hello / Shadow Credentials). |
| `msDS-SupportedEncryptionTypes` | 32-bit Integer Bitmask | Defines supported ciphers: <br>• `0x1`: DES-CBC-CRC<br>• `0x2`: DES-CBC-MD5<br>• `0x4`: RC4-HMAC<br>• `0x8`: AES128-CTS-HMAC-SHA1-96<br>• `0x10`: AES256-CTS-HMAC-SHA1-96 |
| `supplementalCredentials` | Encrypted Octet String | Stores primary password-derived Kerberos keys (AES salts and hashes) in `ntds.dit`. |

---

### 7.2 Service Principal Name (SPN) Architecture & Forest Constraints
An SPN is the unique identifier by which a Kerberos client references a service instance.

#### Standard SPN Syntax:
$$\text{SPN} = \langle \text{service class} \rangle / \langle \text{host} \rangle : \langle \text{port} \rangle / \langle \text{service name} \rangle$$
- **Service Class:** The architectural category of the service (e.g., `HOST`, `cifs`, `MSSQLSvc`, `HTTP`, `LDAP`, `WSMan`).
- **Host:** The Fully Qualified Domain Name (FQDN) or NetBIOS name of the server hosting the service (e.g., `fs01.corp.local`).
- **Port:** The listening port (mandatory for multi-instance services like SQL instances: `:1433`).

#### Critical Forest Constraints:
1. **Uniqueness Requirement:** Within an Active Directory forest, an SPN **must be globally unique**. Two distinct accounts cannot register the same SPN. If an administrator accidentally registers duplicate SPNs, the KDC cannot determine which account key to use, and Kerberos ticket issuance fails with error `KDC_ERR_BADOPTION` or `KRB_ERR_DUPLICATE_TICKETS`.
2. **Account Association Impact:**
   - **Computer Account SPNs:** When an SPN is registered on a machine account (e.g., `HOST/FS01`), the Service Ticket is encrypted with the computer's 120-character machine password. Machine accounts rotate passwords automatically every 30 days and are practically impossible to crack offline.
   - **User Account SPNs:** When an SPN is registered on a human user account (e.g., `svc_sql`), the ticket is encrypted with the user's password hash, exposing that account directly to offline dictionary cracking.

---

### 7.3 The `krbtgt` Domain Account & Dual-Rotation Lifecycle
The `krbtgt` user object (RID `502`) is the root cryptographic authority for the entire Active Directory domain:
- **Properties:** Built-in account, disabled for interactive logon (`ACCOUNTDISABLE`), password managed internally by the Domain Controllers.
- **Key Roles:** Its long-term secret key ($K_{krbtgt}$) encrypts every TGT issued in the domain and signs the KDC Privilege Attribute Certificate (PAC) signature.
- **The Two-Password Architecture:** Active Directory maintains both the *current* password and the *previous* password for `krbtgt`.
  - When the `krbtgt` password is reset, the old password moves to the "previous" key slot.
  - The KDC continues to honor existing TGTs that were minted using the previous key until their maximum ticket lifetime expires (typically 10 hours).
- **The Mandatory Dual-Reset Procedure:**
  To completely purge forged Golden Tickets after a security incident, the `krbtgt` account password **must be reset twice**, separated by a time interval longer than the maximum ticket lifetime (at least 10 hours, recommended 24 hours):
  - **First Reset:** Replaces the active key. Old forged tickets continue to function via the "previous" key slot.
  - **Wait Period:** Allows legitimate enterprise users to naturally renew tickets.
  - **Second Reset:** Overwrites the "previous" slot with the key from the first reset, completely invalidating every historical ticket across the entire forest.

---

## 8. Defensive Telemetry, Detection Engineering & Hardening

### 8.1 Windows Security Event Telemetry
Kerberos operations generate rich, high-fidelity security events on Active Directory Domain Controllers:

| Event ID | Log Name | Operational Meaning | Strategic Telemetry Significance |
|:---:|:---:|:---|:---|
| **4768** | Security | A Kerberos authentication ticket (TGT) was requested (`AS-REQ`). | Monitors initial logons. Inspect for accounts with Pre-Authentication disabled (`Pre-Auth Type: 0`) and unusual encryption types (`0x17` vs `0x12`). |
| **4769** | Security | A Kerberos service ticket was requested (`TGS-REQ`). | Primary telemetry for service ticket generation. High volumes of requests for user-associated SPNs or RC4 encryption (`Ticket Options: 0x40810000`, `Encryption: 0x17`) indicate reconnaissance or ticket extraction. |
| **4770** | Security | A Kerberos service ticket was renewed. | Monitors ticket extension patterns. |
| **4771** | Security | Kerberos pre-authentication failed. | **High-Value.** Indicates bad password attempts (`Failure Code: 0x18`) or clock skew (`0x25`). Useful for detecting password spraying. |
| **4624** | Security | An account was successfully logged on. | Look for Logon Type 3 (Network) accompanied by Kerberos authentication packages. |
| **4741** | Security | A computer account was created. | Telemetry marker for Resource-Based Constrained Delegation (RBCD) exploitation staging. |
| **5136** | Security | A directory service object was modified. | Vital for detecting changes to `msDS-AllowedToDelegateTo`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, or `msDS-KeyCredentialLink`. |

---

### 8.2 Detection Heuristics & Hunting Logic

#### 1. Kerberoasting Detection (Kusto Query Language - KQL):
Detects anomalous volume of Service Ticket requests requesting legacy RC4 encryption for user accounts:

```kusto
SecurityEvent
| where EventID == 4769
| where ServiceName !endswith "$" and ServiceName != "krbtgt"
| where TicketEncryptionType == "0x17" // RC4-HMAC
| where Status == "0x0" // Success
| summarize RequestCount = count(), SPNList = make_set(ServiceName) by TargetUserName, ClientAddress, bin(TimeGenerated, 5m)
| where RequestCount >= 5
| project TimeGenerated, TargetUserName, ClientAddress, RequestCount, SPNList
```

#### 2. Golden Ticket Anomaly Heuristic:
Golden Tickets frequently lack preceding AS-REQ telemetry or exhibit impossible ticket lifetimes:
- **Heuristic A (TGS without AS):** Flag any `Event 4769` where no corresponding `Event 4768` (TGT request) was logged for that user/IP within the preceding 10 hours.
- **Heuristic B (Domain Controller TGS):** Flag any Service Ticket request (`4769`) where the requesting client IP is an unmanaged external workstation but the account claims membership in Domain Admins (`RID 512`).

---

### 8.3 Enterprise Hardening Blueprint & Remediation Roadmap
Securing Kerberos requires eliminating weak legacy cryptography and restricting delegation privileges:

1. **Deprecate RC4 Domain-Wide:**
   - Configure Group Policy: `Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> Network security: Configure encryption types allowed for Kerberos`.
   - Restrict allowed encryption types strictly to `AES128_HMAC_SHA1`, `AES256_HMAC_SHA1`, and `Future encryption types`.
2. **Eliminate User-Account SPNs:**
   - Transition all database, web, and custom service accounts from standard Active Directory user accounts to **Group Managed Service Accounts (gMSAs)**. gMSAs use complex, automatically rotated 128-byte passwords that render offline cracking mathematically infeasible.
3. **Audit and Eradicate Unconstrained Delegation:**
   - Query all domain objects where `userAccountControl` contains the `TRUSTED_FOR_DELEGATION` flag.
   - Refactor these systems to use **Resource-Based Constrained Delegation (RBCD)**, ensuring that sensitive credentials are never stored in intermediate LSASS caches.
4. **Deploy the "Protected Users" Security Group:**
   - Add all Tier-0 administrative accounts (Enterprise Admins, Domain Admins, sensitive service principals) to the **Protected Users** security group (introduced in Windows Server 2012 R2).
   - *Protective Controls Enforced:*
     - Credentials are never cached in LSASS.
     - NTLM authentication is completely disabled for the account.
     - Kerberos pre-authentication cannot be downgraded to RC4.
     - Delegation is strictly disabled (TGTs cannot be forwarded).
     - Ticket lifetime is capped at 4 hours.
5. **Enable FAST (Flexible Authentication Secure Tunneling / Kerberos Armoring):**
   - Enable Kerberos Armoring on all Domain Controllers via GPO (`KDC support for claims, compound authentication and Kerberos armoring`).
   - FAST encrypts the initial `AS-REQ` exchange inside a tunnel sealed with the computer account's key, protecting pre-authentication timestamps from interception and cracking even on untrusted networks.
6. **Enforce PAC Signature Validation (KB5008380 / KB5020805):**
   - Verify that all Domain Controllers have PAC signature validation and ticket checksum enforcement set to full Enforcement Mode, preventing PAC modification and identity spoofing across the directory.

---

## 9. Authoritative Specifications, RFCs & Cross-Vault Links

### 9.1 Authoritative Specifications
- **RFC 4120:** *The Kerberos Network Authentication Service (V5)* — The foundational specification of the protocol architecture, message types, and exchange sequences.
- **RFC 3961 / RFC 3962:** *Encryption and Checksum Specifications for Kerberos 5 & AES Encryption* — Defines key derivation functions, PBKDF2 parameters, and AES cipher modes.
- **RFC 4556:** *Public Key Cryptography for Initial Authentication in Kerberos (PKINIT)* — Protocol specification for certificate-based pre-authentication.
- **RFC 6113:** *A Generalized Framework for Kerberos Pre-Authentication (FAST)* — Specification for Kerberos armoring tunnels.
- **[MS-KILE]:** *Kerberos Protocol Extensions* — Microsoft documentation detailing Windows-specific Kerberos behaviors, logon session management, and cipher negotiations.
- **[MS-PAC]:** *Privilege Attribute Certificate Data Structure* — Official specification defining the structure, buffer formats, and cryptographic signature algorithms of the PAC.
- **[MS-SFU]:** *Kerberos Protocol Extensions: Service for User and Constrained Delegation Protocol* — Formal documentation of S4U2Self and S4U2Proxy extensions.
