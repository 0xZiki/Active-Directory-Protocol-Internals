---
title: "Phase 0 — Foundations & Protocol Internals: Architectural Reference"
doc_type: "foundation"
phase: 0
category: "reference"
target_tool: "General"
platform: "Windows"
status: "verified"
tags:
  - reference
  - foundation
  - architecture
  - kerberos
  - ntlm
  - ldap
  - acl
  - gpo
  - dns
  - adcs
  - trusts
  - ntds
  - replication
  - fsmo
---

# Phase 0 — Foundations & Protocol Internals: The Master Architectural Flight Manual

> **Phase Mission:** This master summary synthesizes the ten foundational pillars of Active Directory Domain Services (AD DS) into a single, cohesive architectural mental model. It serves as the primary technical flight manual for Phase 0. Every downstream offensive primitive and defensive detection rule from Phase 1 through Phase 8 is not an isolated trick, but the direct, mathematically predictable outcome of the protocol designs, database structures, and cryptographic trust boundaries documented below.

---

## 1. The Unified Active Directory Ecosystem

Active Directory is not a single executable or monolithic database. It is a distributed, multi-master ecosystem of protocols, databases, cryptographic engines, and kernel objects working in synchronized orchestration.

### The Six Operational Pillars of Active Directory:
1. **Identity Storage & Replication:** The Extensible Storage Engine (`ntds.dit`) maintaining hierarchical naming contexts, protected by a three-layer encryption hierarchy (BootKey $\rightarrow$ PEK $\rightarrow$ User Secrets) and synchronized via multi-master DRSUAPI replication.
2. **Service Discovery & Routing:** Active Directory-Integrated DNS (ADIDNS) mapping network topologies via dynamic SRV records, replicating across application partitions (`DomainDnsZones`, `ForestDnsZones`), and securing updates via Kerberos GSS-TSIG.
3. **Authentication Highway:** The dual-protocol engine balancing symmetric ticket-based Kerberos v5 (with PAC authorization envelopes and ephemeral session keys) against legacy challenge-response NTLMv2 with Netlogon passthrough validation.
4. **Directory Interrogation & Mutation:** Lightweight Directory Access Protocol (LDAP) operating via ASN.1 BER encoding, offering granular Polish prefix search filters and matching rule OIDs, secured by SASL GSS-API signing and Channel Binding Tokens (CBT).
5. **Authorization & Kernel Enforcement:** The Windows Security Reference Monitor (SRM) evaluating in-memory Access Tokens (SIDs, integrity levels, and privileges) against on-disk `nTSecurityDescriptor` binary structures, audited via SDDL and protected by the automated AdminSDHolder/SDProp repair engine.
6. **Identity Augmentation & Federation:** Asymmetric Public Key Infrastructure (AD CS) bridging certificate-based authentication via Kerberos PKINIT, paired with Inter-Realm Trust relationships using shared Trust Keys and SID Filtering firewalls.

---

## 2. High-Level Architectural Flowchart

The following decision and interaction flowchart traces how a client transitions from bare-metal network boot to authenticated, authorized execution across trust boundaries:

```text
  +----------------------------------------------------------------------------------------------------+
  |                        THE UNIFIED ACTIVE DIRECTORY ACCESS & TRUST LIFECYCLE                       |
  +----------------------------------------------------------------------------------------------------+

     [ CLIENT BOOT & SERVICE DISCOVERY ]
     1. Client boots on subnet 10.10.1.0/24.
     2. Invokes Netlogon DC Locator -> Queries DNS for _ldap._tcp.dc._msdcs.corp.local (UDP 53).
     3. DNS server resolves SRV record from ForestDnsZones partition in ntds.dit.
     4. Client sends UDP Netlogon ping -> DC identifies local site (HeadQuarters-Cairo).
     5. Client connects to optimal local Domain Controller (DC01).
                    |
                    v
     [ AUTHENTICATION PHASE: Kerberos vs. NTLM ]
     Is client connecting via Hostname/FQDN or Raw IP address?
                    |
          +---------+---------+
          |                   |
        FQDN                 RAW IP
          |                   |
          v                   v
     [ KERBEROS v5 ]     [ NTLM FALLBACK ]
     - AS-REQ / AS-REP   - Kerberos lacks SPN for raw IP; falls back to NTLMSSP.
       (Pre-Auth w/ Key) - 3-Message Handshake: Type 1 -> Type 2 (Challenge) -> Type 3.
     - Obtains TGT       - Target Server executes Netlogon Passthrough Authentication
       sealed with         (NetrLogonSamLogonEx) over RPC to DC01.
       K_krbtgt + PAC.   - DC verifies challenge-response against stored NT Hash.
          |                   |
          +---------+---------+
                    |
                    v
     [ DIRECTORY ACCESS & QUERYING (LDAP) ]
     - Client opens TCP 389/636 to DC01.
     - Authenticates via SASL GSS-SPNEGO Bind (Kerberos Service Ticket for ldap/dc01).
     - Derives session keys for LDAP Signing & Sealing (preventing relay).
     - Client queries directory using Polish Prefix Filters: (&(objectClass=user)(sAMAccountName=...)).
     - DC executes search against ntds.dit datatable using ESE B-Tree indices.
                    |
                    v
     [ AUTHORIZATION & KERNEL RUNTIME MATERIALIZATION ]
     - LSASS unseals authentication proof (PAC or Netlogon Validation Buffer).
     - Invokes kernel executive (NtCreateToken) -> Materializes volatile ACCESS TOKEN.
     - Token populates User SID, Group SIDs, System Privileges (LUIDs), and Integrity Level.
     - When thread attempts action, Security Reference Monitor (SRM) executes Access Check:
       * Compares Token SIDs against object DACL in nTSecurityDescriptor.
       * Canonical Traversal: Explicit Deny -> Explicit Allow -> Inherited Deny -> Inherited Allow.
                    |
                    v
     [ IDENTITY AUGMENTATION (AD CS & PKI) ]
     - Need hardware-backed or certificate identity? Client queries Configuration Partition.
     - Locates Certificate Template in CN=Certificate Templates.
     - Client generates local Private Key (K_priv) -> Submits CSR to Enterprise CA via MS-ICPR.
     - CA validates template DACL, verifies EKU (Client Authentication), and signs X.509 Certificate.
     - Client uses certificate for Kerberos PKINIT (PA-PK-AS-REQ) -> KDC checks NTAuthStore.
                    |
                    v
     [ CROSS-BOUNDARY FEDERATION (TRUSTS) ]
     - Resource located in foreign domain/forest?
     - Local KDC mints Inter-Realm Referral TGT sealed with shared Trust Key (K_trust).
     - Client presents Referral TGT to Foreign KDC.
     - Foreign KDC enforces SID Filtering (Quarantine) -> Strips unauthorized foreign SIDs.
     - Foreign KDC issues target Service Ticket -> Access granted to foreign resource!
  +----------------------------------------------------------------------------------------------------+
```

---

## 3. The Master Phase 0 Architecture Reference Matrix

The following reference matrix synthesizes the ten foundational components, documenting their wire protocols, physical storage paths, directory locations, and foundational security friction points:

| Foundational Component | Primary Ports & Protocols | Storage Location (Disk / DB / Registry) | Active Directory Schema Container / Class | Foundational Security Friction Point |
|:---|:---|:---|:---|:---|
| **AD DS Directory Engine** | TCP/UDP 389, 636, 3268, 88 | `%SystemRoot%\NTDS\ntds.dit` (ESE Jet Blue) | `Domain`, `OrganizationalUnit`, `Configuration`, `Schema` | Multi-master DRSUAPI replication permits secret synchronization (DCSync root). |
| **Kerberos v5 Engine** | UDP/TCP 88, TCP 464 (kpasswd) | LSASS Memory (`lsass.exe` / `kerberos.dll`) | Service Principal Names (`servicePrincipalName`), `krbtgt` account | Offline cracking of service tickets (Kerberoasting) & stateless KDC trust (Golden Tickets). |
| **NTLM Protocol Suite** | Embedded in SMB (445), HTTP (80/443), RPC (135) | SAM hive, `ntds.dit`, and LSASS memory | User account password attributes (`unicodePwd`) | Decoupling of challenge from transport channel allows cross-protocol NTLM Relay. |
| **LDAP Query Engine** | TCP/UDP 389 (LDAP), TCP 636 (LDAPS), TCP 3268/3269 | `ntds.dit` (`datatable`, `link_table`) | All directory object classes | Unsigned LDAP permits MitM manipulation and NTLM relay into directory writes. |
| **Security Descriptors & ACLs** | Evaluated locally by Windows Kernel (SRM) | Binary attribute: `nTSecurityDescriptor` | Stored on every Active Directory object | Discretionary delegation paths form a directed mathematical graph of privilege escalation. |
| **Group Policy Infrastructure** | LDAP (389) for GPC; SMB (445) for GPT | Split: LDAP (`CN=Policies`) + SYSVOL (`\\corp.local\SYSVOL`) | `groupPolicyContainer` (`CN=Policies,CN=System`) | Unchecked GPO write permissions allow instant mass-execution across endpoints as `SYSTEM`. |
| **Privileged Groups & Tokens** | Kernel system calls (`NtCreateToken`, Win32 API) | Volatile Kernel Pool Memory (`TOKEN` structure) | Built-in Groups (`CN=Builtin`, `CN=Users`), Group SIDs | Kernel privileges (`SeDebug`, `SeImpersonate`) bypass DACLs and allow full system takeover. |
| **AD-Integrated DNS (ADIDNS)** | UDP/TCP 53 (DNS / GSS-TSIG) | `ntds.dit` (`DomainDnsZones`, `ForestDnsZones`) | `dnsNode` (`CN=MicrosoftDNS`) | Default `CreateChild` rights allow standard users to inject wildcard and spoofing records. |
| **Certificate Services (AD CS)** | TCP 135 / RPC (MS-ICPR), HTTP/S 80/443 (`/certsrv`) | CA database (`certlog.edb`), Configuration NC | `pKICertificateTemplate`, `pKIEnrollmentService` | Supplying arbitrary SANs on Client Auth templates enables complete identity impersonation. |
| **Trust Architecture** | UDP/TCP 88 (Referral), TCP 135 / 445 (Netlogon) | Trusted Domain Objects (`trustedDomain`), LSA Secrets | `CN=System,DC=corp,DC=local` (`trustedDomain`) | Intra-forest trusts lack SID filtering by default, allowing parent takeover from compromised children. |

---

## 4. Synthesis of the Ten Foundational Chapters

### Chapter 1: Active Directory Architecture (`active-directory-architecture.md`)
- **The Core Axiom:** The **Forest is the true security boundary**, while the **Domain is merely an administrative boundary**.
- **Database Internals:** `ntds.dit` is powered by the Extensible Storage Engine (ESE / Jet Blue) with three core tables: `datatable`, `link_table`, and `secret_table`.
- **The Three-Layer Credential Encryption Hierarchy:** Password hashes are encrypted using the Password Encryption Key (PEK), which is encrypted with the BootKey (Syskey) stored in the `SYSTEM` registry hive. Stealing `ntds.dit` without `SYSTEM` yields zero plaintext or usable hashes.
- **Replication Mathematics:** DRSUAPI tracks state using 64-bit Update Sequence Numbers (USNs), InvocationIDs, and Up-To-Dateness (UTD) vectors, resolving write collisions deterministically via Version $\rightarrow$ Timestamp $\rightarrow$ InvocationID.

### Chapter 2: Kerberos Authentication (`kerberos-authentication.md`)
- **The Scenario Triad:** Replaces plaintext password transmission with symmetric cryptographic envelopes issued by a Trusted Third Party (the KDC).
- **The Three Protocol Phases:**
  1. *AS Exchange:* Client proves key possession via `PA-ENC-TIMESTAMP` $\rightarrow$ KDC issues TGT (sealed with $K_{krbtgt}$) and Logon Session Key.
  2. *TGS Exchange:* Client presents TGT and Authenticator $\rightarrow$ KDC issues Service Ticket (sealed with $K_{service}$) and Service Session Key.
  3. *AP Exchange:* Client presents Service Ticket to application server $\rightarrow$ Server decrypts ticket locally and executes mutual authentication.
- **The Privilege Attribute Certificate (PAC):** Microsoft's vital extension containing user SIDs and group tokens, signed with dual signatures (Server Signature + KDC Signature) to eliminate LDAP connection storms.
- **Delegation Models:** Unconstrained (full TGT caching in LSASS) vs. Constrained (S4U2Self/S4U2Proxy whitelist) vs. Resource-Based (RBCD target-driven security descriptors).

### Chapter 3: NTLM Authentication (`ntlm-authentication.md`)
- **The Fallback Reality:** Triggered automatically whenever clients connect via raw IP addresses or non-domain channels where Kerberos cannot resolve an SPN.
- **The 3-Message Handshake:** Type 1 (Negotiate capabilities) $\rightarrow$ Type 2 (Server Challenge 8-byte nonce + TargetInfo AV Pairs) $\rightarrow$ Type 3 (Authenticate proof `NTProofStr` + Client Blob).
- **Netlogon Passthrough:** Member servers cannot verify domain credentials locally; they pass the challenge and response over an encrypted Netlogon RPC pipe (`MS-NRPC`) to a Domain Controller.
- **The Relay Flaw & Defenses:** NTLM challenge responses are unbonded to the network transport. Message Integrity Checks (MIC) protect packet tampering, while Extended Protection for Authentication (EPA) with Channel Binding Tokens (CBT) binds authentication to outer TLS certificate hashes.

### Chapter 4: LDAP Protocol (`ldap-protocol.md`)
- **The Directory Access Highway:** All directory queries and object mutations traverse LDAP over TCP 389/636 using ASN.1 BER Tag-Length-Value encoding.
- **The Four Bind Models:** Anonymous Bind (restricted by `SeventhDsHeuristic`), Simple Bind (plaintext password hazard), SASL GSS-API Bind (Kerberos-signed enterprise standard), and LDAPS (TLS encapsulation).
- **Filter Mechanics:** Polish prefix notation (`&`, `|`, `!`) augmented by Extensible Matching Rule OIDs: Bitwise AND (`1.2.840.113556.1.4.803`), Bitwise OR (`.804`), and In-Chain Transitive Matching (`1.2.840.113556.1.4.1941`).
- **Pagination & Signing:** Bypassing the `MaxPageSize` 1,000-object limit via the Simple Paged Results Control (RFC 2696), and defeating NTLM relaying into directory writes via mandatory LDAP Server Signing.

### Chapter 5: Security Descriptors & ACLs (`security-descriptors-acls.md`)
- **Runtime Authorization Truth:** Privilege in Active Directory is not a boolean "admin" flag; it is the mathematical evaluation of an Access Token against a Security Descriptor.
- **The SRM Access Check Algorithm:** Deterministic traversal of the DACL in canonical order (Explicit Deny $\rightarrow$ Explicit Allow $\rightarrow$ Inherited Deny $\rightarrow$ Inherited Allow) until the requested access mask is completely satisfied or default deny terminates.
- **Binary `nTSecurityDescriptor` & SDDL:** Self-relative binary layout deconstructed into Owner SID, Group SID, SACL, and DACL, represented as formal SDDL strings (`O:owner G:group D:dacl S:sacl`).
- **The Directed Graph Model:** Proves why `WriteDacl` and `WriteOwner` are mathematically equivalent to `GenericAll`, and examines the automated inheritance repair cycle of `AdminSDHolder` and `SDProp`.

### Chapter 6: Group Policy Objects (`group-policy-objects.md`)
- **Declarative Orchestration at Scale:** Asynchronous, pull-based configuration management replacing manual endpoint registry modifications.
- **The Split Architecture:**
  - *Group Policy Container (GPC):* Stored in Active Directory LDAP (`CN=Policies,CN=System`) holding metadata, status flags, and CSE GUID lists.
  - *Group Policy Template (GPT):* Stored in SYSVOL (`\\corp.local\SYSVOL\...\Policies\{GUID}`) holding `GPT.INI`, `registry.pol`, scripts, and XML preferences.
- **Version Synchronization:** 32-bit arithmetic tracking independent machine and user versions: $(\text{Machine Version} \ll 16) \mid \text{User Version}$.
- **Precedence & Execution:** The **LSDOU** rule (**L**ocal $\rightarrow$ **S**ite $\rightarrow$ **D**omain $\rightarrow$ **OU**) where "last applied wins", modified by Block Inheritance and Enforced overrides, executed locally by `gpsvc.exe` and Client-Side Extensions (CSEs).

### Chapter 7: Privileged Groups & Access Tokens (`privileged-groups-and-tokens.md`)
- **Kernel Token Materialization:** How static LDAP records in `ntds.dit` transform into volatile kernel `TOKEN` structures during interactive logon.
- **Token Anatomy:** Primary Tokens (process-bound) vs. Impersonation Tokens (thread-bound), governed by four impersonation levels (Anonymous, Identification, Impersonation, Delegation).
- **Mandatory Integrity Control (MIC) & UAC:** Hierarchical integrity levels (Untrusted, Low, Medium, High, System) enforcing "No-Write-Up", and UAC dual-linked tokens (Filtered Medium Token vs. Elevated High Token).
- **Dangerous Kernel Superpowers:** Deconstructing the Win32 mechanics of `SeImpersonatePrivilege` (token capture to `SYSTEM`), `SeDebugPrivilege` (process DACL bypass to dump LSASS), `SeBackupPrivilege` (file DACL bypass to copy `ntds.dit`), `SeTakeOwnershipPrivilege`, and `SeLoadDriverPrivilege`.
- **Group Taxonomy:** AGDLP group nesting and why legacy operator groups (**Account Operators**, **Server Operators**, **Backup Operators**) represent catastrophic Tier-0 delegation risks.

### Chapter 8: AD-Integrated DNS Architecture (`ad-dns-architecture.md`)
- **DNS as Identity Infrastructure:** Active Directory cannot function without DNS; DNS acts as the service discovery engine for Kerberos, LDAP, and GC endpoints.
- **The DC Locator Pipeline:** Workstations query generic SRV records (`_ldap._tcp.dc._msdcs.corp.local`), receive prioritized DC lists, perform Netlogon UDP pings to identify their Active Directory Site, and query site-specific SRV records for optimal routing.
- **Physical LDAP Reality:** DNS records exist as physical `dnsNode` objects inside Application Naming Contexts (`DomainDnsZones` and `ForestDnsZones`), each possessing its own `nTSecurityDescriptor` DACL.
- **Dynamic Updates & Scavenging:** GSS-TSIG Kerberos-authenticated updates vs. unauthenticated update risks, aging timelines (No-Refresh + Refresh), tombstoning, and Global Query Block List (GQBL) protections against WPAD hijacking.

### Chapter 9: Certificate Services Architecture (`certificate-services-architecture.md`)
- **The Asymmetric Partner:** Supplements symmetric Kerberos passwords with public-key cryptography for smart cards, VPNs, and non-domain identity verification.
- **Active Directory PKI Containers:** Deep dive into `CN=Public Key Services` in the Configuration partition, specifically the **`NTAuthCertificates`** store which acts as the mandatory cryptographic gateway for domain authentication.
- **Certificate Templates & EKUs:** Schema rules governing enrollment DACLs, Extended Key Usages (Client Authentication `1.3.6.1.5.5.7.3.2`, Smart Card Logon, Enrollment Agent), and the critical Subject Alternative Name divide: directory-built vs. `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`.
- **Architectural Vulnerability Primitives:** Arbitrary SAN injection (ESC1), enrollment agent proxying (ESC3), and unhardened HTTP Web Enrollment NTLM relaying (ESC8).

### Chapter 10: Trust Architecture (`trust-architecture.md`)
- **Federation Without Replication:** Federating identity across corporate boundaries without replicating `ntds.dit` databases.
- **The Cryptographic Anchor:** The shared symmetric **Trust Key** stored in Trusted Domain Objects (TDOs) and LSA Secrets, rotated every 30 days.
- **The Inter-Realm Referral Hop:** Client queries local KDC $\rightarrow$ receives Referral TGT sealed with the shared Trust Key $\rightarrow$ presents Referral TGT to foreign KDC $\rightarrow$ receives foreign Service Ticket.
- **Perimeter Boundaries:** Why intra-forest trusts are NOT security boundaries (SID History manipulation permits child-to-parent forest compromise), and how cross-forest trusts enforce hard isolation through **SID Filtering (Quarantine)** and **Selective Authentication**.

---

## 5. The Bridge to Offensive & Defensive Mastery

With Phase 0 complete, the technical foundation of Active Directory Domain Services is established. 

Every subsequent phase in this vault builds directly upon these ten architectural pillars:
- **Phase 1 (Reconnaissance & Enumeration):** Leverages LDAP search filters, DNS SRV records, and broad default `Authenticated Users` read scopes to map forest infrastructure.
- **Phase 2 (Credential Access):** Leverages Kerberos ticket extraction from LSASS memory, NTLM challenge-response capturing, and offline cracking of service envelopes.
- **Phase 3 (Privilege Escalation):** Traverses the directed mathematical graph of `nTSecurityDescriptor` ACEs, abuses dangerous token privileges (`SeImpersonate`), and exploits misconfigured certificate templates (AD CS).
- **Phase 4 (Lateral Movement):** Abuses Kerberos delegation (S4U2Self/S4U2Proxy, RBCD), GPO deployment pipelines, and cross-tier ticket passing.
- **Phase 5 (Domain Dominance & Persistence):** Leverages `krbtgt` key control (Golden Tickets), `AdminSDHolder` template poisoning, and DRSUAPI directory replication (DCSync).
- **Phase 6 (Cross-Forest Pivoting):** Exploits inter-realm referral routing, trust key extraction, and SID History across unhardened trust boundaries.

Whoever masters the foundational mechanics of the TGT, the PAC, the SAM, the DIT, and the Security Descriptor holds absolute comprehension of the enterprise identity plane.
