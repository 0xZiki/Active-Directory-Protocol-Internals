---
title: "Trust Architecture — Trust Relationships Between Domains"
doc_type: "foundation"
phase: 0
phase_name: "00-Foundations"
topic: "Directory-Internals"
core_primitives: ["Trust", "Inter-Realm TGT", "Trust Key", "SID Filtering", "SID History", "TDO", "PAM Trust", "Shadow Principal", "Transitive Trust", "Selective Authentication", "Name Suffix Routing"]
applies_to: ["Active Directory", "Kerberos KDC", "Forest", "Domain"]
status: "verified"
tags: [foundation, internals, trusts, inter-realm, sid-filtering, sid-history, trust-keys, pam, routing]
---

# Trust Architecture — Trust Relationships Between Domains

> **Architectural Mission:** Master the internal mechanics of Active Directory Trust relationships and cross-realm Kerberos authentication. Understand how distinct domains and forests federate identity without replicating directory databases, dissect the cryptographic anchor of the shared Trust Key and the Trusted Domain Object (TDO), trace the multi-hop Inter-Realm Referral TGT ticket exchange, deconstruct SID Filtering, Name Suffix Routing, and Quarantine boundaries, and analyze why intra-forest trusts fail to provide security isolation while cross-forest trusts enforce hard cryptographic perimeters.

---

## 1. Architectural Foundations: Identity Federation Without Database Replication

### 1.1 The Enterprise Federation Dilemma
In a growing enterprise or multinational corporation, organizations frequently operate multiple distinct Active Directory domains or separate forests (e.g., resulting from corporate mergers, regulatory geographical partitioning, or supply chain partnerships). 

An architectural question arises:
> *"How can an employee in the European child domain (`eu.corp.local`) securely access an internal resource hosted on a server in the corporate headquarters domain (`dc01.corp.local`) without replicating the entire European user database into headquarters?"*

Duplicating directory databases across organizational boundaries is an engineering failure:
- It creates massive network bandwidth overhead across WAN links.
- It introduces directory naming collisions and schema conflicts.
- It destroys decentralized administrative autonomy and violates regional data sovereignty laws.

### 1.2 The Trust Concept: Cryptographic Authentication Agreements
To solve this dilemma, Active Directory implements **Trust Relationships**. 

A Trust is an established cryptographic agreement between two independent Kerberos realms where the **Trusting Domain** agrees to honor authentication proofs minted by the **Trusted Domain**:
- **Trusting Domain (Resource Domain):** The domain hosting the resource (e.g., the file share, server, or application) that trusts another domain.
- **Trusted Domain (Account Domain):** The domain holding the user accounts whose identities are verified and vouched for.

```text
+----------------------------------------------------------------------------------------------------+
|                               THE DIRECTIONALITY OF TRUST VS. ACCESS                               |
+----------------------------------------------------------------------------------------------------+

        TRUSTED DOMAIN (Account Domain)                    TRUSTING DOMAIN (Resource Domain)
        [ eu.corp.local (Holds Alice) ]                   [ corp.local (Hosts Resource on DC01) ]
                       |                                                  |
                       |                  TRUST DIRECTION                 |
                       | <=============================================== |
                       |    corp.local TRUSTS identities from eu.corp.local
                       |                                                  |
                       |                  ACCESS DIRECTION                |
                       | ===============================================> |
                       |    Alice in eu.corp.local ACCESSES resources in corp.local
+----------------------------------------------------------------------------------------------------+
```

> **The Directionality Rule:** **Access flows in the opposite direction of the trust arrow.**
> If Domain B trusts Domain A (Trust arrow: $B \longrightarrow A$), users in Domain A can access resources in Domain B.

---

### 1.3 The Trust Taxonomy
Active Directory supports several distinct categories of trust relationships:

| Trust Category | Transitivity | Boundary Scope | Typical Operational Use Case |
|:---|:---:|:---|:---|
| **Parent-Child Trust** | **Transitive** | Intra-Forest | Established automatically between parent and child domains (e.g., `corp.local` and `eu.corp.local`). Two-way transitive by default. |
| **Tree-Root Trust** | **Transitive** | Intra-Forest | Established automatically between distinct domain trees within the same forest sharing a common schema and configuration (e.g., `corp.local` and `acquiredcompany.com`). |
| **Forest Trust** | **Transitive** | Cross-Forest | Links two separate forest root domains. Transitive across all domains within both forests. Supports Kerberos AES encryption and requires Forest Functional Level 2003+. |
| **External Trust** | **Non-Transitive** | Cross-Forest / Legacy | Connects two specific domains across different forests, or links to a legacy NT4 domain. Does not flow transitively to child domains. |
| **Realm Trust** | Transitive / Non-Transitive | Non-Windows | Connects an Active Directory domain to an external non-Windows Kerberos realm (such as an MIT Kerberos realm running on Linux/UNIX). |
| **Shortcut Trust** | **Transitive** | Intra-Forest | An explicit trust link created between two distant child domains in the same forest to optimize Kerberos referral hop latency across large domain trees. |

---

### 1.4 Terminology & Core Primitives (Zero-Acronym Onboarding)
- **TDO (Trusted Domain Object):** An Active Directory object of class `trustedDomain` stored under `CN=System,DC=corp,DC=local` that records the operational attributes, direction, partner name, and security flags of a trust relationship.
- **Trust Key:** A shared, symmetric cryptographic password negotiated between the Domain Controllers of two trusting domains, used to seal and unseal Inter-Realm Kerberos referral tickets.
- **Inter-Realm TGT (Referral TGT):** A specialized Kerberos Ticket Granting Ticket issued by a client's local KDC, encrypted with the shared Trust Key, addressed to the Ticket Granting Service (TGS) of the remote trusting domain.
- **SID Filtering (Quarantine):** A security boundary enforcement mechanism where the KDC of a trusting forest inspects the Privilege Attribute Certificate (PAC) of an incoming cross-forest referral ticket and strips out any SIDs that do not belong to the trusted domain's legitimate SID namespace.
- **SID History (`sIDHistory`):** An Active Directory attribute storing previous Security Identifiers assigned to a principal during historical domain migrations, carried inside the PAC to maintain legacy resource access.
- **Name Suffix Routing:** The directory mechanism that routes authentication requests across a Forest Trust based on DNS domain namespaces and NetBIOS names associated with each forest.
- **Selective Authentication:** A trust setting that enforces strict access control by requiring foreign users to be explicitly granted the `Allowed to Authenticate` permission on specific target computer objects before the KDC will issue service tickets.
- **PAM Trust (Privileged Access Management Trust):** A specialized, one-way shadow forest trust (introduced in Windows Server 2016) used to isolate Tier-0 administrative identities inside a dedicated "Bastion" forest.

---

## 2. The Cryptographic Anchor: The Trust Key & The TDO

### 2.1 The Trusted Domain Object (TDO)
Every trust relationship is represented within the Active Directory database by a **Trusted Domain Object (TDO)** residing in the Domain Naming Context under:
`CN=<DomainNetBIOSName>,CN=System,DC=corp,DC=local`

#### Critical TDO Attributes:
- **`trustPartner`:** The Fully Qualified Domain Name (FQDN) of the partner domain (e.g., `eu.corp.local`).
- **`trustDirection`:** Integer bitmask defining the direction of trust:
  - `1`: Inbound Trust (Trusting Domain).
  - `2`: Outbound Trust (Trusted Domain).
  - `3`: Bidirectional / Two-Way Trust.
- **`trustType`:** Integer indicating partner protocol (e.g., `2` for an Active Directory Windows domain, `3` for an MIT Kerberos realm).
- **`trustAttributes`:** 32-bit bitmask governing security boundary controls:
  - `0x00000004` (`TRUST_ATTRIBUTE_QUARANTINED_DOMAINS`): **SID Filtering is enforced.**
  - `0x00000008` (`TRUST_ATTRIBUTE_FOREST_TRANSITIVE`): Trust is forest-wide transitive.
  - `0x00000040` (`TRUST_ATTRIBUTE_CROSS_ORGANIZATION`): Selective Authentication is enabled.

---

### 2.2 The Trust Key Architecture
How do two Domain Controllers in completely separate domains establish mutual cryptographic trust without sharing a master administrative password?

**The Shared Symmetric Secret:**
When a trust is established, the Domain Controllers of both domains negotiate a cryptographically random, 30-character shared secret password known as the **Trust Key**.
- In the local domain, the Trust Key is represented as a specialized service principal:
  $$\mathbf{krbtgt/TRUSTED\_REALM\_NAME} \quad \text{and} \quad \mathbf{krbtgt/TRUSTING\_REALM\_NAME}$$
- The Trust Key password is encrypted and stored in two locations:
  1. Inside `ntds.dit` within the TDO object's secure properties.
  2. Inside the local Domain Controller's **LSA Secrets** registry store (under keys such as `$MACHINE.ACC` and `G$BCKUPKEY`).
- **Automatic Rotation:** Active Directory Domain Controllers automatically rotate this shared Trust Key password **every 30 days**. Like the domain's root `krbtgt` account, Active Directory maintains both the current and previous Trust Key in memory to ensure ongoing authentications are not abruptly severed during rotation.

---

## 3. Walkthrough: Cross-Domain Kerberos Referral Flow

### 3.1 The Scenario Setup
To observe how an Inter-Realm Kerberos handshake operates on the wire, trace this enterprise access:
- **User:** `alice@eu.corp.local` (Resides in child domain `eu.corp.local`).
- **Client Machine:** `WKSTN01.eu.corp.local`.
- **Target Resource:** A shared resource hosted on `dc01.corp.local` (Resides in parent domain `corp.local`):
  `\\dc01.corp.local\shared` (SPN: `cifs/dc01.corp.local`).
- **Local Domain Controller / KDC:** `DC-EU.eu.corp.local`.
- **Foreign Domain Controller / KDC:** `DC01.corp.local`.
- **The Shared Key:** Both DCs possess the inter-domain Trust Key: $K_{trust}$.

---

### 3.2 Diagram: The Inter-Realm Kerberos Referral Exchange

```text
  +----------------------------------------------------------------------------------------------------+
  |                           INTER-REALM KERBEROS REFERRAL PACKET FLOW                                |
  +----------------------------------------------------------------------------------------------------+

     CLIENT WORKSTATION                               LOCAL KDC                               FOREIGN KDC
     [ alice @ WKSTN01 ]                             [ DC-EU (eu.corp.local) ]               [ DC01 (corp.local) ]
              |                                                 |                                       |
              | ====== STEP 1: LOCAL TGS-REQ (SPN Not Found Locally) ================================== |
              |                                                 |                                       |
              |  1. TGS-REQ (UDP/TCP 88):                       |                                       |
              |     - Requested SPN: cifs/dc01.corp.local       |                                       |
              |     - Attached: Alice's Local TGT (krbtgt_eu)   |                                       |
              |     - Authenticator: Signed w/ Local Session Key|                                       |
              |  ---------------------------------------------> |                                       |
              |                                                 |                                       |
              |                                  [DC-EU unseals TGT with krbtgt_eu]                     |
              |                                  [DC-EU sees SPN belongs to corp.local]                 |
              |                                  [DC-EU retrieves shared Trust Key: K_trust]             |
              |                                  [DC-EU generates Referral Session Key: K_ref]          |
              |                                  [DC-EU mints Referral TGT for krbtgt/CORP.LOCAL]       |
              |                                  [Seals Referral TGT with K_trust!]                     |
              |                                                 |                                       |
              |  2. TGS-REP (Kerberos Referral):                |                                       |
              |     - Encrypted with Local Session Key:         |                                       |
              |         * Referral Session Key: K_ref           |                                       |
              |     - Encrypted with Shared Trust Key (K_trust):|                                       |
              |         * Referral TGT (Contains Alice's PAC)   |                                       |
              |  <--------------------------------------------- |                                       |
              |                                                                                         |
              | ====== STEP 2: CROSS-DOMAIN TGS-REQ (Contacting Foreign KDC) =========================== |
              |                                                                                         |
              |  3. TGS-REQ (UDP/TCP 88):                                                               |
              |     - Requested SPN: cifs/dc01.corp.local                                               |
              |     - Attached: Referral TGT (Sealed with K_trust)                                      |
              |     - Authenticator: Signed w/ Referral Session Key (K_ref)                             |
              |  -------------------------------------------------------------------------------------> |
              |                                                                                         |
              |                                                 |        [DC01 unseals Referral TGT     |
              |                                                 |         using shared Trust Key K_trust]
              |                                                 |        [DC01 validates Alice's PAC]   |
              |                                                 |        [DC01 applies SID Filtering]   |
              |                                                 |        [Generates Service Key K_svc]  |
              |                                                 |        [Mints Service Ticket sealed   |
              |                                                 |         with DC01 machine key K_DC01] |
              |                                                 |                                       |
              |  4. TGS-REP:                                                                            |
              |     - Service Ticket for cifs/dc01 (Sealed with K_DC01)                                 |
              |     - New Service Session Key (Sealed with K_ref)                                       |
              |  <------------------------------------------------------------------------------------- |
              |                                                                                         |
              | ====== STEP 3: AP EXCHANGE WITH TARGET RESOURCE ======================================= |
              |                                                                                         |
      CLIENT WORKSTATION                                                                       TARGET SERVER
     [ alice @ WKSTN01 ]                                                                      [ DC01.corp.local ]
              |                                                                                         |
              |  5. AP-REQ (TCP 445 SMB Tree Connect):                                                  |
              |     - Attached: Service Ticket (Sealed with K_DC01)                                     |
              |  -------------------------------------------------------------------------------------> |
              |                                                                 [DC01 decrypts ticket]  |
              |                                                                 [Alice accesses share!] |
              +-----------------------------------------------------------------------------------------+
```

---

### 3.3 The Referral Hop Step-by-Step

#### Step 1: Querying the Local KDC
Alice’s workstation possesses a local Ticket Granting Ticket issued by `eu.corp.local`. Alice attempts to connect to `\\dc01.corp.local\shared`.
`WKSTN01` sends a `TGS-REQ` packet to `DC-EU` specifying SPN `cifs/dc01.corp.local`.
- `DC-EU` inspects its local directory database. The computer account `DC01$` does not exist in `eu.corp.local`.
- `DC-EU` analyzes the domain suffix (`corp.local`). Because `corp.local` is the direct parent domain, an active trust relationship exists.

#### Step 2: Minting the Inter-Realm Referral TGT
Instead of returning an error, `DC-EU` generates a **Kerberos Referral**:
- It retrieves the shared **Trust Key** ($K_{trust}$) corresponding to partner domain `corp.local`.
- It generates an ephemeral **Referral Session Key** ($K_{ref}$).
- It mints a **Referral TGT** addressed to the principal `krbtgt/CORP.LOCAL`.
  - Inside this ticket, it embeds Alice's identity, her group SIDs, her PAC, and a copy of $K_{ref}$.
  - **It encrypts this entire ticket using the shared Trust Key ($K_{trust}$).**
- It sends the Referral TGT back to Alice in a `TGS-REP` message.

#### Step 3: Presenting the Referral TGT to the Foreign KDC
Alice’s workstation receives the referral. Alice cannot decrypt the ticket, but she unseals the response wrapper to obtain the Referral Session Key ($K_{ref}$).
- Alice constructs a new `TGS-REQ` packet addressed directly to the foreign Domain Controller (`DC01.corp.local`), attaching the Referral TGT and an Authenticator signed with $K_{ref}$.

#### Step 4: Foreign KDC Verification & Service Ticket Issuance
`DC01` receives Alice's request:
- `DC01` inspects the ticket header and retrieves its own copy of the shared **Trust Key** ($K_{trust}$).
- It decrypts the incoming Referral TGT. Because decryption succeeds, `DC01` has mathematical proof that this ticket was minted by an authorized partner Domain Controller (`DC-EU`).
- `DC01` extracts Alice's PAC, executes **SID Filtering** checks (detailed in Section 4), locates the local computer account `DC01$`, retrieves `DC01$`'s machine key ($K_{DC01}$), and mints a standard Service Ticket for `cifs/dc01.corp.local`.
- Alice receives the final Service Ticket and connects to `DC01` over SMB port 445 without ever transmitting a password across the network.

---

## 4. Boundary Enforcement: SID Filtering vs. Intra-Forest Trust Mechanics

Understanding trust architecture requires distinguishing between trusts that enforce hard cryptographic isolation and trusts that serve merely as administrative routing agreements.

### 4.1 Why Intra-Forest Trust is NOT a Security Boundary
Within a single Active Directory forest (between Parent-Child domains or Tree-Root domains):
- All domains share a single, unified Configuration partition and a single Schema.
- All domains are linked by automatic, two-way transitive Kerberos trusts.
- **SID Filtering is DISABLED by default.**

#### The Mechanism of SID History Escalation:
When an Active Directory user migrates from Domain A to Domain B, Active Directory populates their legacy SID into their `sIDHistory` attribute. When the user logs in, the KDC includes these historical SIDs in the `ExtraSids` buffer of the PAC so the user retains access to files in their old domain.

Because child domains inside a forest are assumed to be cooperative:
- If an adversary achieves local administrative compromise of a child domain controller (`DC-EU`), the adversary extracts the shared **Trust Key** ($K_{trust}$).
- The adversary can forge an Inter-Realm Referral TGT locally.
- **The Exploit Mechanism:** The adversary injects the **Enterprise Admins SID** (`S-1-5-21-<root>-519`) directly into the `ExtraSids` buffer of the forged ticket.
- When presented to the root Domain Controller (`DC01`), the root DC decrypts the ticket with $K_{trust}$. Because this is an intra-forest trust, **the root DC does not filter out foreign administrative SIDs**. The root DC accepts the Enterprise Admins SID and issues a ticket granting full forest compromise.

> **Architectural Law:** A child domain within a forest cannot defend itself against a compromised parent, and **a parent domain cannot defend itself against a compromised child**. The Forest remains the only true security boundary.

---

### 4.2 Why Forest Trusts WITH SID Filtering ARE a Security Boundary
When establishing a **Forest Trust** between two completely separate Active Directory forests (e.g., `corp.local` and `externalpartner.com`), Microsoft enforces **SID Filtering (Quarantine)** by default:

```text
+----------------------------------------------------------------------------------------------------+
|                               THE SID FILTERING QUARANTINE FIREWALL                                |
+----------------------------------------------------------------------------------------------------+

  FOREIGN FOREST (externalpartner.com)                                    LOCAL FOREST (corp.local)
  [ Malicious or Compromised Domain ]                                     [ Resource Forest Root KDC ]
          |                                                                       |
          |  Cross-Forest Referral TGT arriving over Forest Trust                 |
          |  -------------------------------------------------------------------> |
          |                                                                       |
          |                                  [DC01 inspects incoming PAC SIDs]    |
          |                                  [Evaluates SID Filtering Rules]:     |
          |                                                                       |
          |                                  1. Permitted Subnet Check:           |
          |                                     Does SID start with partner's     |
          |                                     domain SID: S-1-5-21-999... ?     |
          |                                     * YES -> PERMITTED (Normal User)  |
          |                                                                       |
          |                                  2. Foreign Forest Injection Check:   |
          |                                     Does PAC contain SIDs matching    |
          |                                     corp.local's Domain Admins?       |
          |                                     * VIOLATION DETECTED!             |
          |                                                                       |
          |                                  3. Well-Known RID Check:             |
          |                                     Does PAC contain RIDs < 1000?     |
          |                                     (RID 500, 502, 512, 519)          |
          |                                     * VIOLATION DETECTED!             |
          |                                                                       |
          |                                  [ACTION: STRIPS ALL MALICIOUS SIDs!] |
          |                                  [Emits Event 4675 in Security Log]   |
          |                                  [Proceeds with cleaned, safe PAC]    |
          +-----------------------------------------------------------------------+
```

#### The Rules of SID Filtering (MS-KILE / MS-PAC):
1. **Domain Namespace Verification:** The receiving KDC ensures that all SIDs in the PAC originate exclusively from the domain SID namespace assigned to the trusted partner forest.
2. **Stripping Well-Known Privileged RIDs:** Any SID possessing a Relative Identifier below `1000` (such as `500` for Administrator, `512` for Domain Admins, or `519` for Enterprise Admins) is **unconditionally stripped from the PAC**.
3. **Quarantine Enforcement:** Even if an attacker in the partner forest compromises their own forest root and injects administrative SIDs into a referral ticket, **the receiving forest's KDC removes those SIDs at the trust boundary**. The attacker cannot escalate privileges into the trusting forest.

---

### 4.3 Selective Authentication
By default, when a Forest Trust is established, **Forest-Wide Authentication** is active: any user in Forest A can authenticate to any computer in Forest B (though resource DACLs still govern file access).

Administrators can harden cross-forest relationships by enabling **Selective Authentication**:
- **Mechanism:** The KDC in Forest B will **refuse to issue a Service Ticket** for any computer in Forest B unless the incoming user explicitly possesses the **`Allowed to Authenticate`** permission (`ADS_RIGHT_DS_CONTROL_ACCESS` / `0x00000100`) on the target computer's Active Directory object!
- **Impact:** Even if a user from Forest A has valid credentials, they cannot complete an authentication handshake against servers in Forest B unless pre-approved by an administrator.

---

## 5. Defensive Telemetry, Detection Engineering & Hardening

### 5.1 Trust Security Event Telemetry
Cross-domain authentications and trust modifications emit high-priority audit events:

| Event ID | Log Name | Operational Meaning | Strategic Significance |
|:---:|:---:|:---|:---|
| **4769** | Security (DC) | A Kerberos service ticket was requested. | **Inter-Realm Telemetry:** Look for `ServiceName` starting with `krbtgt/` pointing to a foreign realm (e.g., `krbtgt/CORP.LOCAL`). |
| **4675** | Security (DC) | SIDs were filtered out of an incoming identity proof. | **High-Value Attack Marker:** Generated whenever the SID Filtering firewall detects and strips unauthorized or forged SIDs from a cross-forest referral PAC! |
| **4820** | Security (DC) | A Kerberos TGT request was denied due to Selective Authentication. | Indicates that a foreign user attempted to authenticate to a computer where they lack the `Allowed to Authenticate` permission. |
| **4706 / 4707** | Security (DC) | A new trust relationship was created or deleted. | Emitted when a Trusted Domain Object (TDO) is provisioned or removed. |

---

### 5.2 Detection Heuristics & Hunting Logic

#### 1. Detecting SID Filtering Violations (KQL):
Flags attempts to inject unauthorized cross-forest SIDs through trust boundaries:

```kusto
SecurityEvent
| where EventID == 4675
| project TimeGenerated, SubjectUserName, SubjectDomainName, TargetUserName, Computer, EventData
```

#### 2. Auditing Inter-Realm Ticket Requests (KQL):
Tracks cross-domain activity by monitoring TGS requests addressed to foreign `krbtgt` accounts:

```kusto
SecurityEvent
| where EventID == 4769
| where ServiceName startswith "krbtgt/" and ServiceName !endswith "corp.local"
| project TimeGenerated, TargetUserName, ClientAddress, ServiceName, TicketOptions
```

---

### 5.3 Enterprise Hardening Blueprint
Securing Active Directory trust relationships requires strict perimeter filtering:

1. **Enforce SID Filtering on All External Trusts:**
   - Verify that SID Filtering (Quarantine) is enabled across all non-intra-forest trusts using `netdom`:
     ```cmd
     netdom trust corp.local /Domain:externalpartner.com /FilterSIDs:Yes
     ```
2. **Disable SID History on Forest Trusts:**
   - Unless actively executing a cross-forest domain migration, explicitly disable SID History across forest trusts:
     ```cmd
     netdom trust corp.local /Domain:externalpartner.com /EnableSIDHistory:No
     ```
3. **Deploy Selective Authentication for Sensitive Resource Domains:**
   - Configure external and forest trusts to use **Selective Authentication** rather than Forest-Wide Authentication, ensuring only authorized users can authenticate to specific server objects.
4. **Isolate Administrative Forests with PAM Trusts:**
   - When deploying Red Forest / Bastion Forest architectures, use one-way incoming PAM trusts with **Shadow Principals** and strictly audited SID mapping, ensuring administrative identities never cross into untrusted user tiers.

---

## 6. Authoritative Specifications, RFCs & Cross-Vault Links

### 6.1 Authoritative Specifications
- **[MS-KILE]:** *Kerberos Protocol Extensions* — Section 3.2.5.4 details cross-realm referral ticket issuance, routing, and trust key decryption.
- **[MS-PAC]:** *Privilege Attribute Certificate Data Structure* — Section 4.1.2 defines the mathematical rules of the SID Filtering algorithm and prohibited RIDs.
- **[MS-ADTS]:** *Active Directory Technical Specification* — Section 6.1.6 defines the schema attributes and flags of `trustedDomain` objects (TDOs).
- **RFC 4120:** *The Kerberos Network Authentication Service (V5)* — Section 3.3 documents Inter-Realm authentication and referral path traversal.

