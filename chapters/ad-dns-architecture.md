---
title: "AD-Integrated DNS Architecture — The Identity Resolution Backbone"
doc_type: "foundation"
phase: 0
phase_name: "00-Foundations"
topic: "Directory-Internals"
core_primitives: ["SRV Records", "Dynamic Updates", "Secure Dynamic Updates", "GSS-TSIG", "ADIDNS", "Wildcard Injection", "LLMNR", "NBT-NS", "Application Partitions", "dnsNode", "Zone Scavenging", "Tombstoning"]
applies_to: ["Active Directory", "DNS Server", "Netlogon", "ADIDNS", "Windows Kernel"]
status: "verified"
tags: [foundation, internals, dns, adidns, srv-records, dynamic-updates, wildcard-injection, llmnr, nbt-ns, scavenging]
---

# AD-Integrated DNS Architecture — The Identity Resolution Backbone

> **Architectural Mission:** Master the internal mechanics of Active Directory-Integrated Domain Name System (ADIDNS). Understand why Active Directory is architecturally non-viable without DNS, analyze how directory partitions host DNS zones as LDAP objects within `DomainDnsZones` and `ForestDnsZones`, dissect the Domain Controller (DC) Locator process and SRV record resolution, deconstruct Secure Dynamic Updates via GSS-TSIG, examine the scavenging and tombstoning lifecycle, and evaluate how directory access control lists (DACLs) on DNS nodes create structural network interception surfaces.

---

## 1. Architectural Foundations: Why Active Directory Cannot Function Without DNS

### 1.1 From NetBIOS Flat Broadcasts to Hierarchical Service Discovery
In the pre-Active Directory Windows NT 4.0 era, name resolution relied on flat, broadcast-heavy mechanisms: **NetBIOS over TCP/IP Name Service (NBT-NS)** and the **Windows Internet Name Service (WINS)**. These legacy protocols were fundamentally unsuited for modern distributed enterprise computing:
- They possessed no concept of organizational hierarchy or domain trees.
- They generated severe broadcast traffic storms across subnets.
- Most critically, they could not answer the core service discovery question demanded by modern distributed directories:

> *"Which specific server in this enterprise hosts the Kerberos Key Distribution Center (KDC) and LDAP directory services for my domain, and which of those servers is located closest to my physical network subnet?"*

When Microsoft engineered Active Directory Domain Services (AD DS), it made the **Domain Name System (DNS)** the mandatory, foundational backbone of the entire identity plane. In Active Directory, DNS is not merely a utility for translating hostnames to IP addresses; **it is the service discovery, topology mapping, and authentication routing engine for the entire forest**.

---

### 1.2 Standalone BIND vs. Active Directory-Integrated DNS (ADIDNS)
Traditional DNS implementations (such as standalone Berkeley Internet Name Domain [BIND] or standard file-backed DNS servers) manage zones via static text files stored on local disks. In an enterprise environment, this traditional model introduces critical single points of failure:

| Architectural Dimension | Standalone File-Backed DNS (BIND / File-Based) | Active Directory-Integrated DNS (ADIDNS) |
|:---|:---|:---|
| **Storage Engine** | Flat text files (`named.conf`, zone text files) stored on local disk. | **Directory Objects inside `ntds.dit`** (Application Naming Contexts). |
| **Replication Topology** | Single-master zone transfers (AXFR / IXFR) from a single Primary server. | **Multi-Master Replication** via the Directory Replication Service Remote Protocol (DRSUAPI). |
| **Availability / Fault Tolerance** | If the Primary DNS server goes offline, zone updates fail globally. | **Zero Single Point of Failure.** Every Domain Controller running DNS is a writable primary. |
| **Record Security** | Coarse zone-level permissions or IP-based access control. | **Granular Per-Record DACLs** via Active Directory Security Descriptors (`nTSecurityDescriptor`). |
| **Update Authentication** | Shared static TSIG keys or unauthenticated updates. | **GSS-TSIG (RFC 3645)** authenticated dynamically via **Kerberos tickets**. |

By storing DNS zones directly inside Active Directory database partitions, Microsoft eliminated the single-master bottleneck of DNS, bound name resolution directly into the Kerberos authentication boundary, and granted every individual DNS record an enterprise-grade security descriptor.

---

### 1.3 Terminology & Core Primitives (Zero-Acronym Onboarding)
- **ADIDNS (Active Directory-Integrated DNS):** A DNS zone whose database records are stored directly within the Active Directory database (`ntds.dit`) and replicated via multi-master directory replication.
- **SRV Record (Service Location Record):** A standardized DNS record type (RFC 2782) that specifies the hostname, port number, priority, and weight of servers providing specific network services (such as LDAP or Kerberos).
- **DC Locator:** The programmatic algorithm executing inside the Windows Netlogon service (`netlogon.dll` / `DsGetDcName`) that discovers, pings, and selects the optimal Domain Controller for an endpoint.
- **Dynamic DNS (DDNS):** An extension to DNS (RFC 2136) allowing client endpoints to automatically register and update their own A (IPv4) and AAAA (IPv6) address records with the DNS server.
- **GSS-TSIG (Generic Security Services Algorithm for Secret Key Transaction Authentication for DNS):** An RFC 3645 standard that uses the Generic Security Services Application Program Interface (GSS-API) and Kerberos tickets to cryptographically sign and authenticate Dynamic DNS updates.
- **Application Naming Context:** A partition within Active Directory (`DomainDnsZones` or `ForestDnsZones`) dedicated to replicating non-security application data strictly among specified Domain Controllers running DNS.
- **Scavenging:** The automated maintenance process running on Windows DNS servers that periodically purges obsolete, stale dynamic DNS records whose timestamps have expired.
- **Tombstoning:** The transitional lifecycle state where a deleted or scavenged DNS record is flagged as inactive (`dNSTombstoned = TRUE`) across directory replication before physical garbage collection.
- **GQBL (Global Query Block List):** A security feature in Windows DNS Server that refuses by default to resolve queries for high-risk protocol names such as `wpad` (Web Proxy Auto-Discovery) and `isatap` (Intra-Site Automatic Tunnel Addressing Protocol).

---

## 2. Walkthrough: The DC Locator Process in Action

### 2.1 The Enterprise Scenario Setup
To understand how an endpoint establishes identity trust upon booting up, trace this concrete sequence:
- **Client Workstation:** `WKSTN01.corp.local` (IP: `10.10.1.50`, physical location: Cairo Office).
- **Local Active Directory Site:** `HeadQuarters-Cairo` (Subnet: `10.10.0.0/16`).
- **Remote Active Directory Site:** `Europe-London` (Subnet: `10.20.0.0/16`).
- **Domain Controllers:**
  - `DC01.corp.local` (IP: `10.10.1.10`, located in `HeadQuarters-Cairo`).
  - `DC02.corp.local` (IP: `10.20.1.10`, located in `Europe-London`).

When `WKSTN01` boots up and an employee prepares to log in, **`WKSTN01` does not have any hardcoded IP address for a Domain Controller**. It relies entirely on the **DC Locator** algorithm executed by `netlogon.dll`.

---

### 2.2 Diagram: The DC Locator Resolution Sequence

```text
  +----------------------------------------------------------------------------------------------------+
  |                           THE DC LOCATOR SERVICE DISCOVERY LIFECYCLE                               |
  +----------------------------------------------------------------------------------------------------+

     CLIENT WORKSTATION                                                      AD-INTEGRATED DNS SERVER
    [ WKSTN01 (10.10.1.50) ]                                                [ DC01 (10.10.1.10) ]
             |                                                                       |
             | ====== STEP 1: INITIAL GENERIC SRV QUERY ============================ |
             |                                                                       |
             |  1. DNS Query (UDP 53) -> _ldap._tcp.dc._msdcs.corp.local             |
             |  -------------------------------------------------------------------> |
             |                                                                       |
             |                                  [DNS server queries ForestDnsZones]  |
             |                                  [Returns prioritized list of DCs]    |
             |                                                                       |
             |  2. DNS Response:                                                     |
             |     - DC01.corp.local:389 (Priority: 0, Weight: 100)                  |
             |     - DC02.corp.local:389 (Priority: 0, Weight: 100)                  |
             |  <------------------------------------------------------------------- |
             |                                                                       |
             | ====== STEP 2: UDP NETLOGON SITE DISCOVERY PING ===================== |
             |                                                                       |
             |  3. UDP Ping (UDP 389 / Netlogon Mailslot Ping)                       |
             |     - Sent directly to first DC: DC01 (10.10.1.10)                    |
             |  -------------------------------------------------------------------> |
             |                                                                       |
             |                                  [DC01 inspects caller IP: 10.10.1.50]|
             |                                  [Maps IP to Subnet 10.10.0.0/16]     |
             |                                  [Resolves Site: HeadQuarters-Cairo]  |
             |                                                                       |
             |  4. NETLOGON_SAM_LOGON_RESPONSE (UDP 389):                            |
             |     - DC Name     : DC01.corp.local                                   |
             |     - Client Site : HeadQuarters-Cairo (Discovered!)                  |
             |     - DC Site     : HeadQuarters-Cairo                                |
             |  <------------------------------------------------------------------- |
             |                                                                       |
             | ====== STEP 3: OPTIMAL SITE-SPECIFIC SRV QUERY ====================== |
             |                                                                       |
             |  5. DNS Query (UDP 53):                                               |
             |     _ldap._tcp.HeadQuarters-Cairo._sites.dc._msdcs.corp.local         |
             |  -------------------------------------------------------------------> |
             |                                                                       |
             |  6. DNS Response:                                                     |
             |     - DC01.corp.local:389 (Target DC in client's local subnet!)       |
             |  <------------------------------------------------------------------- |
             |                                                                       |
             | ====== STEP 4: AUTHENTICATION CHANNEL ESTABLISHMENT ================= |
             |                                                                       |
             |  7. TCP Connect to DC01 on Port 88 (Kerberos AS-REQ)                  |
             |  -------------------------------------------------------------------> |
             | [Client authenticates successfully against closest geographic DC!]    |
             +-----------------------------------------------------------------------+
```

---

### 2.3 The Critical SRV Record Hierarchy
When Active Directory initializes, the Netlogon service on every Domain Controller automatically compiles and registers a structured hierarchy of SRV records. These records are published under the **`_msdcs`** subdomain (e.g., `_msdcs.corp.local`):

1. **Generic Domain Controller Locator:**
   `_ldap._tcp.dc._msdcs.corp.local`
   - Maps to port `389`. Used by any domain client to locate any available DC in the domain.
2. **Site-Specific Domain Controller Locator:**
   `_ldap._tcp.<SiteName>._sites.dc._msdcs.corp.local`
   - Example: `_ldap._tcp.HeadQuarters-Cairo._sites.dc._msdcs.corp.local`.
   - Restricts resolution strictly to Domain Controllers physically located within the caller's geographic site, eliminating cross-WAN latency and bandwidth bottlenecks.
3. **Kerberos Key Distribution Center Locator:**
   `_kerberos._tcp.dc._msdcs.corp.local`
   - Maps to port `88`. Used by Kerberos clients to locate the KDC for ticket granting.
4. **Primary Domain Controller (PDC) Emulator Locator:**
   `_ldap._tcp.pdc._msdcs.corp.local`
   - Locates the single DC holding the PDC Emulator Flexible Single Master Operation (FSMO) role. Essential for urgent password change verification, GPO edits, and domain time synchronization.
5. **Global Catalog Locator:**
   `_gc._tcp.<SiteName>._sites.corp.local`
   - Maps to port `3268`. Used to locate Global Catalog servers for forest-wide identity searches and universal group membership expansion during logon.

---

## 3. The Physical Reality: How DNS Records Exist in LDAP

### 3.1 The Storage Partitions: `DomainDnsZones` and `ForestDnsZones`
In Windows 2000, AD-Integrated DNS zones were stored inside the standard Domain Naming Context (`DC=corp,DC=local`). This created an operational flaw: DNS records replicated to *every* Domain Controller in the domain, even if that DC was not configured as a DNS server.

Starting in Windows Server 2003, Microsoft transitioned ADIDNS into **Application Naming Contexts**:

```text
+----------------------------------------------------------------------------------------------------+
|                         ADIDNS DIRECTORY PARTITION ARCHITECTURE                                    |
+----------------------------------------------------------------------------------------------------+

  1. ForestDnsZones PARTITION
  ====================================================================================================
  - Directory Path   : DC=ForestDnsZones,DC=corp,DC=local
  - Replication Scope: Replicates to EVERY Domain Controller running DNS across the ENTIRE forest.
  - Primary Contents : The forest-wide root discovery zone:
                       _msdcs.corp.local

  2. DomainDnsZones PARTITION
  ====================================================================================================
  - Directory Path   : DC=DomainDnsZones,DC=corp,DC=local
  - Replication Scope: Replicates to all Domain Controllers running DNS within THIS specific domain.
  - Primary Contents : The domain's forward and reverse lookup zones:
                       corp.local
                       10.10.in-addr.arpa
+----------------------------------------------------------------------------------------------------+
```

---

### 3.2 The `dnsNode` Object Class
Every DNS record stored inside an AD-Integrated zone is an actual, physical object in the directory database (`ntds.dit`). 
- **Object Class:** **`dnsNode`**
- **Container Path:**
  `DC=<RecordName>,DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local`

For example, workstation `WKSTN01`'s address record is stored at:
`DC=WKSTN01,DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local`

#### Critical Attributes of a `dnsNode` Object:
1.  **`dnsRecord` (Octet String / Binary BLOB):**
   Stores the raw binary representation of the DNS resource record per **[MS-DNSP] §2.2.2.2.4**:
   - Record Type (e.g., `0x0001` for Type A, `0x0021` for Type SRV, `0x0005` for Type CNAME).
   - Serial Number and Versioning.
   - Time-to-Live (TTL).
   - IP Address or Target FQDN string.
2. **`dNSTombstoned` (Boolean):**
   Set to `TRUE` when a record has expired or been deleted, marking it for scavenging.
3. **`nTSecurityDescriptor` (Binary Security Descriptor):**
   **Every single DNS record in ADIDNS possesses its own Discretionary Access Control List (DACL)!**
   - When `WKSTN01$` dynamically registers its DNS record, `WKSTN01$`'s computer SID is stamped as the **Owner** of the `dnsNode` object, granting it full write permissions (`GenericAll`) over its own record.
   - Standard domain users (`Authenticated Users`) do not have write access to `WKSTN01`'s record, preventing a malicious user from modifying another machine's IP address.

---

## 4. Dynamic Updates: Non-Secure vs. Secure (GSS-TSIG)

### 4.1 Non-Secure Dynamic Updates (RFC 2136)
- **The Mechanism:** An unauthenticated DNS client sends a raw UDP `DNS UPDATE` packet (Opcode 5) to the DNS server instructing it to add or modify an A record:
  `"Map server01.corp.local to 10.10.1.99"`
- **The Failure Mode:** Non-secure updates perform **zero authentication**. The DNS server does not verify who sent the packet. Any host on the network can claim any hostname, overwrite records belonging to Domain Controllers, and hijack corporate traffic. Non-secure updates should **never** be permitted in an enterprise environment.

---

### 4.2 Secure Dynamic Updates via GSS-TSIG (RFC 3645)
Windows Active Directory environments enforce **Secure Dynamic Updates Only**. Under this policy, dynamic DNS updates are cryptographically bound to Kerberos:

```text
+----------------------------------------------------------------------------------------------------+
|                         GSS-TSIG SECURE DYNAMIC UPDATE FLOW                                        |
+----------------------------------------------------------------------------------------------------+

  CLIENT WORKSTATION (WKSTN01$)                                           AD-INTEGRATED DNS SERVER
          |                                                                       |
          | ====== STEP 1: TKEY NEGOTIATION (Kerberos AP-REQ) =================== |
          |                                                                       |
          |  1. TKEY Query (Negotiates GSS-API Security Context)                  |
          |     - Attaches Kerberos Service Ticket for DNS/dc01.corp.local        |
          |  -------------------------------------------------------------------> |
          |                                                                       |
          |                                  [DNS server decrypts Kerberos Ticket]
          |                                  [Extracts WKSTN01$ Computer Identity]
          |                                  [Derives Shared Session Key: K_session]
          |                                                                       |
          |  2. TKEY Response (Confirms context establishment)                    |
          |  <------------------------------------------------------------------- |
          |                                                                       |
          | ====== STEP 2: SIGNED DNS UPDATE TRANSACTION ======================== |
          |                                                                       |
          |  3. DNS UPDATE Packet:                                                |
          |     - Resource Record: WKSTN01.corp.local -> 10.10.1.50               |
          |     - TSIG Record: HMAC signature computed using K_session            |
          |  -------------------------------------------------------------------> |
          |                                                                       |
          |                                  [DNS verifies HMAC signature]        |
          |                                  [DNS queries LDAP for dnsNode DACL]  |
          |                                  [Checks if WKSTN01$ has Write access]|
          |                                                                       |
          |                                  * If record doesn't exist:           |
          |                                    Creates dnsNode, sets Owner=WKSTN01$
          |                                  * If record exists and Owner matches:
          |                                    Updates IP address in ntds.dit!    |
          |                                                                       |
          |  4. DNS UPDATE Response: STATUS_SUCCESS (RCODE: 0)                    |
          |  <------------------------------------------------------------------- |
          +-----------------------------------------------------------------------+
```

1. **TKEY Exchange:** The client contacts the DNS server and initiates a Transaction Key (`TKEY`) exchange using Kerberos (`GSS-SPNEGO`), presenting a Service Ticket for the SPN `DNS/dc01.corp.local`.
2. **Session Key Derivation:** Both parties derive an ephemeral symmetric session key ($K_{session}$).
3. **Signed Transaction (`TSIG`):** The client transmits the `DNS UPDATE` packet with a Transaction Signature (`TSIG`) record containing an HMAC calculated using the session key.
4. **Directory ACL Enforcement:** The DNS server verifies the HMAC signature, confirms the caller is genuinely `WKSTN01$`, and evaluates the DACL on the `dnsNode` object in LDAP. If the caller has permission, the record is committed to `ntds.dit`.

---

## 5. Zone Scavenging and the Tombstoning Lifecycle

In a dynamic enterprise network where laptops change IP addresses across Wi-Fi networks and virtual machines are frequently decommissioned, DNS zones would rapidly accumulate thousands of stale, orphaned records without automated cleanup.

### 5.1 The Scavenging Time Windows
Windows DNS Server manages dynamic record cleanup through **Aging and Scavenging**, governed by two sequential intervals:

```text
+----------------------------------------------------------------------------------------------------+
|                                  DNS RECORD AGING & SCAVENGING TIMELINE                            |
+----------------------------------------------------------------------------------------------------+

  [ Time 0: Record Registered ] -> Timestamp T_0
  |
  |=================== NO-REFRESH INTERVAL (Default: 7 Days) ===================|
  | - The client CANNOT update the record's timestamp.                          |
  | - If the client sends an update with the same IP, DNS accepts but DOES NOT  |
  |   modify the timestamp in ntds.dit.                                         |
  | - Purpose: Minimizes Active Directory multi-master replication traffic!     |
  |                                                                             |
  |---> [ Day 7: No-Refresh Ends, Refresh Interval Begins ]                     |
        |
        |===================== REFRESH INTERVAL (Default: 7 Days) =====================|
        | - The client CAN update the record's timestamp.                              |
        | - If the client refreshes, the timestamp resets to current time (T_new),     |
        |   and the cycle resets back to the No-Refresh Interval!                      |
        |                                                                              |
        \---> [ Day 14: Refresh Interval Expires -> RECORD IS NOW STALE! ]             |
              |
              v
  [ Scavenging Period (Default: Runs Every 7 Days on Scavenging Server) ]
  - The designated Scavenging Server scans the zone.
  - Detects records whose age > (No-Refresh + Refresh) [14 Days].
  - Sets dNSTombstoned = TRUE on the dnsNode object in LDAP.
  - Active Directory replication propagates the tombstone.
  - After the tombstone lifetime expires, the object is permanently deleted.
+----------------------------------------------------------------------------------------------------+
```

- **Static Records (Timestamp = 0):** Records created manually by administrators have a timestamp of `0`. **Static records are never scavenged**, ensuring critical servers, routers, and infrastructure records persist indefinitely.

---

## 6. Architectural Vulnerability Primitives (Zero Tool Dumping)

Security vulnerabilities in Active Directory-Integrated DNS stem directly from **default directory permissions, unhardened fallbacks, and zone configuration oversights**.

### 6.1 The Open Creation Boundary: `CreateChild` for `Authenticated Users`
- **The Design Principle:** To allow any domain-joined laptop or workstation to dynamically register its own hostname, Microsoft configured the default DACL on ADIDNS zone containers (`DC=corp.local,CN=MicrosoftDNS,...`) with:
  `Grant Authenticated Users: CreateChild (dnsNode)`
- **The Friction Point:** The permission is **not restricted to computer accounts**. Any standard domain user account (`CORP\ahmed`) possesses the exact same directory right to create new `dnsNode` objects inside the corporate zone!
- **The Architectural Consequence:**
  An adversary with standard user credentials can query the zone for non-existent records and register arbitrary A records (e.g., creating `legit-portal.corp.local` pointing to an attacker-controlled IP). When internal corporate users attempt to navigate to that portal, DNS resolves it directly to the attacker's server, enabling credential harvesting and man-in-the-middle attacks.

---

### 6.2 Wildcard Injection (`*` Records)
- **The Mechanics:** In DNS, an asterisk (`*`) represents a wildcard record. If a client queries DNS for a name that does not exist (e.g., `internal-reporting-app.corp.local`), the DNS server checks if a wildcard record exists (`*.corp.local`). If present, the DNS server returns the IP address specified in the wildcard record.
- **The Architectural Consequence:** Because standard users can create records in ADIDNS, an attacker creates an object named `*` in the zone pointing to their own machine. Any mistyped URL, failed internal service connection, or unresolved internal hostname across the entire enterprise resolves directly to the attacker.

---

### 6.3 The WPAD Hijack Surface
- **The Protocol:** Windows systems utilize **Web Proxy Auto-Discovery (WPAD)** to automatically discover corporate web proxies by querying DNS for the hostname:
  `wpad.corp.local`
- **The Friction Point:** If an organization does not utilize a proxy server, the record `wpad.corp.local` does not exist in the zone.
- **The Defense & Bypass:** Microsoft introduced the **Global Query Block List (GQBL)**, instructing Windows DNS Server to refuse resolution for `wpad` by default. However, if an administrator disables the GQBL, or if an attacker registers the record directly as a `dnsNode` object in LDAP, endpoints automatically route corporate HTTP/HTTPS traffic through the attacker's listener, capturing Net-NTLM challenge-response authentications.

---

## 7. Defensive Telemetry, Detection Engineering & Hardening

### 7.1 DNS Security Event Telemetry
Monitoring DNS activity requires collecting both Directory Service audit events and Windows DNS Server audit logs:

| Event ID | Log Name | Operational Meaning | Strategic Significance |
|:---:|:---:|:---|:---|
| **5136** | Security (DC) | A directory service object was modified. | **High-Value:** Generated when a `dnsNode` object's IP address (`dnsRecord`) or permissions (`nTSecurityDescriptor`) are modified in LDAP. |
| **5137** | Security (DC) | A directory service object was created. | Tracks the creation of new `dnsNode` objects (detects unauthorized record creation or wildcard injection). |
| **541** | DNS Server / Audit | A dynamic update was processed. | Logs client IP, updated record name, and update status. |

---

### 7.2 Detection Heuristics & Hunting Logic

#### 1. Detecting Wildcard or WPAD DNS Node Creation (KQL):
Detects the creation of high-risk DNS records within Active Directory Application Partitions:

```kusto
SecurityEvent
| where EventID == 5137
| where ObjectDN has "CN=MicrosoftDNS"
| where ObjectDN has "DC=*" or ObjectDN has "DC=wpad"
| project TimeGenerated, SubjectUserName, SubjectDomainName, ObjectDN
```

#### 2. Detecting Non-Machine Accounts Creating DNS Records (KQL):
Standard dynamic DNS updates are generated by computer accounts ending with `$`. Flags any record creation initiated by human user accounts:

```kusto
SecurityEvent
| where EventID == 5137
| where ObjectDN has "CN=MicrosoftDNS"
| where SubjectUserName !endswith "$" // Flag human user accounts
| where SubjectUserName !in ("SYSTEM", "Administrator")
| project TimeGenerated, SubjectUserName, ObjectDN
```

---

### 7.3 Enterprise Hardening Blueprint
Securing AD-Integrated DNS requires enforcing cryptographic update policies and cleaning default permissions:

1. **Enforce "Secure Only" Dynamic Updates:**
   - On all AD-Integrated zones, set Dynamic Updates to **Secure only**. Never allow non-secure updates.
2. **Restrict Container Creation Rights:**
   - Modify the DACL on `CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local` and `CN=MicrosoftDNS,DC=ForestDnsZones,DC=corp,DC=local`.
   - Remove `CreateChild` rights from `Authenticated Users` or restrict them to a specific security group composed exclusively of domain computer accounts.
3. **Verify Global Query Block List (GQBL) Enforcement:**
   - Ensure the Global Query Block List is active on all DNS servers:
     ```powershell
     Get-DnsServerGlobalQueryBlockList
     # Verify that 'wpad' and 'isatap' are listed and enabled
     ```
4. **Pre-Create a Static WPAD Record:**
   - If your organization does not use WPAD, create an empty static `wpad.corp.local` A record pointing to a non-routable loopback address (`127.0.0.1`) with a static timestamp of `0`. This permanently prevents attackers from creating the record in the zone.

---

## 8. Authoritative Specifications, RFCs & Cross-Vault Links

### 8.1 Authoritative Specifications
- **RFC 2782:** *A DNS RR for specifying the location of services (DNS SRV)* — The foundation for Active Directory service discovery.
- **RFC 2136:** *Dynamic Updates in the Domain Name System (DNS UPDATE)*.
- **RFC 3645:** *Generic Security Service Algorithm for Secret Key Transaction Authentication for DNS (GSS-TSIG)* — Formal specification for Kerberos-signed DNS updates.
- **[MS-DNSP]:** *Domain Name System (DNS) Server Management Protocol* — Microsoft specification detailing the binary structure of `dnsRecord` attributes and `dnsNode` object classes in LDAP.
