# Active Directory Enumeration Lab — BloodHound Collection over Signed LDAP

Enumerating a hardened Windows Server 2025 domain (`shaka.com`) from Kali Linux using a custom Impacket-based collector, after the stock tooling failed. Includes the collector script, the raw BloodHound-compatible dataset, an attack-path analyzer, and the findings.

> **Lab disclaimer:** everything here ran against a private, self-hosted lab (VMware). No production or third-party systems were touched. Built for learning.

## Lab setup

| Role | Details |
|---|---|
| Attacker | Kali Linux (Rolling) |
| Domain controller | `WIN-T2RBR8AQLMU` — Windows Server 2025 @ `192.168.23.142` |
| Domain | `shaka.com` |
| Bind account | `hrusr1` (low-privilege domain user) |

## The problem with stock tooling

`bloodhound-python` could not complete a collection against this DC:

1. **LDAP signing is enforced** — the DC rejects unsigned binds.
2. **LDAPS (port 636) is broken** — connections reset, so no TLS fallback.
3. **The Kerberos collection path failed** in this environment.

## What worked

A custom collector (`collector/ad_ldap_collector.py`) built on Impacket:

- Plain LDAP on **port 389** with an **NTLM bind that negotiates signing** (`NTLMSSP_NEGOTIATE_SIGN`) — satisfies the DC's signing requirement without LDAPS.
- Paged subtree searches per object class, mapped to **BloodHound legacy JSON** (importable with the classic BloodHound UI).
- Group-member DNs resolved to SIDs in a second pass, so `Members` entries carry real `ObjectIdentifier` SIDs.

```bash
pip install -r requirements.txt
python3 collector/ad_ldap_collector.py -dc 192.168.23.142 -d shaka.com -u hrusr1
# password is prompted securely via getpass — never stored
```

## Collection results

| Object class | Count |
|---|---|
| Users | 6 |
| Groups | 52 |
| Computers | 2 |
| OUs | 1 |
| GPOs | 3 |

Users found: `Administrator`, `Guest`, `krbtgt` (built-ins) plus `hr`, `hrusr1`, `student1` (custom). A custom group `CONNECTOR` contains `hr` and `hrusr1`.

## Attack-path analysis

`analysis/analyze_paths.py` builds the membership graph from the collected JSON and runs BFS from every user to the high-value groups (Domain Admins, Enterprise Admins, Schema Admins, Administrators):

```bash
python3 analysis/analyze_paths.py   # reproduces data/report.json
```

**Findings** (`data/report.json`):

- `ADMINISTRATOR → DOMAIN ADMINS`: **1 hop** (`MemberOf`). Administrator is also the sole member of Enterprise Admins and Schema Admins.
- `hr`, `hrusr1`, `student1`, `Guest`, `krbtgt`: **no membership path** to any high-value group in the collected data.

![Attack-path graph](assets/ad_graph.jpg)

## Known limitation (important)

The low-privilege bind did **not** return `nTSecurityDescriptor`, so the dataset contains **no ACL edges** (`GenericAll`, `WriteDACL`, `ForceChangePassword`, …). The graph above is complete for *membership* relationships but is **not** a complete attack-path assessment — real engagements need a privileged bind (or BloodHound's full collector) for the ACL layer.

## Repo structure

```
├── collector/
│   └── ad_ldap_collector.py   # signed-LDAP BloodHound collector (Impacket)
├── analysis/
│   └── analyze_paths.py       # membership BFS -> data/report.json
├── data/
│   ├── bloodhound_*.json      # raw collected dataset (legacy format)
│   └── report.json            # attack-path findings
├── assets/
│   └── ad_graph.png           # rendered attack-path graph
└── requirements.txt
```

## Reproduce it

1. Run the collector against your own lab DC (see usage above).
2. Import the JSON files into BloodHound, or run `analysis/analyze_paths.py` for the text report.
3. Compare membership paths before/after hardening changes (e.g. removing stale delegations).

## Takeaways

- Enforcing LDAP signing breaks naive collectors — but signed NTLM binds over port 389 still work fine for enumeration.
- A "clean" membership graph (no paths for standard users) is a good sign, but **without ACL data you cannot call the domain secure**.
- Always check *what your collector could not see*, not just what it found.
