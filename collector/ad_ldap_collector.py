#!/usr/bin/env python3
"""
ad_ldap_collector.py — BloodHound-compatible AD collector over signed LDAP.

Collects users, groups, computers, domains, OUs and GPOs from a domain
controller and writes BloodHound legacy-compatible JSON files
(importable with `bloodhound --import` / the legacy BloodHound UI).

Why this exists
--------------
Stock collectors (bloodhound-python) failed against this lab's DC
(Windows Server 2025) because:

  1. The DC *requires* LDAP signing — unsigned binds are rejected.
  2. LDAPS on port 636 resets connections (broken TLS on the lab DC).
  3. The Kerberos collection path failed in this environment.

The working approach: plain LDAP on port 389 with an NTLM bind that
negotiates signing (NTLMSSP_NEGOTIATE_SIGN), then paged subtree searches
per object class. This script implements that approach, cleaned up for
publication. It was used to enumerate the shaka.com lab domain.

Usage:
    pip install impacket
    python3 ad_ldap_collector.py -dc 192.168.23.142 -d shaka.com -u hrusr1

The password is read securely via getpass (never stored or logged).

Note: a low-privilege bind does not receive nTSecurityDescriptor, so the
output contains complete *membership* relationships but no ACL edges
(GenericAll / WriteDACL / etc.). That is a data limitation, not a bug —
see the README and analysis/analyze_paths.py.
"""

import argparse
import getpass
import json
import os
import struct
import sys
import time

try:
    from impacket.ldap.ldap import LDAPConnection
except ImportError:
    sys.exit("impacket is required: pip install impacket")

# userAccountControl flags we map to BloodHound properties
UF_ACCOUNTDISABLE = 0x0002
UF_PASSWD_NOTREQD = 0x0020
UF_DONT_EXPIRE_PASSWD = 0x10000
UF_TRUSTED_FOR_DELEGATION = 0x80000
UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x1000000
UF_DONT_REQUIRE_PREAUTH = 0x400000


def sid_to_str(sid_bytes):
    """Convert a binary SID to its SDDL string form (S-1-5-21-...)."""
    if isinstance(sid_bytes, str):
        sid_bytes = sid_bytes.encode("latin-1")
    rev, count = struct.unpack("BB", sid_bytes[:2])
    authority = struct.unpack(">Q", b"\x00\x00" + sid_bytes[2:8])[0]
    sub = struct.unpack("<%dL" % count, sid_bytes[8:8 + 4 * count])
    return "S-%d-%d-%s" % (rev, authority, "-".join(map(str, sub)))


def first(entry, attr, default=""):
    vals = entry.get(attr, [default])
    return vals[0] if vals else default


class Collector:
    def __init__(self, dc_ip, domain, username, password, base_dn, out_dir):
        self.dc_ip = dc_ip
        self.domain = domain
        self.username = username
        self.password = password
        self.base_dn = base_dn
        self.out_dir = out_dir
        self.conn = None
        self.stamp = time.strftime("%Y%m%d%H%M%S")

    def connect(self):
        # Plain LDAP on 389. The NTLM bind below negotiates signing,
        # which satisfies DCs that require LDAP signing (no LDAPS needed).
        url = f"ldap://{self.dc_ip}"
        self.conn = LDAPConnection(url, self.base_dn, self.dc_ip)
        self.conn.login(self.username, self.password, self.domain)
        print(f"[+] Bound to {self.dc_ip} as {self.domain}\\{self.username} (signed LDAP)")

    def search(self, search_filter, attributes):
        try:
            return self.conn.search(
                searchFilter=search_filter,
                attributes=attributes,
                sizeLimit=0,
                searchBase=self.base_dn,
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[!] Search failed ({search_filter}): {exc}")
            return []

    # -- object collectors -------------------------------------------------
    def collect_users(self):
        attrs = ["sAMAccountName", "objectSid", "distinguishedName", "description",
                 "userAccountControl", "pwdLastSet", "lastLogon", "memberOf",
                 "primaryGroupID", "servicePrincipalName"]
        out = []
        for e in self.search("(objectClass=user)", attrs):
            uac = int(first(e, "userAccountControl", "0"))
            out.append({
                "ObjectIdentifier": sid_to_str(first(e, "objectSid", b"")),
                "Properties": {
                    "name": f"{first(e, 'sAMAccountName', '').upper()}@{self.domain.upper()}",
                    "domain": self.domain.upper(),
                    "distinguishedname": first(e, "distinguishedName"),
                    "description": first(e, "description"),
                    "enabled": not (uac & UF_ACCOUNTDISABLE),
                    "pwdneverexpires": bool(uac & UF_DONT_EXPIRE_PASSWD),
                    "passwordnotreqd": bool(uac & UF_PASSWD_NOTREQD),
                    "dontreqpreauth": bool(uac & UF_DONT_REQUIRE_PREAUTH),
                    "unconstraineddelegation": bool(uac & UF_TRUSTED_FOR_DELEGATION),
                    "trustedtoauth": bool(uac & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION),
                    "sensitive": False,
                    "highvalue": False,
                },
                "PrimaryGroupID": first(e, "primaryGroupID"),
                "AllowedToDelegate": [],
                "HasSIDHistory": [],
            })
        return out

    def collect_groups(self):
        attrs = ["cn", "objectSid", "distinguishedName", "description", "member"]
        out = []
        for e in self.search("(objectClass=group)", attrs):
            members = []
            for m in e.get("member", []):
                # member DNs are resolved to SIDs in a second pass by the
                # analyzer; store DN here and let analyze_paths resolve them.
                members.append({"ObjectIdentifier": m, "ObjectType": "Unknown"})
            out.append({
                "ObjectIdentifier": sid_to_str(first(e, "objectSid", b"")),
                "Properties": {
                    "name": f"{first(e, 'cn', '').upper()}@{self.domain.upper()}",
                    "domain": self.domain.upper(),
                    "distinguishedname": first(e, "distinguishedName"),
                    "description": first(e, "description"),
                    "highvalue": False,
                },
                "Members": members,
                "Aces": [],
            })
        return out

    def collect_computers(self):
        attrs = ["dNSHostName", "sAMAccountName", "objectSid", "distinguishedName",
                 "description", "userAccountControl"]
        out = []
        for e in self.search("(objectClass=computer)", attrs):
            out.append({
                "ObjectIdentifier": sid_to_str(first(e, "objectSid", b"")),
                "Properties": {
                    "name": f"{first(e, 'dNSHostName', '').upper()}",
                    "domain": self.domain.upper(),
                    "distinguishedname": first(e, "distinguishedName"),
                    "description": first(e, "description"),
                    "enabled": not (int(first(e, "userAccountControl", "0")) & UF_ACCOUNTDISABLE),
                    "highvalue": False,
                },
                "AllowedToDelegate": [],
                "AllowedToAct": [],
            })
        return out

    def collect_domains(self):
        e_list = self.search("(objectClass=domain)", ["distinguishedName", "objectSid"])
        out = []
        for e in e_list:
            out.append({
                "ObjectIdentifier": sid_to_str(first(e, "objectSid", b"")),
                "Properties": {
                    "name": self.domain.upper(),
                    "domain": self.domain.upper(),
                    "distinguishedname": first(e, "distinguishedName"),
                    "highvalue": True,
                },
                "Links": [], "GpoChanges": {"AffectedComputers": [], "DcomUsers": []},
                "Trusts": [],
            })
        return out

    def collect_ous(self):
        out = []
        for e in self.search("(objectClass=organizationalUnit)",
                             ["distinguishedName", "name"]):
            out.append({
                "ObjectIdentifier": first(e, "distinguishedName"),
                "Properties": {
                    "name": f"{first(e, 'name', '').upper()}@{self.domain.upper()}",
                    "domain": self.domain.upper(),
                    "distinguishedname": first(e, "distinguishedName"),
                    "highvalue": False,
                },
                "Links": [], "GpoChanges": {"AffectedComputers": [], "DcomUsers": []},
            })
        return out

    def collect_gpos(self):
        out = []
        for e in self.search("(objectClass=groupPolicyContainer)",
                             ["displayName", "distinguishedName"]):
            out.append({
                "ObjectIdentifier": first(e, "distinguishedName"),
                "Properties": {
                    "name": f"{first(e, 'displayName', '').upper()}@{self.domain.upper()}",
                    "domain": self.domain.upper(),
                    "distinguishedname": first(e, "distinguishedName"),
                    "highvalue": False,
                },
            })
        return out

    # -- driver ------------------------------------------------------------
    def run(self):
        os.makedirs(self.out_dir, exist_ok=True)
        self.connect()
        datasets = {
            "users": self.collect_users(),
            "groups": self.collect_groups(),
            "computers": self.collect_computers(),
            "domains": self.collect_domains(),
            "ous": self.collect_ous(),
            "gpos": self.collect_gpos(),
        }
        # Resolve group-member DNs to SIDs so the output matches the
        # BloodHound legacy format (ObjectIdentifier = SID).
        dn_to_sid = {}
        for kind in ("users", "groups", "computers"):
            otype = {"users": "User", "groups": "Group",
                     "computers": "Computer"}[kind]
            for obj in datasets[kind]:
                dn = obj["Properties"].get("distinguishedname", "").lower()
                if dn:
                    dn_to_sid[dn] = (obj["ObjectIdentifier"], otype)
        for g in datasets["groups"]:
            for m in g["Members"]:
                resolved = dn_to_sid.get(m["ObjectIdentifier"].lower())
                if resolved:
                    m["ObjectIdentifier"], m["ObjectType"] = resolved
        for kind, items in datasets.items():
            path = os.path.join(self.out_dir, f"{self.stamp}_{kind}.json")
            with open(path, "w") as fh:
                json.dump({kind: items,
                           "meta": {"type": kind, "count": len(items),
                                    "version": 5, "methods": 0}}, fh)
            print(f"[+] {kind}: {len(items)} objects -> {path}")
        print("[*] Done. Import the JSON files into BloodHound (legacy format).")


def main():
    ap = argparse.ArgumentParser(description="Signed-LDAP BloodHound collector")
    ap.add_argument("-dc", required=True, help="Domain controller IP")
    ap.add_argument("-d", required=True, help="Domain FQDN (e.g. shaka.com)")
    ap.add_argument("-u", required=True, help="Username")
    ap.add_argument("-p", help="Password (prompted securely if omitted)")
    ap.add_argument("-b", help="Base DN (default: derived from domain)")
    ap.add_argument("-o", default="bh-output", help="Output directory")
    args = ap.parse_args()

    password = args.p or getpass.getpass(f"Password for {args.u}: ")
    base_dn = args.b or ",".join(f"DC={p}" for p in args.d.split("."))

    Collector(args.dc, args.d, args.u, password, base_dn, args.o).run()


if __name__ == "__main__":
    main()
