#!/usr/bin/env python3
"""
analyze_paths.py — Membership attack-path analysis for BloodHound legacy JSON data.

Reads the collected BloodHound files in ../data/ and, for every domain user,
finds the shortest MemberOf path to any high-value admin group
(Domain Admins, Enterprise Admins, Schema Admins, Administrators).

Reproduces data/report.json. Run from this directory:
    python3 analyze_paths.py
"""

import json
import os
from collections import deque

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")

HIGH_VALUE_GROUPS = {
    "DOMAIN ADMINS@SHAKA.COM",
    "ENTERPRISE ADMINS@SHAKA.COM",
    "SCHEMA ADMINS@SHAKA.COM",
    "ADMINISTRATORS@SHAKA.COM",
}


def load(name):
    with open(os.path.join(DATA_DIR, name)) as fh:
        return json.load(fh)


def main():
    users = load("bloodhound_users.json")["users"]
    groups = load("bloodhound_groups.json")["groups"]

    # SID -> display name for users and groups
    names = {}
    for u in users:
        names[u["ObjectIdentifier"]] = u["Properties"]["name"]
    for g in groups:
        names[g["ObjectIdentifier"]] = g["Properties"]["name"]

    # member SID -> set of parent group SIDs (handles nested groups)
    member_of = {}
    for g in groups:
        gid = g["ObjectIdentifier"]
        for m in g.get("Members", []):
            member_of.setdefault(m["ObjectIdentifier"], set()).add(gid)

    high_value_sids = {
        g["ObjectIdentifier"]
        for g in groups
        if g["Properties"]["name"] in HIGH_VALUE_GROUPS
    }

    def shortest_path(user_sid):
        """BFS from user through group nesting to any high-value group."""
        queue = deque([(user_sid, [user_sid])])
        seen = {user_sid}
        while queue:
            sid, path = queue.popleft()
            if sid in high_value_sids:
                return [names.get(s, s).split("@")[0] for s in path], len(path) - 1
            for parent in member_of.get(sid, ()):  # noqa: E731
                if parent not in seen:
                    seen.add(parent)
                    queue.append((parent, path + [parent]))
        return None

    report = {"paths": {}, "ace_edges": []}
    for u in users:
        uname = u["Properties"]["name"].split("@")[0]
        found = shortest_path(u["ObjectIdentifier"])
        if found:
            path_names, hops = found
            report["paths"][uname] = {
                "target": path_names[-1].replace(" ", " "),
                "hops": hops,
                "path": path_names,
                "edges": ["MemberOf"] * hops,
            }
        else:
            report["paths"][uname] = None

    out_path = os.path.join(DATA_DIR, "report.json")
    with open(out_path, "w") as fh:
        json.dump(report, fh, indent=1)
    print(f"Wrote {out_path}")
    for user, path in report["paths"].items():
        if path:
            print(f"  {user}: {' -> '.join(path['path'])} ({path['hops']} hop)")
        else:
            print(f"  {user}: no path to high-value group")


if __name__ == "__main__":
    main()
