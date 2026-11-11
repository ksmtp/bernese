#!/usr/bin/env python3
"""
bernese - BloodHound attack-path explorer

An interactive terminal tool for triaging BloodHound CE / RustHound-CE data and
piecing together Active Directory privilege-escalation paths that the BloodHound
GUI doesn't surface on its own.

Run it with just `-d <data>` to drop into the interactive app (pick a start node,
browse the attack tree, escalation routes, rights, etc.). If the optional
`textual` + `rich` packages are installed you get the full-screen TUI; otherwise
it falls back to a stdlib curses menu. The subcommands below always work for
one-off / scripted use with zero third-party packages.

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

Python 3.8+. The CLI + curses menu are stdlib-only; the full TUI additionally
needs `pip install textual rich`.
"""

import argparse
import codecs
import contextlib
import io
import json
import os
import sys
import zipfile
from collections import defaultdict, deque

__version__ = "1.0"

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
def _kc(key):
    """A highlighted key 'chip': bold black on bright-cyan background."""
    return C.w(f" {key} ", "1;30;106")

def _navbar(pairs, lead="\n  "):
    """Render a consistent legend/prompt bar from (key, label) pairs — chips in
    colour, labels in bold, never dim. Returns a string ready to pass to input()."""
    return lead + "   ".join(_kc(k) + " " + bold(lbl) for k, lbl in pairs) + bold(cyan("   › "))

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
    "519": "Enterprise Admins", "520": "Group Policy Creator Owners",
    "521": "Read-only Domain Controllers", "526": "Key Admins",
    "527": "Enterprise Key Admins", "502": "krbtgt",
}
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

def technique(right, target_kind, target_name):
    k = (target_kind or "").lower()
    tn = bold(target_name)
    esc = {
        "ESC1": f"ESC1: enroll a cert with an arbitrary SAN -> authenticate as any user (DA) -> {tn}",
        "ESC2": f"ESC2: enroll an Any-Purpose cert -> impersonate any user -> {tn}",
        "ESC3": f"ESC3: get an Enrollment Agent cert, then enroll on behalf of a DA -> {tn}",
        "ESC4": f"ESC4: rewrite the template to be ESC1, then enroll as a DA -> {tn}",
        "ESC9": f"ESC9: no-security-extension cert + weak mapping -> impersonate a DA -> {tn}",
    }
    if right in esc:
        return esc[right]
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
            return "Domain object (full compromise)"
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
            if n.kind == "Domain":
                for psid, rights in repl_by.items():
                    if ("GetChanges" in rights and "GetChangesAll" in rights) or "DCSync" in rights:
                        self.add_edge(psid, sid, "DCSync")
            for a in n.admins:
                self.add_edge(a, sid, "AdminTo")
            for a in n.allowed_to_act:
                self.add_edge(a, sid, "AllowedToAct")

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
    else:
        raise SystemExit(red(f"[!] Don't know how to read: {path}"))

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
    http = []
    for e in _get(obj, "HttpEnrollmentEndpoints", default=[]) or []:
        r = e.get("Result") if isinstance(e, dict) else e
        if not r:
            continue
        if isinstance(r, str):
            http.append(r)
        elif isinstance(r, dict):                       # {url/ADCSWebEnrollmentHTTP/...}
            url = (r.get("url") or r.get("Url") or r.get("URL")
                   or r.get("ADCSWebEnrollmentHTTP") or r.get("ADCSWebEnrollmentHTTPS"))
            http.append(str(url) if url else str(r))
        elif isinstance(r, list):
            http.extend(str(x) for x in r if x)
        else:
            http.append(str(r))
    san = crd.get("IsUserSpecifiesSanEnabled") if isinstance(crd, dict) else None
    if isinstance(san, dict):
        san = san.get("Value") if san.get("Collected") else None
    return {"name": p.get("name", "?"), "props": p, "aces": aces + casec,
            "casecurity": casec, "user_san": san, "http": http}

def _ekus(tmpl):
    e = tmpl["props"].get("effectiveekus") or tmpl["props"].get("ekus") or []
    return [str(x) for x in e] if isinstance(e, list) else []

def _truthy(v):
    return v is True or str(v).lower() in ("true", "1", "yes")

def _is_admin(g, sid):
    if g.is_highvalue(sid):
        return True
    rid = sid.rsplit("-", 1)[-1]
    if rid in ("500", "512", "519", "518", "520", "516", "502"):
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
        if n.kind == "Group" and sid.rsplit("-", 1)[-1] in ("512", "519", "518", "516", "520"):
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

# interesting, non-default, non-blank user property fields worth showing
_USER_FIELDS = [
    ("description", "desc"), ("title", "title"), ("email", "email"),
    ("displayname", "display"), ("pwdlastset", "pwdset"),
    ("lastlogontimestamp", "lastlogon"), ("useraccountcontrol", "uac"),
]

def _user_detail_lines(g, n):
    """Non-blank, interesting fields for a user, as 'key = value' strings."""
    out = []
    for key, short in [("description", "description"), ("title", "title"),
                       ("email", "email"), ("displayname", "displayname")]:
        v = n.p(key)
        if v not in (None, "", []):
            out.append(f"{short} = {v}")
    return out

def analyze_adcs(g):
    domain = g.domain_sids[0] if g.domain_sids else None

    def expand(psid):
        out = {psid}
        n = g.nodes.get(psid)
        if n and n.kind == "Group":
            for m in _expand_members(g, psid):
                out.add(m)
        return out

    for t in g.templates:
        p = t["props"]
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
        if domain and (set(escs) & {"ESC1", "ESC2", "ESC3", "ESC9"}):
            code = next(c for c in escs if c in ("ESC1", "ESC2", "ESC3", "ESC9"))
            for e in enrollers:
                en = g.nodes.get(e)
                if en and en.kind in ("User", "Computer"):
                    g.add_edge(e, domain, code)
                    g.esc_branches.append((code, e, t["name"]))
        if domain and "ESC4" in escs:
            for e in write_abusers:
                en = g.nodes.get(e)
                if en and en.kind in ("User", "Computer"):
                    g.add_edge(e, domain, "ESC4")
                    g.esc_branches.append(("ESC4", e, t["name"]))

    for ca in g.cas:
        abusers = set()
        for psid, right in ca["aces"]:
            if right in ("ManageCA", "ManageCertificates"):
                for e in expand(psid):
                    en = g.nodes.get(e)
                    if en and en.kind in ("User", "Group") and not _is_admin(g, e):
                        abusers.add(e)
        ca["esc7"] = abusers

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

def load(path):
    g = Graph()
    total = len(_json_member_names(path)) or 1
    seen_files = 0
    for fname, blob in _iter_json(path):
        seen_files += 1
        _progress(f"loading [{seen_files}/{total}] {os.path.basename(fname)} …")
        if not isinstance(blob, dict):
            continue
        meta = blob.get("meta", {}) or {}
        data = blob.get("data", []) or []
        kind = _kind_from(meta.get("type"), fname)
        for obj in data:
            if not isinstance(obj, dict):
                continue
            if kind == "CertTemplate":
                g.templates.append(_mk_template(obj))
                continue
            if kind == "EnterpriseCA":
                g.cas.append(_mk_ca(obj))
                continue
            if kind in ("RootCA", "NTAuthStore", "IssuancePolicy", "AIACA"):
                continue
            sid = _get(obj, "ObjectIdentifier", "objectid", "ObjectId")
            if not sid:
                continue
            sid = str(sid)
            n = g.node(sid)
            if n.kind == "Base":
                n.kind = kind
            props = _get(obj, "Properties", default={}) or {}
            n.props = {str(k).lower(): v for k, v in props.items()}
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
            la = _get(obj, "LocalAdmins", default=None)
            if isinstance(la, dict):
                for r in la.get("Results", []) or []:
                    rid = _get(r, "ObjectIdentifier", "objectid")
                    if rid:
                        n.admins.append(str(rid))
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
            sess = _get(obj, "Sessions", default=None)
            if isinstance(sess, dict):
                sess = sess.get("Results", []) or []
            for r in (sess or []):
                u = _get(r, "UserSID", "UserSid") if isinstance(r, dict) else None
                if u:
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
    return pubs

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
    return [base]

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
        if ca.get("http"):
            print(red("      ESC8: HTTP enrollment endpoint(s): "
                      + ", ".join(str(x) for x in ca["http"])))
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
    primary_tgt = targets[0] if targets else (None, "<ADMIN_SID>", "administrator@" + dom.lower(), "")

    vuln = [t for t in g.templates if t.get("escs")]
    def _abusers(t):
        ab = t.get("enrollers", set()) if (set(t["escs"]) & {"ESC1", "ESC2", "ESC3", "ESC9"}) else set()
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
        print(red("      enroll as    : NON-admin principals (own one => domain compromise):"))
        for a in interesting:
            sid = a
            print(f"            {green(g.nodes[a].name)}   {dim(sid)}")
        if admins:
            print(dim(f"      (also enrollable by admins: {', '.join(admins)})"))
        # ready-to-adapt certipy — use the first non-admin enroller + the primary target
        code = next((c for c in ("ESC1", "ESC4", "ESC3", "ESC2", "ESC9") if c in t["escs"]), t["escs"][0])
        ca = pubs[0] if pubs else (g.cas[0] if g.cas else None)
        caname = _ca_name(ca) if ca else "<CA_NAME>"
        cahost = _ca_host(ca) if ca else "<CA_HOST>"
        enroller = _login_name(g, interesting[0], dom) if interesting else f"<you>@{dom}"
        print(cyan(f"      certipy {code}:"))
        for line in _certipy_lines(code, dom, caname, cahost, cn, enroller,
                                   primary_tgt[2], primary_tgt[1]):
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
    if right in ("ESC1", "ESC2", "ESC3", "ESC4", "ESC9"):
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

_GLYPH = {"User": ("U", green), "Group": ("G", yellow), "Computer": ("C", blue),
          "Domain": ("D", mag), "GPO": ("P", cyan)}

def _glyph(g, sid):
    n = g.nodes.get(sid)
    sym, col = _GLYPH.get(n.kind if n else "", ("?", lambda s: s))
    return col(f"[{sym}]")

# ACL takeover rights that should visually jump out in a tree
_DANGER = {"ForceChangePassword", "GenericAll", "GenericWrite", "WriteDacl",
           "WriteOwner", "Owns", "Owner", "AddKeyCredentialLink", "AllExtendedRights",
           "AddMember", "AddSelf", "WriteSPN", "WriteAccountRestrictions",
           "ReadGMSAPassword", "ReadLAPSPassword"}

def _edge_render(lbl):
    """Colour an edge label by danger so ACL abuse stands out from membership."""
    if lbl.startswith("ESC") or lbl in ("DCSync", "AdminTo", "AllowedToAct", "GPOAbuse"):
        return bold(red(lbl))
    if lbl == "MemberOf":
        return dim("memberof")
    if lbl in _DANGER:
        return bold(mag(lbl))
    return yellow(lbl)

def _node_tags(g, sid, owned=None):
    tags = []
    if owned and sid in owned:
        tags.append(bold(green("✓ OWNED")))
    hv = g.is_highvalue(sid)
    if hv:
        tags.append(red(f"★ {hv}"))
    n = g.nodes.get(sid)
    if n:
        is_kerb = (n.kind == "User"
                   and (n.p("hasspn") or n.p("serviceprincipalnames"))
                   and sid.rsplit("-", 1)[-1] != "502")
        if is_kerb:
            enc = _A_plain(_roast_enc_tag(n)[0])
            if hv or sid in _priv_set(g):
                tags.append(bold(red(f"⚠ ROASTABLE ADMIN ({enc})")))
            else:
                tags.append(bold(red(f"⚑ Kerberoastable ({enc})")))
        if n.p("dontreqpreauth"):
            tags.append(bold(red("⚑ AS-REP")))
        d = n.p("description")
        if d:
            tags.append(dim(f'"{str(d)[:50]}"'))
    return "  " + "  ".join(tags) if tags else ""

def _build_tree(g, starts, max_depth=12, max_nodes=600, fanout=12):
    """BFS spanning tree from one sid or a set of sids (multi-source).

    When a single node has more than `fanout` outbound edges of the SAME label
    (e.g. one group that can ReadLAPSPassword on 1000 computers), those targets
    are recorded as a compressed BUNDLE instead of being expanded as individual
    nodes — so they don't blow the node cap and every such group still shows."""
    if isinstance(starts, str):
        starts = [starts]
    seen = set(starts)
    children = defaultdict(list)
    bundles = defaultdict(list)              # parent sid -> [(label, [target sids])]
    depth = {s: 0 for s in starts}
    q = deque(starts)
    truncated = False
    while q:
        cur = q.popleft()
        if depth[cur] >= max_depth:
            continue
        bylabel = defaultdict(list)
        for (nxt, lbl) in g.ctrl.get(cur, []):
            bylabel[lbl].append(nxt)
        stop = False
        for lbl, targets in bylabel.items():
            if lbl != "MemberOf" and len(targets) > fanout:
                bundles[cur].append((lbl, targets))     # compress — don't expand/recurse
                continue
            for nxt in targets:
                if nxt in seen:
                    continue
                if len(seen) >= max_nodes:
                    truncated = True
                    stop = True
                    break
                seen.add(nxt)
                depth[nxt] = depth[cur] + 1
                children[cur].append((nxt, lbl))
                q.append(nxt)
            if stop:
                break
        if stop:
            break
    return children, bundles, truncated, seen

def _foothold_note(g, sid):
    n = g.nodes.get(sid)
    notes = []
    if n and (n.p("hasspn") or n.p("serviceprincipalnames")) and sid.rsplit("-", 1)[-1] != "502":
        notes.append("Kerberoastable (SPN set) — roast the TGS offline")
    if n and n.p("dontreqpreauth"):
        notes.append("AS-REP roastable (no pre-auth)")
    return notes

def _render_tree(g, roots, owned=None, title="Attack tree", expand_bundles=False):
    owned = owned or set()
    header(title)
    children, bundles, truncated, seen = _build_tree(g, list(roots))
    reached_hv = []
    had_bundle = [False]
    priv = _priv_set(g)

    def _bundle_line(prefix, conn, lbl, targets):
        """One compressed line for a big same-label fan-out (e.g. LAPS on 1000 hosts)."""
        had_bundle[0] = True
        hv_t = [t for t in targets if g.is_highvalue(t)]
        for t in hv_t:
            reached_hv.append(t)
        kind = (g.nodes[targets[0]].kind if g.nodes.get(targets[0]) else "object")
        plural = {"Computer": "computers", "User": "users", "Group": "groups"}.get(kind, "objects")
        tech = _tech_short(lbl, kind)
        names = sorted((g.nodes[t].name.split("@")[0] for t in targets if g.nodes.get(t)), key=str.lower)
        print(f"  {prefix}{dim(conn)} {_edge_render(lbl)} "
              + bold(f"{len(targets)} {plural}") + (f"   {dim('· ' + tech)}" if tech else ""))
        sub = prefix + "    "
        if kind == "Computer":
            # which of these hosts are actually worth it: a DC, or a privileged
            # user exposes creds there (session / local admin)
            juicy = [(t, _computer_value(g, t, priv)[1]) for t in targets]
            juicy = [(t, tg) for t, tg in juicy if tg]
            if juicy:
                print(f"  {sub}{bold(red('★ ' + str(len(juicy)) + ' worth popping here '))}"
                      + dim("(read LAPS / local admin → steal those creds):"))
                for t, tags in sorted(juicy, key=lambda e: (not _is_dc(g, e[0]), g.nodes[e[0]].name))[:8]:
                    print(f"  {sub}  {blue(g.nodes[t].name.split('@')[0])}  {red('· ' + ' · '.join(tags))}")
                if len(juicy) > 8:
                    print(f"  {sub}  {dim('… +' + str(len(juicy) - 8) + ' more — press x to list all')}")
        elif hv_t:
            hv_names = sorted({g.nodes[t].name.split('@')[0] for t in hv_t}, key=str.lower)
            shown = ", ".join(hv_names[:10]) + (f" … +{len(hv_names) - 10}" if len(hv_names) > 10 else "")
            print(f"  {sub}{bold(red('★ ' + str(len(hv_t)) + ' high-value here: '))}{bold(red(shown))}")
        if expand_bundles:
            for nm in names:
                print(f"  {sub}{dim(nm)}")
        else:
            sample = ", ".join(names[:6]) + (f" … +{len(names) - 6} more" if len(names) > 6 else "")
            print(f"  {sub}{dim(sample)}")
            if len(names) > 6:
                print(f"  {sub}{dim('(press x to list all, or inspect the group with i)')}")

    def rec(sid, prefix):
        kids = children.get(sid, [])
        bnd = bundles.get(sid, [])
        total = len(kids) + len(bnd)
        for i, (c, lbl) in enumerate(kids):
            last = (i == total - 1)
            conn = "└──" if last else "├──"
            cn = g.nodes.get(c)
            note = _tech_short(lbl, cn.kind if cn else "")
            note_s = f"   {dim('· ' + note)}" if note else ""
            name = g.nodes[c].name.split("@")[0] if cn else c
            hv = g.is_highvalue(c)
            goal = bold(red("   ⟹ FULL DOMAIN COMPROMISE")) if (cn and cn.kind == "Domain") else ""
            is_priv = bool(hv) or c in priv
            namecol = f"{_glyph(g, c)} " + (bold(red(name)) if is_priv else name)
            print(f"  {prefix}{dim(conn)} {_edge_render(lbl)} {namecol}"
                  f"{_node_tags(g, c, owned)}{note_s}{goal}")
            if hv:
                reached_hv.append(c)
            rec(c, prefix + ("    " if last else dim("│") + "   "))
        for j, (lbl, targets) in enumerate(bnd):
            last = (len(kids) + j == total - 1)
            _bundle_line(prefix, "└──" if last else "├──", lbl, targets)

    roots = list(roots)
    for root in roots:
        rn = g.nodes.get(root)
        if not rn:
            continue
        print(f"\n  {_glyph(g, root)} {bold(green(rn.name.split('@')[0]))}{_node_tags(g, root, owned)}")
        for note in _foothold_note(g, root):
            print(dim(f"      ↳ potential foothold: {note}"))
        adminto = [d for (d, l) in g.ctrl.get(root, []) if l == "AdminTo"]
        if adminto:
            print(bold(red("      ↳ local admin on: "))
                  + red(", ".join(sorted(g.nodes[d].name.split("@")[0] for d in adminto if g.nodes.get(d)))))
        if not children.get(root) and not bundles.get(root):
            print(dim("      (no outbound control — can't take over anything via ACLs here)"))
        rec(root, "")

    if truncated:
        print(dim("\n  … tree truncated at the node cap; narrow the start node(s)."))
    if reached_hv:
        print(bold(green("\n  ⇒ Reaches high-value: "
                         + ", ".join(sorted({g.nodes[s].name.split('@')[0] for s in reached_hv})))))
    else:
        print(bold(yellow("\n  ⚑ No high-value target reached by ACL from here.")))

    # Anything a plain domain user can do regardless of ACLs (privileged ones flagged)
    priv = _priv_set(g)
    rootset = set(roots)

    def _roast_name(s):
        nm = g.nodes[s].name.split("@")[0]
        return bold(red(nm + " ⚠")) if (s in priv or g.is_highvalue(s)) else green(nm)

    roast = [s for s in g.nodes if g.nodes[s].kind == "User"
             and (g.nodes[s].p("hasspn") or g.nodes[s].p("serviceprincipalnames"))
             and s.rsplit("-", 1)[-1] != "502" and s not in rootset]
    asrep = [s for s in g.nodes if g.nodes[s].kind == "User" and g.nodes[s].p("dontreqpreauth")]
    roast.sort(key=lambda s: (s not in priv, g.nodes[s].name))
    asrep.sort(key=lambda s: (s not in priv, g.nodes[s].name))
    if roast or asrep:
        print(bold(cyan("\n  Reachable by any domain user (no ACL needed):")))
        if roast:
            print(f"    Kerberoast:  {', '.join(_roast_name(s) for s in roast)}  {dim('(⚠ = privileged)')}")
        if asrep:
            print(f"    AS-REP:      {', '.join(_roast_name(s) for s in asrep)}")

    _print_esc_branches(g, exclude_reachable=seen)

    if had_bundle[0] and not expand_bundles and sys.stdin.isatty():
        try:
            ans = input(_navbar([("x", "list every target in the compressed rows"),
                                 ("Enter", "continue")])).strip().lower()
        except EOFError:
            ans = ""
        if ans == "x":
            _render_tree(g, roots, owned, title, expand_bundles=True)
            return reached_hv
    return reached_hv

def print_attack_tree(g, start, owned=None, expand_bundles=False):
    sn = g.nodes.get(start)
    if not sn:
        print(red("  unknown node"))
        return
    _render_tree(g, [start], owned, f"Attack tree — what you can do as {sn.name.split('@')[0]}",
                 expand_bundles=expand_bundles)

def print_combined_tree(g, owned):
    """Multi-source tree from every owned node, plus chains between owned nodes."""
    roots = sorted(owned, key=lambda s: g.nodes[s].name if s in g.nodes else s)
    names = ", ".join(g.nodes[s].name.split("@")[0] for s in roots if s in g.nodes)
    _render_tree(g, roots, set(owned), f"Combined attack surface — OWNED: {names}")
    # chains between owned principals
    chains = []
    for a in roots:
        reach = g.reachable(a)
        for b in roots:
            if b != a and b in reach:
                chains.append((a, b, reach[b][0], reach[b][1]))
    if chains:
        print(bold(cyan("\n  Chains between owned principals:")))
        for a, b, hops, lbl in chains:
            print(f"    {green(g.nodes[a].name.split('@')[0])} {dim('──' + str(hops) + 'h▶')} "
                  f"{green(g.nodes[b].name.split('@')[0])}  {dim('(leverage one to pivot to the other)')}")

def print_escalation_overview(g, owned=None, expand=False, allow_prompt=True):
    """High-level routes to high-value. Condensed by default; [x] expands the
    long lists. Credential wins (roast-a-DA / DCSync / LAPS / ESC) are called out
    separately from ACL chains because on an engagement those are usually the path."""
    owned = owned or set()
    header("Escalation overview — routes to a high-value target")
    da_set = _da_member_set(g)

    # --- compute ACL routes from each launch point (owned, else non-admin users)
    launch = [s for s in owned] if owned else [
        n.sid for n in g.nodes.values() if n.kind == "User" and not _is_admin(g, n.sid)]
    routes = []                                  # (src, hv_sid, hops, via)
    for s in launch:
        if s not in g.nodes:
            continue
        reach = g.reachable(s)
        hits = [h for h in reach if h != s and g.is_highvalue(h)]
        if hits:
            b = min(hits, key=lambda h: reach[h][0])
            routes.append((s, b, reach[b][0], reach[b][1]))
    routes.sort(key=lambda r: (r[2], g.nodes[r[0]].name))

    scope = "from OWNED" if owned else "from any non-admin account"
    if routes:
        src, b, hops, _ = routes[0]
        path = g.bfs_path(src, b)
        chain = "  →  ".join((g.nodes[x].name.split("@")[0] if g.nodes.get(x) else x)
                             for x, _ in (path or []))
        print(bold(yellow(f"  ★ FASTEST ACL WIN ({scope}, {hops} hop(s)):")))
        print(f"     {green(g.nodes[src].name.split('@')[0])}  ⇒  {red(g.is_highvalue(b))}")
        print(dim(f"     {chain}\n"))

    # --- credential wins (no ACL chain needed) --------------------------------
    print(bold("  ● Credential wins (out-of-band — usually the real path):"))
    any_cred = False
    priv_roast = [n for n in g.nodes.values() if n.kind == "User"
                  and (n.p("hasspn") or n.p("serviceprincipalnames"))
                  and n.sid.rsplit("-", 1)[-1] != "502"
                  and (n.sid in da_set or g.is_highvalue(n.sid) or n.p("admincount"))]
    for n in priv_roast:
        any_cred = True
        print(f"     {bold(red('⚠ ROAST'))} {green(n.name.split('@')[0])} {_roast_enc_tag(n)[0]}"
              f"{_priv_roast_tag(g, n.sid, da_set)}  {_optref(7)}")
    dcs = sorted({(g.nodes[s].name.split('@')[0] if s in g.nodes else (_sid_hint(s) or s))
                  for d in g.domain_sids for (s, l) in g.rctrl.get(d, [])
                  if (l == "DCSync" or l in REPL_RIGHTS) and not _is_default_dcsync(g, s)})
    if dcs:
        any_cred = True
        print(f"     {bold(red('⚠ DCSync'))} {green(', '.join(dcs))} "
              f"{dim('→ dump every hash in the domain')}  {_optref(12)}")
    laps = defaultdict(set)
    for r, c in _laps_readers(g):
        laps[r].add(c)
    # which LAPS readers does your OWNED set actually hold (member of that group)?
    own_closure = set()
    for o in owned:
        own_closure |= _principal_closure(g, o)
    # yours first, then by how many hosts
    laps_sorted = sorted(laps.items(), key=lambda kv: (kv[0] not in own_closure, -len(kv[1])))
    for r, cs in (laps_sorted if expand else laps_sorted[:6]):
        any_cred = True
        yours = bold(green("  ✓ YOU HOLD THIS")) if r in own_closure else ""
        print(f"     {bold(red('⚠ LAPS'))} {green(g.nodes[r].name.split('@')[0])} "
              f"{dim('→ local admin on ' + str(len(cs)) + ' host(s)')}  {_optref(17)}{yours}")
    if not expand and len(laps_sorted) > 6:
        print(dim(f"     … +{len(laps_sorted) - 6} more LAPS readers (expand)"))
    if owned and laps and not any(r in own_closure for r in laps):
        print(dim("     (none of the LAPS readers above are groups your owned set is in)"))
    if not any_cred:
        print(dim("     (none)"))

    _print_esc_branches(g)                        # ADCS ESC branches

    # --- ACL paths, bucketed by distance --------------------------------------
    quick = [r for r in routes if r[2] <= 2]
    med = [r for r in routes if 3 <= r[2] <= 5]
    far = [r for r in routes if r[2] > 5]

    def line(r):
        src, b, hops, via = r
        return (f"       {green(g.nodes[src].name.split('@')[0])} "
                f"{dim('— ' + str(hops) + 'h via ' + str(via) + ' ▶ ')}{red(g.is_highvalue(b))}")

    print(bold(f"\n  ● ACL control paths to high-value  ({len(routes)} start point(s)):"))
    if quick:
        print(dim(f"     quick (≤2 hops) — {len(quick)}:"))
        for r in (quick if expand else quick[:15]):
            print(line(r))
        if not expand and len(quick) > 15:
            print(dim(f"       … +{len(quick) - 15} more (expand)"))
    if med:
        print(dim(f"     medium (3–5 hops) — {len(med)}:"))
        for r in (med if expand else med[:5]):
            print(line(r))
        if not expand and len(med) > 5:
            print(dim(f"       … +{len(med) - 5} more (expand)"))
    if far:
        print(dim(f"     long (>5 hops) — {len(far)}" + ("" if expand else "  (expand to list)")))
        if expand:
            for r in far:
                print(line(r))
    if not routes:
        print(dim("     (none reach high-value by ACL alone — use the credential wins above)"))

    # --- footholds (counts, not a wall of names) ------------------------------
    kerb = [n for n in g.nodes.values() if n.kind == "User"
            and (n.p("hasspn") or n.p("serviceprincipalnames")) and n.sid.rsplit("-", 1)[-1] != "502"]
    asrep = [n for n in g.nodes.values() if n.kind == "User" and n.p("dontreqpreauth")]
    rc4 = sum(1 for n in kerb if "RC4" in _enc_types(n))
    aes = sum(1 for n in kerb if _enc_types(n) and "RC4" not in _enc_types(n))
    unk = len(kerb) - rc4 - aes
    print(bold("\n  ● Footholds any domain user can grab:"))
    print(f"     kerberoastable: {bold(str(len(kerb)))}  "
          f"{dim('(' + str(rc4) + ' RC4, ' + str(aes) + ' AES-only, ' + str(unk) + ' enc-unset)')}  {_optref(7)}")
    print(f"     AS-REP roastable: {bold(str(len(asrep)))}  {_optref(8)}")

    truncated = (not expand) and (len(quick) > 15 or len(med) > 5 or bool(far)
                                  or len(laps_sorted) > 6)
    if allow_prompt and truncated and sys.stdin.isatty():
        try:
            ans = input(_navbar([("x", "expand full detail"), ("b", "back")])).strip().lower()
        except EOFError:
            ans = ""
        if ans == "x":
            print_escalation_overview(g, owned, expand=True, allow_prompt=False)
            return
    print("\n  " + dim("Tip: set a listed account as start") + " " + _kc("s")
          + " " + dim("then view its attack tree") + " " + _kc("2"))

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

_JUICY_RIGHTS = ("DCSync", "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
                 "Owns", "ForceChangePassword", "AddKeyCredentialLink", "AddMember",
                 "AdminTo", "AllowedToAct", "ReadLAPSPassword", "ReadGMSAPassword",
                 "GPOAbuse", "WriteSPN", "AllExtendedRights")

def _group_priv_summary(g, gsid):
    """Short note on what belonging to this group grants (notable rights / HV)."""
    if g.is_highvalue(gsid):
        return red(f"★ {g.is_highvalue(gsid)}")
    cnt = defaultdict(int)
    for (_dst, l) in g.ctrl.get(gsid, []):
        if l != "MemberOf":
            cnt[l] += 1
    bits = [f"{k}×{cnt[k]}" for k in _JUICY_RIGHTS if cnt.get(k)]
    if bits:
        return red("grants " + ", ".join(bits[:4]))
    _, _, best = _user_profile(g, gsid)
    if best:
        return red(f"→ reaches ★ {best[0]} in {best[1]}h")
    return ""

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

def print_node_detail(g, sid, full=False):
    n = g.nodes.get(sid)
    if not n:
        print(red("  unknown node"))
        return
    cap = None if full else 20
    truncated = False
    header(f"{n.name}   [{n.kind}]")
    hv = g.is_highvalue(sid)
    if hv:
        print(red(f"  ★ HIGH-VALUE: {hv}"))
    fl = flags_for(g, n)
    if fl:
        print("  " + fl)
    print(bold("\n  Properties:"))
    for key, lab in _DETAIL_FIELDS:
        v = n.p(key)
        if v not in (None, "", [], False) or (key == "enabled" and v is False):
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            elif key in ("pwdlastset", "lastlogontimestamp", "whencreated"):
                v = _fmt_ts(v)
            print(f"    {dim(lab + ':'):<28} {v}")
    # SPNs are only actionable on USER accounts (kerberoastable). A computer's host
    # SPNs are noise — its password is machine-managed and uncrackable — so skip them.
    spns = n.p("serviceprincipalnames")
    if spns and n.kind == "User":
        print(f"    {dim('SPNs:')}")
        for s in (spns if isinstance(spns, list) else [spns]):
            print(f"        {s}")

    # Roast / privilege callout (actionable, up top)
    notes = []
    if n.kind == "User" and (n.p("hasspn") or n.p("serviceprincipalnames")) and sid.rsplit("-", 1)[-1] != "502":
        enc, hint = _roast_enc_tag(n)
        adm = " " + red("ROASTABLE ADMIN ⚠") if (hv or sid in _priv_set(g)) else ""
        notes.append(f"Kerberoastable ({_A_plain(enc)}){adm} — {hint}")
    if n.p("dontreqpreauth"):
        notes.append("AS-REP roastable — hashcat -m 18200")
    if sid in _priv_set(g) and not hv:
        notes.append("member of a privileged group (effectively admin)")
    for nt in notes:
        print(red(f"  ⚠ {nt}"))

    # Member of — direct AND nested, high-value groups flagged (like the tree)
    closure = _principal_closure(g, sid)
    direct = set(_direct_groups(g, sid))
    grp_sids = [d for d in closure
                if d != sid and g.nodes.get(d) and g.nodes[d].kind == "Group"]
    grp_sids.sort(key=lambda s: (not bool(g.is_highvalue(s)), g.nodes[s].name))
    if grp_sids:
        print(bold(f"\n  Member of ({len(grp_sids)} incl. nested) — what each grants you:"))
        for d in (grp_sids if full else grp_sids[:cap]):
            nm = g.nodes[d].name.split("@")[0]
            hvg = g.is_highvalue(d)
            name = bold(red(nm)) if hvg else nm
            via = "" if d in direct else dim(" (nested)")
            summ = _group_priv_summary(g, d)
            print(f"    {name}{via}" + (f"   {summ}" if summ else ""))
        if not full and len(grp_sids) > cap:
            truncated = True
            print(dim(f"    … +{len(grp_sids) - cap} more  (press x to expand)"))

    # Where this leads — nearest high-value + overall reach
    size, hvreach, best = _user_profile(g, sid)
    print(bold("\n  Where this leads:"))
    if hv:
        print(red(f"    this node IS high-value: {hv}"))
    elif best:
        print(red(f"    shortest path to ★ {best[0]}  ({best[1]} step{'s' if best[1] != 1 else ''}):"))
        reach = g.reachable(sid)
        hvs = [s for s in reach if s != sid and g.is_highvalue(s)]
        target = min(hvs, key=lambda s: reach[s][0]) if hvs else None
        path = g.bfs_path(sid, target) if target else None
        for i, (psid, lbl) in enumerate(path or []):
            nm = g.nodes[psid].name.split("@")[0] if psid in g.nodes else (_sid_hint(psid) or psid)
            if i == 0:
                print(f"      {dim('you are here:')} {green(nm)}")
            else:
                star = red(" ★") if g.is_highvalue(psid) else ""
                print(f"      {dim(str(i) + '.')} {yellow(lbl)} -> {nm}{star}")
    if size:
        kinds = defaultdict(int)
        for s in g.reachable(sid):
            if s != sid and g.nodes.get(s):
                kinds[g.nodes[s].kind] += 1
        brk = ", ".join(f"{kinds[k]} {k.lower()}(s)" for k in ("User", "Computer", "Group") if kinds[k])
        print(f"    can ultimately control {bold(str(size))} node(s)" + (dim("  (" + brk + ")") if brk else ""))
    elif not hv and not best:
        print(dim("    controls nothing further via ACLs"))

    outbound = g.ctrl.get(sid, [])
    acl_out = [(d, l) for (d, l) in outbound if l != "MemberOf"]
    if acl_out:
        print(bold(f"\n  Controls ({len(acl_out)}):"))
        rows = sorted(acl_out, key=lambda e: g.nodes.get(e[0], Node(e[0])).name)
        for dst, lbl in (rows if full else rows[:cap]):
            print(f"    {_edge_render(lbl)}  {dim('->')}  {g.label(dst)}")
        if not full and len(acl_out) > cap:
            truncated = True
            print(dim(f"    … +{len(acl_out) - cap} more  (press x to expand)"))

    if n.kind == "Group":
        priv = _priv_set(g)
        mem = [m for m in _expand_members(g, sid)
               if g.nodes.get(m) and g.nodes[m].kind in ("User", "Computer")]
        mem.sort(key=lambda s: (s not in priv and not g.is_highvalue(s), g.nodes[s].name))
        print(bold(f"\n  Members ({len(mem)}):"))
        if not mem:
            print(dim("    (no user/computer members — may contain only nested groups)"))
        for m in (mem if full else mem[:cap]):
            mn = g.nodes[m]
            is_priv = m in priv or g.is_highvalue(m)
            kerb = (mn.kind == "User" and (mn.p("hasspn") or mn.p("serviceprincipalnames"))
                    and m.rsplit("-", 1)[-1] != "502")
            tags = (red(" ⚠ privileged") if is_priv else "") + (red(" [roastable]") if kerb else "")
            print(f"    {g.label(m)}{tags}")
        if not full and len(mem) > cap:
            truncated = True
            print(dim(f"    … +{len(mem) - cap} more  (press x to expand)"))

    if n.kind == "User":
        adminon = sorted({d for (d, l) in g.ctrl.get(sid, [])
                          if l == "AdminTo" and g.nodes.get(d) and g.nodes[d].kind == "Computer"},
                         key=lambda s: g.nodes[s].name)
        sess_on = sorted((c for c, cn in g.nodes.items()
                          if cn.kind == "Computer" and sid in cn.sessions),
                         key=lambda s: g.nodes[s].name)
        if adminon or sess_on:
            print(bold("\n  Machines this user is tied to:"))
            for items, lab, col in ((adminon, "local admin on", red),
                                    (sess_on, "has a session on", yellow)):
                if not items:
                    continue
                shown = ", ".join(g.nodes[c].name.split("@")[0]
                                  for c in (items if full else items[:cap]))
                tail = "" if (full or len(items) <= cap) else dim(f"  … +{len(items) - cap} more")
                if not full and len(items) > cap:
                    truncated = True
                print(f"    {col(lab)} ({len(items)}): {blue(shown)}{tail}")
            print(dim("    (local admin → dump creds there; a live session → steal that token / TGT)"))

    if n.kind == "User":
        macs = _user_machine_accounts(g, sid)
        if g.maq is not None or macs:
            print(bold("\n  Machine accounts / MAQ:"))
            if g.maq is not None:
                mq = red(str(g.maq)) if isinstance(g.maq, int) and g.maq > 0 else str(g.maq)
                print(f"    domain MachineAccountQuota = {mq}")
            if macs:
                print("    owns/created: "
                      + blue(", ".join(sorted(g.nodes[c].name.split('@')[0] for c in macs)))
                      + dim("  (owner of a computer = full control → RBCD / Shadow Creds)"))
            else:
                print(dim("    this user owns no computer objects in the data"))

    if n.kind == "GPO":
        comps = g.gpo_affects.get(sid, set())
        print(bold(f"\n  Linked to / affects ({len(comps)} computer(s)):"))
        if comps:
            print("    " + ", ".join(sorted(g.nodes[c].name.split("@")[0] for c in comps)))
            print(dim("    (control of this GPO = code execution as SYSTEM on all of the above)"))
        else:
            print(dim("    (not linked to any computers)"))

    if n.kind == "Computer" and n.sessions:
        print(bold("\n  Sessions (logged-on users):"))
        for u in (n.sessions if full else n.sessions[:cap]):
            print(f"    {g.label(u)}")
        if not full and len(n.sessions) > cap:
            truncated = True
            print(dim(f"    … +{len(n.sessions) - cap} more  (press x to expand)"))
    adminto = [a for (a, l) in g.rctrl.get(sid, []) if l == "AdminTo"]
    if n.kind == "Computer" and adminto:
        print(bold("\n  Local admins:"))
        for a in (adminto if full else adminto[:cap]):
            print(f"    {g.label(a)}")
        if not full and len(adminto) > cap:
            truncated = True
            print(dim(f"    … +{len(adminto) - cap} more  (press x to expand)"))

    if truncated and sys.stdin.isatty():
        # biggest list on this node is what a filter actually helps with
        if n.kind == "Group":
            findable = [m for m in _expand_members(g, sid)
                        if g.nodes.get(m) and g.nodes[m].kind in ("User", "Computer")]
            findlabel = "Members of " + n.name.split("@")[0]
        else:
            findable = [d for (d, l) in g.ctrl.get(sid, []) if l != "MemberOf"]
            findlabel = n.name.split("@")[0] + " controls"
        pairs = [("x", "expand all lists")]
        if len(findable) > 20:
            pairs.insert(0, ("f", "find / filter the long list"))
        pairs.append(("b", "back"))
        try:
            ans = input(_navbar(pairs)).strip().lower()
        except EOFError:
            ans = ""
        if ans == "x":
            print_node_detail(g, sid, full=True)
        elif ans == "f" and len(findable) > 20:
            _browse_nodes(g, findlabel, findable)

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

def _capture(fn, *a):
    """Run a print-producing function with colour off, return the plain text."""
    old = C.enabled
    C.enabled = False
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            fn(*a)
    finally:
        C.enabled = old
    return buf.getvalue()

def _names_only(g, kind, predicate=None):
    """Print bare object names (samaccountname-ish), one per line, no other data."""
    names = sorted({(g.nodes[s].name.split("@")[0])
                    for s, n in g.nodes.items()
                    if n.kind == kind and (predicate is None or predicate(n))},
                   key=str.lower)
    for nm in names:
        print(nm)

def export_flow(g, start, owned):
    dom = (g.domain_name or "domain").lower()
    _kerb = lambda n: (n.p("hasspn") or n.p("serviceprincipalnames")) and n.sid.rsplit("-", 1)[-1] != "502"
    da_set = _da_member_set(g)
    items = [
        ("1", "users", "Domain users (full detail)", lambda: cmd_users(g, _A())),
        ("2", "domain-admins", "Domain admins & high-value groups", lambda: cmd_das(g, _A())),
        ("3", "kerberoastable", "Kerberoastable accounts", lambda: cmd_kerberoastable(g, _A())),
        ("4", "asreproastable", "AS-REP roastable accounts", lambda: cmd_asreproastable(g, _A())),
        ("5", "computers", "Computers (full detail)", lambda: cmd_computers(g, _A())),
        ("6", "groups", "Groups", lambda: cmd_groups(g, _A())),
        ("7", "spns", "SPN / service accounts", lambda: cmd_spns(g, _A())),
        ("8", "dcsync", "DCSync principals", lambda: cmd_dcsync(g, _A())),
        ("9", "adcs", "ADCS / ESC", lambda: cmd_adcs(g, _A())),
        ("10", "delegation", "Delegation", lambda: cmd_delegation(g, _A())),
        ("14", "domain-controllers", "Domain controllers", lambda: cmd_dcs(g, _A())),
        ("15", "maq", "MachineAccountQuota & user-owned machines", lambda: cmd_maq(g, _A())),
        ("16", "password-policy", "Domain password policy", lambda: cmd_pwpolicy(g, _A())),
        ("11", "summary", "Domain summary", lambda: cmd_summary(g, _A())),
        ("12", "escalation", "Escalation overview", lambda: print_escalation_overview(g, owned, expand=True, allow_prompt=False)),
        ("13", "everything", "EVERYTHING (summary + findings)", None),
        # --- names only (bare list, one per line, no other data) ---
        ("n1", "names-users", "NAMES ONLY: usernames", lambda: _names_only(g, "User")),
        ("n2", "names-computers", "NAMES ONLY: computer names", lambda: _names_only(g, "Computer")),
        ("n3", "names-groups", "NAMES ONLY: group names", lambda: _names_only(g, "Group")),
        ("n4", "names-kerberoastable", "NAMES ONLY: kerberoastable users", lambda: _names_only(g, "User", _kerb)),
        ("n5", "names-da", "NAMES ONLY: domain admins", lambda: _names_only(g, "User", lambda n: n.sid in da_set)),
        ("n6", "names-enabled-users", "NAMES ONLY: enabled users", lambda: _names_only(g, "User", lambda n: n.p("enabled") is not False)),
    ]
    if start:
        items.insert(11, ("t", "attack-tree",
                          f"Attack tree from {g.nodes[start].name.split('@')[0]}",
                          lambda: print_attack_tree(g, start, owned, expand_bundles=True)))
    header("Export to text file — pick what to save")
    for key, _slug, label, _fn in items:
        if key == "n1":
            print(dim("   ── names-only lists (bare, one per line — feed to a tool) ──"))
        print(f"   {bold(key.rjust(2))})  {label}")
    try:
        tok = input(_navbar([("#", "export"), ("b", "back")])).strip().lower()
    except EOFError:
        return
    if not tok or tok in ("b", "q"):
        return
    chosen = next((it for it in items if it[0] == tok), None)
    if not chosen:
        print(red("  unknown choice"))
        return
    _, slug, label, fn = chosen
    if slug == "everything":
        parts = [("Summary", lambda: cmd_summary(g, _A())),
                 ("Domain admins", lambda: cmd_das(g, _A())),
                 ("Kerberoastable", lambda: cmd_kerberoastable(g, _A())),
                 ("AS-REP roastable", lambda: cmd_asreproastable(g, _A())),
                 ("SPN / services", lambda: cmd_spns(g, _A())),
                 ("DCSync", lambda: cmd_dcsync(g, _A())),
                 ("Delegation", lambda: cmd_delegation(g, _A())),
                 ("ADCS / ESC", lambda: cmd_adcs(g, _A())),
                 ("Escalation overview", lambda: print_escalation_overview(g, owned, expand=True, allow_prompt=False))]
        text = "".join(f"\n{'='*70}\n{t}\n{'='*70}\n" + _capture(f) for t, f in parts)
    else:
        text = _capture(fn)
    default = f"bernese_{dom}_{slug}.txt"
    try:
        fname = input(cyan(f"  filename [{default}]: ")).strip() or default
    except EOFError:
        return
    try:
        with open(fname, "w") as fh:
            if not slug.startswith("names-"):     # names-only files stay a clean wordlist
                fh.write(f"# bernese export — {label} — domain {g.domain_name or '?'}\n")
            fh.write(text)
        print(bold(green(f"  wrote {os.path.abspath(fname)}")))
    except OSError as e:
        print(red(f"  could not write file: {e}"))

# --------------------------------------------------------------------------- #
# Interactive mode
# --------------------------------------------------------------------------- #
class _A:
    def __init__(self, **kw):
        self.__dict__.update(kw)

def _ljust(plain, width, colored=None):
    """Left-justify by the PLAIN text width, then apply colour to the content."""
    pad = " " * max(0, width - len(plain))
    return (colored if colored is not None else plain) + pad

def _curses_pick(title, header_line, rows, owned=None, detail=None, toggle=True):
    """Arrow-key / type-to-filter picker. rows = [(key, plain_text, da, _)].
    Enter selects; when `owned` is given its members render with a green ✓ and,
    if `toggle` is set, Tab adds/removes the highlighted row (used by the start
    picker). With `toggle` False the ✓ is a read-only marker (e.g. rights you
    already hold). `detail`, if given, is a callback key -> plain string shown as
    a live info strip for whatever row is highlighted.
    Returns ('ok', key|None) on success, or ('__NOCURSES__', None) to fall back."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return ("__NOCURSES__", None)
    try:
        import curses
    except Exception:
        return ("__NOCURSES__", None)
    # Drop anything typed ahead (e.g. the Enter that submitted the previous
    # input() prompt) so it isn't read as a stray Enter/Esc here.
    try:
        import termios
        termios.tcflush(sys.stdin, termios.TCIFLUSH)
    except Exception:
        pass
    out = {"key": None}

    def run(stdscr):
        curses.curs_set(0)
        curses.flushinp()
        has_color = False
        try:
            curses.start_color(); curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_RED, -1)
            curses.init_pair(2, curses.COLOR_GREEN, -1)
            curses.init_pair(3, curses.COLOR_CYAN, -1)
            curses.init_pair(4, curses.COLOR_YELLOW, -1)
            has_color = True
        except Exception:
            pass
        sel, top, filt = 0, 0, ""
        while True:
            view = [r for r in rows if filt.lower() in r[1].lower()] if filt else rows
            sel = max(0, min(sel, len(view) - 1))
            h, w = stdscr.getmaxyx()
            stdscr.erase()
            stdscr.addnstr(0, 0, title[:w - 1], w - 1,
                           curses.A_BOLD | (curses.color_pair(3) if has_color else 0))
            own_hint = "  Tab own/unown " if (owned is not None and toggle) else " "
            hint = f" ↑↓ move  Enter select {own_hint} Esc back  —  type to filter: {filt}_"
            # reverse-video bar so it reads as a clear control strip, not faint text
            hint_attr = curses.A_REVERSE | curses.A_BOLD
            if has_color:
                hint_attr |= curses.color_pair(3)
            stdscr.addnstr(1, 0, hint.ljust(w - 1)[:w - 1], w - 1, hint_attr)
            if header_line:
                stdscr.addnstr(2, 0, header_line[:w - 1], w - 1, curses.A_BOLD)
            listtop = 3 if header_line else 2
            # last row is the count; when a detail callback is given, the row
            # above it carries the live info strip for the highlighted item
            vis = max(1, h - listtop - 1 - (1 if detail else 0))
            if sel < top:
                top = sel
            if sel >= top + vis:
                top = sel - vis + 1
            for i in range(top, min(len(view), top + vis)):
                r = view[i]; y = listtop + (i - top)
                is_owned = owned is not None and r[0] in owned
                attr = 0
                if has_color:
                    if is_owned:
                        attr |= curses.color_pair(2) | curses.A_BOLD
                    elif r[2]:
                        attr |= curses.color_pair(1) | curses.A_BOLD
                if i == sel:
                    attr |= curses.A_REVERSE
                prefix = ("✔" if is_owned else " ") + ("›" if i == sel else " ")
                stdscr.addnstr(y, 0, prefix + " " + r[1], w - 1, attr)
            if detail:
                try:
                    info = detail(view[sel][0]) if view else ""
                except Exception:
                    info = ""
                info_attr = curses.A_BOLD | (curses.color_pair(4) if has_color else 0)
                stdscr.addnstr(h - 2, 0, ("  " + (info or "")).ljust(w - 1)[:w - 1],
                               w - 1, info_attr)
            stdscr.addnstr(h - 1, 0, f"  {len(view)}/{len(rows)} shown", w - 1, curses.A_DIM)
            stdscr.refresh()
            c = stdscr.getch()
            if c == curses.KEY_UP:
                sel -= 1
            elif c == curses.KEY_DOWN:
                sel += 1
            elif c == curses.KEY_NPAGE:
                sel += vis
            elif c == curses.KEY_PPAGE:
                sel -= vis
            elif c == curses.KEY_HOME:
                sel = 0
            elif c == curses.KEY_END:
                sel = len(view) - 1
            elif c in (10, 13, curses.KEY_ENTER):
                if view:
                    out["key"] = view[sel][0]
                return
            elif c == 27:
                return
            elif owned is not None and toggle and c == 9:   # Tab = own/unown (letters filter)
                if view:
                    sid = view[sel][0]
                    owned.discard(sid) if sid in owned else owned.add(sid)
            elif c in (curses.KEY_BACKSPACE, 127, 8):
                filt = filt[:-1]
            elif 32 <= c <= 126:
                filt += chr(c)
            sel = max(0, sel)
    try:
        curses.wrapper(run)
    except Exception:
        return ("__NOCURSES__", None)
    return ("ok", out["key"])

def _fit(s, w):
    s = s or ""
    return s[:w].ljust(w)

def _pick_principals(g, nodes, title, owned=None, sort="interest"):
    """Shared arrow-key / numbered picker for a set of user/computer nodes."""
    owned = set() if owned is None else owned      # keep caller's set (even if empty)
    prof = {}
    total = len(nodes)
    for i, n in enumerate(nodes, 1):
        if total > 200 and (i % 50 == 0 or i == total):
            _progress(f"profiling {i}/{total} principals for the picker …", done=(i == total))
        size, hv, best = _user_profile(g, n.sid)
        prof[n.sid] = (size, hv, best, _group_names(g, n.sid, limit=3))

    def sort_key(n):
        size, hv, best, grps = prof[n.sid]
        if sort == "name":
            return (n.name,)
        if sort == "group":
            return ((grps[0] if grps else "~"), n.name)
        if sort == "tree":
            return (_is_admin(g, n.sid), -size, n.name)
        roast = bool(n.p("hasspn") or n.p("serviceprincipalnames"))
        return (_is_admin(g, n.sid), not bool(hv), -size, not roast, n.name)

    rows = sorted(nodes, key=sort_key)

    def tags(n):
        t = ""
        # computers carry host SPNs by default, so [Kerb] only makes sense for users
        if n.kind == "User" and (n.p("hasspn") or n.p("serviceprincipalnames")) and n.sid.rsplit("-", 1)[-1] != "502":
            t += " [Kerb]"
        if n.p("dontreqpreauth"):
            t += " [ASREP]"
        if n.kind == "Computer" and _is_dc(g, n.sid):
            t += " [DC]"
        return t

    def reach_str(size, best):
        # one clear column instead of a raw count + a "(Nh via Edge)" blob
        if best:
            return f"★ reaches {best[0].split(' ')[0]} ({best[1]}h)"
        return f"controls {size}" if size else "-"

    hdr = "  " + _fit("NAME", 26) + _fit("GROUPS", 38) + "REACH"
    crows = []
    for n in rows:
        size, hv, best, grps = prof[n.sid]
        txt = (_fit(n.name.split("@")[0] + tags(n), 26) + _fit(", ".join(grps), 38)
               + reach_str(size, best))
        crows.append((n.sid, txt, bool(best), n.sid in owned))

    def detail_line(sid):
        n = g.nodes.get(sid)
        if not n:
            return ""
        size, hv, best, grps = prof.get(sid, (0, [], None, []))
        bits = [n.kind]
        if n.kind == "Computer":
            if _is_dc(g, sid):
                bits.append("DOMAIN CONTROLLER")
            os_ = n.p("operatingsystem")
            if os_:
                bits.append(str(os_))
        if _is_admin(g, sid):
            bits.append("ADMIN")
        en = n.p("enabled")
        if en is not None:
            bits.append("enabled" if _truthy(en) else "DISABLED")
        if n.kind == "User" and (n.p("hasspn") or n.p("serviceprincipalnames")) and sid.rsplit("-", 1)[-1] != "502":
            bits.append("Kerberoastable/" + _A_plain(_roast_enc_tag(n)[0]))
        if n.p("dontreqpreauth"):
            bits.append("AS-REP-roastable")
        if best:
            bits.append(f"→ {best[0]} in {best[1]}h")
        elif size:
            bits.append(f"controls {size} node(s)")
        else:
            bits.append("controls nothing further")
        line = " · ".join(bits)
        desc = n.p("description")
        if desc:
            line += "  —  " + str(desc).replace("\n", " ")
        return line

    status, key = _curses_pick(title, hdr, crows, owned=owned, detail=detail_line)
    if status != "__NOCURSES__":
        return key

    # fallback: numbered list (Enter # to pick; o<#> to toggle owned)
    header(title)
    print(dim("   # " + hdr))
    idx = {}
    for i, n in enumerate(rows, 1):
        idx[str(i)] = n.sid
        size, hv, best, grps = prof[n.sid]
        own = n.sid in owned
        mark = bold(green("✔")) if own else " "
        nm = (bold(green(n.name.split("@")[0])) if own else green(n.name.split("@")[0])) + red(tags(n))
        print(" " + mark + _ljust(str(i), 3)
              + _ljust(n.name.split("@")[0] + tags(n), 26, nm)
              + _ljust((", ".join(grps))[:36], 38, dim((", ".join(grps))[:36]))
              + (red(reach_str(size, best)) if best else dim(reach_str(size, best))))
    try:
        tok = input(_navbar([("#", "pick"), ("o#", "own/unown"),
                             ("sort", "name|group|tree"), ("b", "back")])).strip()
    except EOFError:
        return None
    if not tok or tok.lower() in ("b", "q"):
        return None
    if tok.lower().startswith("sort"):
        parts = tok.split()
        ns = parts[1] if len(parts) > 1 and parts[1] in ("name", "group", "tree", "interest") else sort
        return _pick_principals(g, nodes, title, owned, ns)
    if tok.lower().startswith("o") and tok[1:].strip().isdigit():   # own/unown row #
        sid = idx.get(tok[1:].strip())
        if sid:
            owned.discard(sid) if sid in owned else owned.add(sid)
        return _pick_principals(g, nodes, title, owned, sort)
    return idx.get(tok) or g.resolve(tok)

def browse_users(g, owned=None):
    users = [n for n in g.nodes.values()
             if n.kind == "User" and n.sid.startswith("S-1-5-21")
             and n.sid.rsplit("-", 1)[-1] != "502"]
    return _pick_principals(g, users, "Users — pick a start node", owned)

def browse_computers(g, owned=None):
    comps = [n for n in g.nodes.values() if n.kind == "Computer"]
    if not comps:
        print(dim("  (no computer objects in this collection)"))
        return None
    return _pick_principals(g, comps, "Computers — type to filter, Enter to pick", owned)

def browse_members(g, group_sid, owned=None):
    """Pick a member (user/computer) of a group to read into it."""
    members = [g.nodes[m] for m in _expand_members(g, group_sid)
               if g.nodes.get(m) and g.nodes[m].kind in ("User", "Computer")]
    if not members:
        print(dim("  (group has no user/computer members)"))
        return None
    gname = g.nodes[group_sid].name.split("@")[0]
    return _pick_principals(g, members, f"Members of {gname} — pick one to read into", owned)

def browse_groups(g):
    """Pick one OR MORE groups. Returns a list of group sids (or None).
    In the arrow-key picker, Tab marks several then Enter confirms; in the
    numbered fallback, enter comma-separated numbers (e.g. 1,3,5)."""
    groups = [n for n in g.nodes.values() if n.kind == "Group"]

    def gkey(n):
        return (not bool(g.is_highvalue(n.sid)), -len(_expand_members(g, n.sid)), n.name)

    rows = sorted(groups, key=gkey)

    def desc(n):
        d = n.p("description")
        return str(d).replace("\n", " ") if d else ""

    def preview(n):
        allm = _expand_members(g, n.sid)
        names = [g.nodes[m].name.split("@")[0] for m in allm if g.nodes.get(m)
                 and g.nodes[m].kind in ("User", "Computer")]
        p = ", ".join(names[:3])
        if len(names) > 3:
            p += f", +{len(names) - 3}"
        return len(allm), p

    hdr = "  " + _fit("GROUP", 30) + _fit("#", 5) + _fit("DESCRIPTION", 40) + "MEMBERS"
    crows = []
    for n in rows:
        cnt, p = preview(n)
        hv = g.is_highvalue(n.sid)
        label = n.name.split("@")[0] + (" ★" if hv else "")
        crows.append((n.sid, _fit(label, 30) + _fit(str(cnt), 5)
                      + _fit(desc(n), 40) + p, bool(hv), False))

    marked = set()                     # Tab toggles membership; ✓ shows it
    status, key = _curses_pick("Groups — Tab to mark several, Enter to confirm",
                               hdr, crows, owned=marked)
    if status != "__NOCURSES__":
        if marked:
            return sorted(marked)
        return [key] if key else None

    header(f"Groups ({len(rows)})")
    print(dim("   # " + hdr))
    idx = {}
    for i, n in enumerate(rows, 1):
        idx[str(i)] = n.sid
        cnt, p = preview(n)
        hv = g.is_highvalue(n.sid)
        disp = n.name.split("@")[0][:26] + (" ★" if hv else "")
        label = red(disp) if hv else yellow(disp)
        print("  " + _ljust(str(i), 3) + _ljust(disp, 30, label)
              + _ljust(str(cnt), 5) + _ljust(desc(n)[:38], 40, dim(desc(n)[:38]))
              + dim(p))
    try:
        tok = input(_navbar([("#", "pick"), ("#,#,#", "multi-select"), ("b", "back")])).strip()
    except EOFError:
        return None
    if not tok or tok.lower() in ("b", "q"):
        return None
    if "," in tok:
        sids = [idx.get(t.strip()) for t in tok.split(",")]
        sids = [s for s in sids if s]
        return sids or None
    one = idx.get(tok) or g.resolve(tok)
    return [one] if one else None

def _browse_nodes(g, title, sids, inspect=True):
    """Filterable browser over a set of node SIDs — the answer to a 1000-row
    wall of output. Type to filter, ↑↓ to move, Enter to inspect the highlighted
    node, Esc to leave. Without curses it falls back to a substring-filter prompt
    so the search still works. With inspect=False it returns the chosen sid
    instead of printing its detail."""
    sids = list(dict.fromkeys(s for s in sids if s))          # de-dupe, keep order
    if not sids:
        print(dim("  (nothing to browse)"))
        return None
    # value-rank computers: DC / privileged-session hosts float to the top, so
    # the juicy few in a 1000-row list are the first thing you see / filter.
    priv = _priv_set(g)
    cv = {}
    for s in sids:
        n = g.nodes.get(s)
        cv[s] = _computer_value(g, s, priv) if (n and n.kind == "Computer") else (False, [])

    sids.sort(key=lambda s: (not (bool(g.is_highvalue(s)) or cv[s][0]),
                             (g.nodes[s].name if s in g.nodes else str(s)).lower()))

    def plain(s):
        n = g.nodes.get(s)
        base = f"{n.name.split('@')[0]} ({n.kind})" if n else (_sid_hint(s) or str(s))
        hv = g.is_highvalue(s)
        if hv:
            return base + f"  ★ {hv}"
        return base + ("  ★ high-value" if cv[s][0] else "")

    def detail(s):
        n = g.nodes.get(s)
        if not n:
            return _sid_hint(s) or str(s)
        size, hv, best = _user_profile(g, s)
        bits = [n.kind]
        os_ = n.p("operatingsystem")
        if os_:
            bits.append(str(os_))
        if cv[s][0]:                                          # DC / session / admin tags
            bits.extend(cv[s][1])
        if best:
            bits.append(f"→ {best[0]} in {best[1]}h")
        elif size:
            bits.append(f"controls {size} node(s)")
        d = n.p("description")
        if d:
            bits.append(str(d).replace("\n", " "))
        return " · ".join(bits)

    while True:                                               # curses path
        crows = [(s, _fit(plain(s), 62), bool(g.is_highvalue(s)), False) for s in sids]
        status, key = _curses_pick(
            f"{title} ({len(sids)}) — type to filter · Enter inspect · Esc back",
            "", crows, detail=detail)
        if status == "__NOCURSES__":
            break
        if key is None:
            return None
        if not inspect:
            return key
        print_node_detail(g, key)

    # ---- no-curses fallback: substring-filter prompt -----------------------
    header(f"{title} ({len(sids)})")
    print(dim("  type a substring to filter · Enter lists all · b to go back"))
    while True:
        try:
            q = input(cyan("  filter › ")).strip()
        except EOFError:
            return None
        if q.lower() in ("b", "q"):
            return None
        ql = q.lower()
        matches = [s for s in sids if ql in plain(s).lower()] if q else sids
        if not matches:
            print(dim("    (no matches)"))
            continue
        for s in matches[:40]:
            print("    " + g.label(s))
        if len(matches) > 40:
            print(dim(f"    … +{len(matches) - 40} more — narrow the filter"))
        elif not inspect and len(matches) == 1:
            return matches[0]

def _prompt_node(g, label="node", owned=None):
    hint = "name / SID  ·  Enter to browse  ·  b = back"
    while True:
        try:
            tok = input(cyan(f"  {label} ({hint}): ")).strip()
        except EOFError:
            return None
        if tok.lower() in ("b", "q", "back"):
            return None
        if not tok:
            sid = browse_users(g, owned)        # Enter -> browse
            if sid:
                return sid
            continue
        sid = g.resolve(tok)
        if sid:
            return sid
        print(red("    not found — type part of a name, Enter to browse, or b to go back."))

MENU = [
    ("1", "Escalation overview (how to reach Domain Admin)"),
    ("2", "Attack tree from start node  (visual privesc paths)"),
    ("3", "Shortest path:  start  ->  Domain Admin"),
    ("4", "Shortest path:  start  ->  a target you pick"),
    ("5", "Outbound control of start (what it can take over)"),
    ("6", "Who controls start (inbound)"),
    ("7", "Kerberoastable accounts"),
    ("8", "AS-REP roastable accounts"),
    ("9", "Domain admins & high-value groups"),
    ("10", "Browse groups  ->  pick a member to read into"),
    ("11", "Rights search (who holds a right -> drill in)"),
    ("12", "DCSync-capable principals"),
    ("13", "Delegation (unconstrained / constrained / RBCD)"),
    ("14", "ADCS / certificate abuse (ESC)"),
    ("15", "SPN accounts and what they reach"),
    ("16", "Local admin rights (who is admin on which hosts)"),
    ("17", "Domain summary"),
    ("18", "Domain controllers"),
    ("19", "MachineAccountQuota & user-owned machines"),
    ("20", "Domain password policy"),
]

BANNER = [
    r" ██████╗ ███████╗██████╗ ███╗   ██╗███████╗███████╗███████╗",
    r" ██╔══██╗██╔════╝██╔══██╗████╗  ██║██╔════╝██╔════╝██╔════╝",
    r" ██████╔╝█████╗  ██████╔╝██╔██╗ ██║█████╗  ███████╗█████╗  ",
    r" ██╔══██╗██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝  ╚════██║██╔══╝  ",
    r" ██████╔╝███████╗██║  ██║██║ ╚████║███████╗███████║███████╗",
    r" ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝",
]
def _banner(g, data_path):
    print()
    for line in BANNER:
        print(bold(cyan(line)))
    print(" " + bold(yellow("🐾")) + "  " + bold(cyan("bloodhound attack-path explorer")))
    print()
    da = [g.nodes[m].name.split("@")[0] for sid, n in g.nodes.items()
          if n.kind == "Group" and sid.rsplit("-", 1)[-1] in ("512", "519")
          for m in _expand_members(g, sid)
          if g.nodes.get(m) and g.nodes[m].kind == "User"]
    print(f"  {bold('Domain')} {bold(green(g.domain_name or '?'))}     "
          f"{bold(str(sum(1 for n in g.nodes.values() if n.kind=='User')))} users   "
          f"{bold(str(sum(1 for n in g.nodes.values() if n.kind=='Group')))} groups   "
          f"{bold(str(sum(1 for n in g.nodes.values() if n.kind=='Computer')))} computers   "
          f"{bold(str(sum(len(v) for v in g.ctrl.values())))} control edges")
    print(f"  {dim(os.path.basename(data_path))}")
    if da:
        print(f"  {dim('Domain Admins:')} {', '.join(sorted(set(da)))}")
    if isinstance(g.maq, int):
        if g.maq > 0:
            print("  " + bold(red(f"MachineAccountQuota: {g.maq}"))
                  + dim(f" — any user can add up to {g.maq} machine account(s) (RBCD / Shadow-Creds). option 19"))
        else:
            print(f"  {dim('MachineAccountQuota: 0 (users cannot add machines)')}")

def _availability(g):
    return {
        "7": any(n.kind == "User" and (n.p("hasspn") or n.p("serviceprincipalnames"))
                 and n.sid.rsplit("-", 1)[-1] != "502" for n in g.nodes.values()),
        "8": any(n.kind == "User" and n.p("dontreqpreauth") for n in g.nodes.values()),
        "12": any((lbl == "DCSync" or lbl in REPL_RIGHTS)
                  for d in g.domain_sids for (_, lbl) in g.rctrl.get(d, [])),
        "13": any((n.p("unconstraineddelegation") and not _is_default_unconstrained(g, n.sid))
                  or n.allowed_to_delegate or n.allowed_to_act for n in g.nodes.values()),
        "14": bool(g.templates or g.cas),
        "16": any(l == "AdminTo" for d in g.ctrl.values() for (_, l) in d),
        "18": any(n.kind == "Computer" and _is_dc(g, n.sid) for n in g.nodes.values()),
        "19": (isinstance(g.maq, int) and g.maq > 0) or bool(_user_owned_computers(g)),
        "20": _has_pwpolicy(g),
    }

def _roastable_das(g):
    """Roastable (kerb/AS-REP) accounts that are themselves Domain/Enterprise Admin."""
    da_set = _da_member_set(g)
    out = []
    for sid in da_set:
        n = g.nodes.get(sid)
        if not n or n.kind != "User":
            continue
        kerb = (n.p("hasspn") or n.p("serviceprincipalnames")) and sid.rsplit("-", 1)[-1] != "502"
        if kerb or n.p("dontreqpreauth"):
            out.append((sid, bool(kerb), bool(n.p("dontreqpreauth"))))
    return out

def shortest_to_da(g, start):
    """Shortest ACL path from start to the nearest Domain-Admin-equivalent target."""
    sn = g.nodes.get(start)
    header(f"Shortest path: {sn.name.split('@')[0]}  ->  Domain Admin")

    # A roastable DA is effectively a 'path' with no ACL chain — surface it first.
    rda = _roastable_das(g)
    if rda:
        print(bold(red("  ⚠ Roastable Domain Admin — crack this and you ARE DA (no chain needed):")))
        for sid, kerb, asrep in rda:
            n = g.nodes[sid]
            how = []
            if kerb:
                how.append(f"Kerberoast {_A_plain(_roast_enc_tag(n)[0])}")
            if asrep:
                how.append("AS-REP roast")
            print(f"     {bold(red('⚠'))} {green(n.name.split('@')[0])}  {dim('(' + ', '.join(how) + ')')}")
        print()

    reach = g.reachable(start)
    wins = sorted([s for s in reach if s != start and g.is_highvalue(s)],
                  key=lambda s: reach[s][0])
    if not wins:
        print(bold(yellow("  No ACL path to a high-value / Domain-Admin target from here.")))
        _print_esc_branches(g, exclude_reachable=set(reach))
        return
    best = wins[0]
    path = g.bfs_path(start, best)
    _print_path(g, path)

def _reach_note(g, sid):
    """Short 'where controlling this leads' note: nearest high-value + hops."""
    if g.is_highvalue(sid):
        return bold(red(f"  ★ {g.is_highvalue(sid)}"))
    size, hv, best = _user_profile(g, sid)
    if best:
        return red(f"  → reaches ★ {best[0]} in {best[1]} hop(s)")
    if size:
        return dim(f"  → controls {size} more node(s), none high-value")
    return dim("  → dead end (controls nothing further)")

def _print_right_detail(g, psid, r, holders, full, cap=25):
    """Show what the holder can do with this right over each target, and — more
    usefully than a member dump — where controlling each target LEADS."""
    pn = g.nodes.get(psid)
    header(f"{pn.name.split('@')[0]} ({pn.kind})  —  holds {r}")
    if pn and pn.kind == "Group":
        mcnt = sum(1 for mm in _expand_members(g, psid)
                   if g.nodes.get(mm) and g.nodes[mm].kind in ("User", "Computer"))
        print(dim(f"  (any of this group's {mcnt} member(s) wields the right below)"))

    tgts = sorted(holders[psid], key=lambda s: (not g.is_highvalue(s),
                                                g.nodes.get(s, Node(s)).name))
    truncated = (not full) and len(tgts) > cap
    shown = tgts if full else tgts[:cap]
    print(bold(f"\n  Can {r} over {len(tgts)} target(s)  —  what you get & where it leads:"))
    for t in shown:
        tn = g.nodes.get(t)
        print(f"    {red('→')} {g.label(t)}{_reach_note(g, t)}")
        print(dim(f"        {technique(r, tn.kind if tn else '', tn.name if tn else t)}"))
        if tn and tn.kind == "Group":
            # the actionable fact for a group target: joining it inherits ITS access
            print(dim("        (control of the group = add yourself → inherit the"
                      " group's memberships & rights above; not the member accounts)"))
    if truncated:
        print(dim(f"    … +{len(tgts) - cap} more target(s) — press x"))
    return truncated

def rights_flow(g, owned=None):
    """Pick a right -> holders -> drill in. 'b' steps back ONE level; 'm' jumps to
    the main menu. Rights/holders you hold via your owned set are highlighted; a
    group target lists the members you'd control (expandable with 'x')."""
    owned = owned or set()
    held = _owned_rights(g, owned)
    own_closure = set()
    for o in owned:
        own_closure |= _principal_closure(g, o)

    while True:                                           # level 1: pick a right
        r = _rights_pick(g, held)
        if not r:
            return                                        # b/q here -> main menu
        holders = defaultdict(list)
        for sid, n in g.nodes.items():
            for (psid, right, inh) in n.aces:
                if right.lower() == r.lower():
                    holders[psid].append(sid)
        if not holders:
            print(dim(f"  (nobody holds {r})"))
            continue

        while True:                                       # level 2: pick a holder
            items = sorted(holders.items(),
                           key=lambda kv: (kv[0] not in own_closure, -len(kv[1]),
                                           g.nodes.get(kv[0], Node(kv[0])).name))

            def hdetail(psid):
                n = g.nodes.get(psid)
                if not n:
                    return (_sid_hint(psid) or "unresolved SID") + f" · {len(holders[psid])} target(s)"
                size, hv, best = _user_profile(g, psid)
                tip = [n.kind, f"{len(holders[psid])} {r} target(s)"]
                if n.kind == "Group":
                    mcnt = sum(1 for mm in _expand_members(g, psid)
                               if g.nodes.get(mm) and g.nodes[mm].kind in ("User", "Computer"))
                    tip.append(f"group of {mcnt} member(s)")
                if psid in own_closure:
                    tip.append("you hold this")
                if best:
                    tip.append(f"→ {best[0]} in {best[1]}h")
                elif size:
                    tip.append(f"controls {size} node(s)")
                return " · ".join(tip)

            crows = [(psid, _fit(_A_plain(g.label(psid)), 50) + f"({len(tgts)} target(s))",
                      False, False) for psid, tgts in items]
            status, key = _curses_pick(
                f"Principals holding {r} — ✓ = you hold it · Enter drill in · Esc back to rights",
                "", crows, owned=own_closure, detail=hdetail, toggle=False)
            if status != "__NOCURSES__":
                if key is None:
                    break                                 # Esc -> back to rights
                psid = key
            else:
                header(f"Principals holding {r}  ({len(items)})")
                if any(p in own_closure for p, _ in items):
                    print(bold(green("  ✓ = you hold this via your owned set")))
                idx = {}
                for i, (psid, tgts) in enumerate(items, 1):
                    idx[str(i)] = psid
                    mine = bold(green(" ✓")) if psid in own_closure else "   "
                    print(f"  {mine}{bold(str(i).rjust(2))})  {g.label(psid)}  {dim('(' + str(len(tgts)) + ' target(s))')}")
                try:
                    tok = input(_navbar([("#", "drill in"), ("b", "back to rights"),
                                         ("m", "main menu")])).strip().lower()
                except EOFError:
                    return
                if tok == "m":
                    return                                # jump to main menu
                if not tok or tok in ("b", "q"):
                    break                                 # back to level 1
                psid = idx.get(tok) or g.resolve(tok)
                if not psid or psid not in holders:
                    print(red("  unknown choice"))
                    continue

            full = False
            while True:                                   # level 3: the detail view
                truncated = _print_right_detail(g, psid, r, holders, full)
                pairs = []
                if len(holders[psid]) > 20:
                    pairs.append(("f", "find / filter targets"))
                if truncated:
                    pairs.append(("x", "show all targets"))
                pairs += [("b", "back to holders"), ("m", "main menu")]
                try:
                    ans = input(_navbar(pairs)).strip().lower()
                except EOFError:
                    return
                if ans == "f" and len(holders[psid]) > 20:
                    pn = g.nodes.get(psid)
                    who = pn.name.split("@")[0] if pn else psid
                    _browse_nodes(g, f"{who} — {r} over", list(holders[psid]))
                    continue
                if ans == "x" and truncated:
                    full = True
                    continue
                if ans == "m":
                    return
                break                                     # back to level 2 (holders)

def _print_menu(g, start, owned, avail):
    W = 72                                            # inner width between borders

    def rule(l, r):
        print(cyan("  " + l + "─" * W + r))

    def row(content=""):
        vis = len(_A_plain(content))
        if vis > W - 1:                               # never let a long line break the frame
            return print(cyan("  │ ") + content)
        print(cyan("  │ ") + content + " " * (W - 1 - vis) + cyan("│"))

    print()
    rule("╭", "╮")
    sname = g.nodes[start].name.split("@")[0] if start else "(none — pick with s / b)"
    row(bold("START  ") + (bold(green(sname)) if start else dim(sname)))
    if owned:
        ownl = ", ".join(sorted(g.nodes[s].name.split("@")[0] for s in owned))
        if len(ownl) > 52:
            ownl = ownl[:51] + "…"
        row(bold("OWNED  ") + bold(green(f"({len(owned)}) ")) + green(ownl))
    else:
        row(bold("OWNED  ") + dim("none — highlight a user and press 'o' to mark it"))
    rule("├", "┤")

    for key, label in MENU:
        if key in avail and not avail[key]:
            row(dim(f"{key.rjust(3)})  {label}  — none"))
        else:
            row(bold(f"{key.rjust(3)})") + f"  {label}")
    rule("├", "┤")

    def cell(key, label, w=34):
        # key chip + label, padded to a fixed visible width so columns line up
        plain = f"{key}  {label}"
        return _kc(key) + " " + bold(label) + " " * max(0, w - len(plain) - 1)

    def legend(pairs, per=2):
        for i in range(0, len(pairs), per):
            row(" " + "".join(cell(x, y) for x, y in pairs[i:i + per]))

    row(bold(yellow("COMMANDS")))
    legend([("s", "set start (user)"), ("b", "browse users"),
            ("comp", "browse computers"), ("o", "own / unown start"),
            ("c", "combined owned tree"), ("i", "inspect node"),
            ("e", "export to file"), ("x", "expand a list"),
            ("q", "quit")])
    row()
    row(bold(cyan("IN THE ARROW-KEY PICKER")) + dim("   (set start / browse users)"))
    legend([("type", "filter as you type"), ("↑↓", "move up / down"),
            ("Enter", "select"), ("Tab", "own / unown"),
            ("Esc", "back")])
    rule("╰", "╯")

def _after_action():
    """Prompt shown after each action: Enter for menu, or type the next option."""
    try:
        nxt = input(_navbar([("Enter", "menu"), ("#", "jump to that option"),
                             ("q", "quit")])).strip().lower()
    except EOFError:
        return "q"
    return nxt or None

def _rights_pick(g, held=None):
    held = held or set()
    holders = defaultdict(set)                 # right -> set of distinct principals
    for n in g.nodes.values():
        for (psid, r, _) in n.aces:
            if r in CONTROL_RIGHTS or r in REPL_RIGHTS:
                holders[r].add(psid)
    # rights you hold (via owned) first, then by popularity
    rights = sorted(holders, key=lambda r: (r not in held, -len(holders[r]), r))
    if not rights:
        print(dim("  (no control rights present in this dataset)"))
        return None

    gloss = {
        "GenericAll": "full control — reset pw / shadow creds / add to group",
        "GenericWrite": "write attrs — targeted Kerberoast / shadow creds",
        "WriteDacl": "rewrite the DACL → grant yourself GenericAll",
        "WriteOwner": "take ownership → grant yourself GenericAll",
        "Owns": "owner → rewrite the DACL", "Owner": "owner → rewrite the DACL",
        "ForceChangePassword": "reset the target's password",
        "AddMember": "add yourself to the group", "AddSelf": "add yourself to the group",
        "AddKeyCredentialLink": "shadow credentials → PKINIT as the target",
        "AllExtendedRights": "all extended rights (ForceChangePassword / DCSync …)",
        "ReadLAPSPassword": "read the host's local-admin (LAPS) password",
        "ReadGMSAPassword": "read the gMSA password",
        "DCSync": "replicate directory secrets — dump every hash",
        "GetChanges": "half of DCSync (pair with GetChangesAll)",
        "GetChangesAll": "half of DCSync (pair with GetChanges)",
    }

    def rdetail(rt):
        return f"{len(holders[rt])} principal(s) hold {rt} · {gloss.get(rt, 'control right')}"

    crows = [(r, _fit(r, 34) + f"({len(holders[r])} principals)", False, False)
             for r in rights]
    status, key = _curses_pick(
        "Control rights present — ✓ = held via your owned set · Enter pick · Esc back",
        "", crows, owned=held, detail=rdetail, toggle=False)
    if status != "__NOCURSES__":
        return key

    header("Rights present — pick one (count = principals that hold it)")
    if held:
        print(bold(green("  ✓ = a right your owned set already holds")))
    for i, r in enumerate(rights, 1):
        mine = bold(green(" ✓")) if r in held else "   "
        name = bold(green(r)) if r in held else r
        print(f"  {mine}{bold(str(i).rjust(2))})  {name}  {dim('(' + str(len(holders[r])) + ' principals)')}")
    try:
        tok = input(_navbar([("#", "pick a right"), ("b", "back")])).strip()
    except EOFError:
        return None
    if not tok or tok.lower() in ("b", "q"):
        return None
    if tok.isdigit() and 1 <= int(tok) <= len(rights):
        return rights[int(tok) - 1]
    return tok

def _show_tree(g, start, owned):
    """Attack tree from start; combined (with chains) when 2+ nodes are owned."""
    if len(owned) >= 2:
        print_combined_tree(g, owned)
    elif start:
        print_attack_tree(g, start, owned)

def _show_start(g, start, owned):
    """What to show right after a node becomes the start. A computer rarely has
    outbound control, so its detail (admins, sessions, who controls it) is far
    more useful than an empty attack tree."""
    n = g.nodes.get(start) if start else None
    if n and n.kind == "Computer" and len(owned) < 2:
        print_node_detail(g, start)
    else:
        _show_tree(g, start, owned)

def interactive(g, data_path):
    owned = set()
    _banner(g, data_path)
    avail = _availability(g)
    print(dim("\n  Pick your start node — type to filter.  (Esc to type a name / SID instead.)"))
    start = browse_users(g, owned)                       # live type-to-filter picker
    if start is None:
        start = _prompt_node(g, "start node", owned=owned)
    if start:
        _show_start(g, start, owned)

    pending = None
    while True:
        if pending is not None:
            choice, pending = pending, None
        else:
            _print_menu(g, start, owned, avail)
            try:
                choice = input(cyan("\n  > ")).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                break
        if not choice:
            continue
        if choice in ("q", "quit", "exit"):
            break

        produced = True
        try:
            if choice in ("s", "b"):
                ns = browse_users(g, owned)              # live picker for both
                if ns is None and choice == "s":         # Esc -> allow typing a name/SID
                    ns = _prompt_node(g, "new start node", owned=owned)
                if ns:
                    start = ns
                    _show_start(g, start, owned)
                else:
                    produced = False
            elif choice in ("comp", "computers", "computer"):
                ns = browse_computers(g, owned)          # Esc -> type a name/SID
                if ns is None:
                    ns = _prompt_node(g, "computer (name / SID)", owned=owned)
                if ns:
                    start = ns
                    _show_start(g, start, owned)
                else:
                    produced = False
            elif choice == "o":
                if not start:
                    print(red("  Set a start node first."))
                elif start in owned:
                    owned.discard(start)
                    print(dim(f"  unmarked {g.nodes[start].name.split('@')[0]} as owned."))
                    _show_start(g, start, owned)
                else:
                    owned.add(start)
                    print(bold(green(f"  marked {g.nodes[start].name.split('@')[0]} as OWNED.")))
                    _show_start(g, start, owned)
            elif choice == "c":
                if owned:
                    print_combined_tree(g, owned)
                else:
                    print(dim("  No owned nodes yet — set a start and press 'o' to mark it."))
            elif choice == "i":
                tgt = start if start else _prompt_node(g, "node to inspect", owned=owned)
                if tgt:
                    print_node_detail(g, tgt)
                else:
                    produced = False
            elif choice == "e":
                export_flow(g, start, owned)
            elif choice in ("2", "3", "4", "5", "6") and not start:
                print(red("  Set a start node first (option s / b)."))
            elif choice == "1":
                print_escalation_overview(g, owned)
            elif choice == "2":
                _show_tree(g, start, owned)
            elif choice == "3":
                shortest_to_da(g, start)
            elif choice == "4":
                tgt = _prompt_node(g, "target node", owned=owned)
                if tgt:
                    header(f"Path: {g.nodes[start].name.split('@')[0]}  ->  {g.nodes[tgt].name.split('@')[0]}")
                    path = g.bfs_path(start, tgt)
                    if path:
                        _print_path(g, path)
                    else:
                        print(bold(yellow("  No ACL path to that target.")))
                        _print_esc_branches(g)
                else:
                    produced = False
            elif choice == "5":
                full = False
                while True:
                    truncated = cmd_control(g, _A(principal=start), full=full)
                    if full or not truncated:
                        break
                    ans = input(_navbar([("f", "find / filter targets"),
                                         ("x", "list every controlled object"),
                                         ("b", "back")])).strip().lower()
                    if ans == "f":
                        reach = g.reachable(start)
                        sids = [s for s in reach if s != start and g.nodes.get(s)]
                        _browse_nodes(g, f"Controlled by {g.nodes[start].name.split('@')[0]}", sids)
                        continue
                    if ans == "x":
                        full = True
                        continue
                    break
            elif choice == "6":
                cmd_controllers(g, _A(principal=start))
            elif choice == "7":
                cmd_kerberoastable(g, _A())
            elif choice == "8":
                cmd_asreproastable(g, _A())
            elif choice == "9":
                cmd_das(g, _A())
            elif choice == "10":
                grps = browse_groups(g)
                if grps:
                    if len(grps) == 1:
                        print_node_detail(g, grps[0])        # the group's rights + members
                        m = browse_members(g, grps[0], owned)  # then pick a member to read into
                    else:
                        # union of members across the selected groups
                        seen, members = set(), []
                        for gs in grps:
                            for mm in _expand_members(g, gs):
                                if mm not in seen and g.nodes.get(mm) and g.nodes[mm].kind in ("User", "Computer"):
                                    seen.add(mm)
                                    members.append(g.nodes[mm])
                        gl = ", ".join(g.nodes[s].name.split("@")[0] for s in grps)
                        print(dim(f"  Combined members of {len(grps)} groups ({gl}): {len(members)}"))
                        m = _pick_principals(g, members,
                                             f"Members of {len(grps)} groups — pick one to read into",
                                             owned) if members else None
                    if m:
                        start = m
                        _show_tree(g, start, owned)
                    elif len(grps) > 1:
                        produced = False      # multi-select with no pick -> nothing shown
                    # single-group: we already printed the group detail, so keep the prompt
                else:
                    produced = False
            elif choice == "11":
                rights_flow(g, owned)
                produced = False          # drop straight back to a freshly listed menu
            elif choice == "12":
                cmd_dcsync(g, _A())
            elif choice == "13":
                cmd_delegation(g, _A())
            elif choice == "14":
                cmd_adcs(g, _A())
            elif choice == "15":
                cmd_spns(g, _A())
            elif choice == "16":
                cmd_adminto(g, _A())
            elif choice == "17":
                cmd_summary(g, _A())
            elif choice == "18":
                cmd_dcs(g, _A())
            elif choice == "19":
                full = False
                while True:
                    truncated = cmd_maq(g, _A(), full=full)
                    if full or not truncated:
                        break
                    ans = input(_navbar([("f", "find / filter machines"),
                                         ("x", "list every machine account"),
                                         ("b", "back")])).strip().lower()
                    if ans == "f":
                        sids = [c for _o, c in _user_owned_computers(g)]
                        _browse_nodes(g, "User-owned computers", sids)
                        continue
                    if ans == "x":
                        full = True
                        continue
                    break
            elif choice == "20":
                cmd_pwpolicy(g, _A())
            else:
                print(red("  unknown option"))
                produced = False
        except SystemExit as e:
            print(e)
        if produced:
            pending = _after_action()
    print(dim("  bye."))

# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _warn_no_tui():
    """Printed when launched interactively but the full-screen TUI can't run because its
    optional dependencies are missing — tells the user how to get it."""
    print(yellow("  [!] Full-screen TUI unavailable — 'textual' and 'rich' are not installed."))
    print(dim("      Falling back to the basic text menu. To run the full interactive TUI:"))
    print(bold("          pip install textual rich") + dim("      (or:  pipx install bernese)"))
    print()

def main():
    ap = argparse.ArgumentParser(
        prog="bernese", description="bernese - BloodHound attack-path explorer")
    ap.add_argument("-d", "--data", required=True,
                    help="BloodHound CE .zip, a directory of *.json, or a single .json")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colour")
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
    g = load(args.data)

    if not args.cmd:
        if _HAS_TUI:
            BerneseApp(g).run()          # the interactive Textual TUI
        else:
            _warn_no_tui()               # no textual/rich -> note it, then the curses menu
            interactive(g, args.data)
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
# (the CLI subcommands and the stdlib curses menu) runs with ZERO pip installs,
# so this block is guarded: if those packages are missing the tool still works,
# it just falls back to the curses menu.
# =========================================================================== #
import time
bh = sys.modules[__name__]            # self-alias so the TUI code's bh.X resolves here

try:
    from rich.text import Text
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical, VerticalScroll
    from textual.screen import Screen
    from textual.widgets import DataTable, Footer, Header, Input, OptionList, Static, Tree
    from textual.widgets.option_list import Option
    _HAS_TUI = True
except ImportError:                   # textual/rich absent -> stub the names so the class
    _HAS_TUI = False                  # definitions below still import (the TUI won't run;
    class _StubMeta(type):            # main() checks _HAS_TUI and uses the curses menu).
        def __getattr__(cls, name):
            return cls
    class _Stub(metaclass=_StubMeta):
        def __init__(self, *a, **k):
            pass
        def __getattr__(self, name):
            return None
    ComposeResult = object
    App = Screen = Vertical = Horizontal = VerticalScroll = _Stub
    Text = DataTable = Footer = Header = Input = OptionList = Static = Tree = Option = _Stub
    Binding = _Stub


KIND_COLOR = {"User": "green", "Group": "yellow", "Computer": "cyan",
              "Domain": "magenta", "GPO": "blue", "OU": "grey62",
              "Container": "grey62", "CertTemplate": "blue"}

INLINE_CAP = 12                       # rows shown when a fan-out / category is dropped down
OWNED = "\U0001f480"                   # 💀 — owned marker, like BloodHound's skull
OWNED_TAG = f"{OWNED} owned"           # icon + word — shown on every owned principal
STAR = "◆"                        # ◆ — high-value (one diamond glyph for all high-priv)
CHECK = "✓"                       # ✓ — right you already hold
PRIV_MARK = "◆"                   # ◆ — privileged (effectively-admin) principal
KERB = "⚑kerb"                    # ⚑ — kerberoastable user (SPN set)
KERB_STYLE = "purple"                 # plain (non-privileged) kerberoastable users — purple
PRIV_STYLE = "bold orange1"           # privileged USERS — orange, never green-like-a-user
PRIV_COMP_STYLE = "bold magenta"      # privileged / high-value COMPUTERS — distinct from users
ROAST_ADMIN_STYLE = "bold red"        # kerberoastable privileged accounts — crack = instant admin
OWNED_STYLE = "bold green"            # the owned icon + word


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


EXPORT_PRESETS = [
    ("name", "Name only (one per line — wordlist)"),
    ("name_os", "Name + OS"),
    ("name_desc", "Name + description"),
    ("name_tags", "Name + tags (SPN / AS-REP / DC / disabled …)"),
    ("full", "Full — name, kind, groups, control, desc, tags"),
]


def export_line(g, s, preset):
    """One output line for a principal under the chosen export preset (tab-separated)."""
    n = g.nodes.get(s)
    nm = short(g, s)
    if preset == "name":
        return nm
    if preset == "name_os":
        return f"{nm}\t{(n.p('operatingsystem') if n else '') or ''}"
    if preset == "name_desc":
        return f"{nm}\t{((n.p('description') if n else '') or '').replace(chr(10), ' ')}"
    if preset == "name_tags":
        return f"{nm}\t{node_tags(g, s).plain.strip()}"
    kind = n.kind if n else "?"
    grps = ", ".join(bh._group_names(g, s, limit=99))
    ctrl = sum(1 for (_d, l) in g.ctrl.get(s, []) if l != "MemberOf")
    desc = ((n.p("description") if n else "") or "").replace("\n", " ")
    return f"{nm}\t{kind}\t{grps}\t{ctrl}\t{desc}\t{node_tags(g, s).plain.strip()}"


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
    # kerberoastable users are shown by their PURPLE name colour (see name_style_for),
    # not an inline flag/tag.
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
    "520": ("Group Policy Creator Owners: members CREATE GPOs and own the ones they make, "
            "so they can author/link policy that runs as SYSTEM on domain-joined machines "
            "(scheduled task, script, add-local-admin) — a path to domain takeover."),
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
    if size:
        out.append(f"  controls {size} node(s) downstream\n", style="white")
    elif best_sid is None and not hv:
        out.append("  controls nothing further\n", style="grey50")

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
    t.append(f"{g.domain_name or '?'}\n", style="bold cyan")
    if isinstance(g.maq, int):
        t.append(f"MAQ {g.maq}" + ("  — any user can add machines" if g.maq > 0 else ""),
                 style="red" if g.maq > 0 else "grey70")
    return t


def color_legend():
    """The marker/colour key — shown at the BOTTOM of the overview, out of the way."""
    t = Text()
    t.append("legend  ", style="grey50")
    t.append(f"{STAR} high-value", style="bold red")
    t.append("  ", style="grey50")
    t.append(f"priv user {PRIV_MARK}", style=PRIV_STYLE)
    t.append("  ", style="grey50")
    t.append("priv host", style=PRIV_COMP_STYLE)
    t.append("  ", style="grey50")
    t.append(KERB, style="yellow")
    t.append("  ", style="grey50")
    t.append(OWNED_TAG, style="green")
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
    if app.start and not g.is_highvalue(app.start):
        _size, _hv, best = bh._user_profile(g, app.start)
        if best:
            return f"{short(g, app.start)} ⇒ {STAR} {best[0]} ({best[1]}h)", "start_path"
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
    """Clickable position rows for the overview: START (+ its shortest path), OWNED, and
    the single FASTEST WIN. Each is (dispatch_id, rich-Text label, enabled)."""
    priv = app.priv
    rows = []
    pad = "  "                                  # small indent for the sub-rows (kept left so
    #                                             a "NAME: Right ×N" line fits without wrapping)
    # START — the node, then on its own indented lines: its route to DA (or lack of one)
    # and the single strongest ACL right it wields.
    if app.start:
        lab = Text(f"{'START':<8}", style="bold grey62")
        lab.append_text(ntext(g, app.start, priv=priv))
        rows.append(("start_tree", lab, True))
        if g.is_highvalue(app.start):
            rows.append(("start_tree", Text(f"{pad}this node IS high-value", style="bold red"), True))
        else:
            _s, _h, best = bh._user_profile(g, app.start)
            if best:
                rows.append(("start_path",
                             Text(f"{pad}→ reaches {STAR} {best[0]} in {best[1]} hop(s)",
                                  style="red"), True))
            else:
                rows.append(("start_tree",
                             Text(f"{pad}no ACL path to a high-value target", style="grey50"), False))
            # even without an ACL path, surface the strongest right this node holds —
            # just the right name + how many objects (no wordy effect text)
            pw = start_power(g, app.start)
            if pw:
                right, cnt, _effect = pw
                rows.append(("start_info", Text(f"{pad}{right} ×{cnt}", style="red"), True))
    else:
        rows.append(("start_tree", Text(f"{'START':<8}none — pick a node from Users / Computers",
                                        style="bold grey62"), True))
    # OWNED — count + the footholds you hold, each with the strongest right IT wields (so an
    # owned foothold's privesc shows here even when it is not the current start node).
    if app.owned:
        names = sorted(short(g, s) for s in app.owned)
        lab = Text(f"{'OWNED':<8}", style="bold grey62")
        lab.append(f"{OWNED} {len(app.owned)}   ", style="bold green")
        lab.append(", ".join(names[:4]) + ("  …" if len(names) > 4 else ""), style="green")
        rows.append(("owned_view", lab, True))
        for s in sorted(app.owned, key=lambda s: short(g, s).lower()):
            if s == app.start:
                continue                          # the start's right is already shown above
            pw = start_power(g, s)
            if pw:
                right, cnt, _effect = pw
                rows.append((s, Text(f"{pad}{short(g, s)}: {right} ×{cnt}", style="red"), True))
    else:
        rows.append(("owned_view", Text(f"{'OWNED':<8}none — highlight a node and press Ctrl+O",
                                        style="bold grey62"), False))
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


class Overview(VerticalScroll):
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

    def __init__(self, g, sids, title, prof_cache, show_kind=True, escalation=False):
        super().__init__()
        self.g = g
        self.all_sids = list(sids)
        self.title = title
        self.prof = prof_cache
        self.show_kind = show_kind
        self.escalation = escalation        # add an ESCALATION column (route to high-value)
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
        for key, what in (("click a column header", "sort + search that column"),
                          ("^s", "set start"), ("^o", "own"),
                          ("^e", "enabled-only"), ("^x", "export")):
            t.append(f" {key} ", style="bold black on grey58")
            t.append(f" {what}   ", style="grey70")
        return t

    def on_mount(self):
        t = self.query_one("#tbl", DataTable)
        self._col_names = (["NAME"] + (["KIND"] if self.show_kind else [])
                           + (["ESCALATION"] if self.escalation else [])
                           + ["GROUPS", "CTRL", "DESC", "TAGS"])
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

    def _ctrl_count(self, s):
        return sum(1 for (_d, l) in self.g.ctrl.get(s, []) if l != "MemberOf")

    def _is_disabled(self, s):
        n = self.g.nodes.get(s)
        en = n.p("enabled") if n else None
        return en is not None and not bh._truthy(en)

    def _interest_key(self, s):
        g, nm = self.g, short(self.g, s).lower()
        spn = bool(g.nodes[s].p("hasspn") or g.nodes[s].p("serviceprincipalnames")) if s in g.nodes else False
        return (not bh._is_admin(g, s), not bool(g.is_highvalue(s)),
                not spn, -self._ctrl_count(s), nm)                 # interest (all cheap)

    def _col_key(self, s, col):
        g, n = self.g, self.g.nodes.get(s)
        if col == "KIND":
            return (n.kind if n else "?").lower()
        if col == "ESCALATION":
            _s, _h, best = bh._user_profile(g, s)
            return best[1] if best else 999            # fewest hops first
        if col == "GROUPS":
            return len(bh._direct_groups(g, s))
        if col == "CTRL":
            return self._ctrl_count(s)
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
        if col == "ESCALATION":
            return self._escalation(s)[0].lower()
        if col == "GROUPS":
            return ", ".join(bh._group_names(g, s, limit=99)).lower()
        if col == "CTRL":
            return str(self._ctrl_count(s))
        if col == "DESC":
            return self._desc(s).lower()
        if col == "TAGS":
            return node_tags(g, s).plain.strip().lower()
        return short(g, s).lower()                                 # NAME

    def _match(self, s):
        return self.filter.lower() in self._col_text(s, self.search_col)

    def _name_cell(self, s):
        t = Text()
        if s in self.app.owned:
            t.append(f"{OWNED_TAG}  ", style=OWNED_STYLE)
        # no "(User)" suffix here — the table already has a KIND column
        t.append_text(ntext(self.g, s, star=False, priv=self.app.priv, kind=False))
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
        self._rows = rows[:2000]
        for s in self._rows:
            gn = bh._group_names(g, s, limit=2)              # keep the GROUPS column narrow
            grps = ", ".join(gn)
            if len(grps) > 22:
                grps = grps[:21] + "…"
            cells = [self._name_cell(s)]
            if self.show_kind:
                kind = g.nodes[s].kind if s in g.nodes else "?"
                cells.append(Text(kind, style=KIND_COLOR.get(kind, "white")))
            if self.escalation:
                route, reaches = self._escalation(s)
                cells.append(Text(route, style="bold red" if reaches else "grey50"))
            cells += [Text(grps, style="grey70"), self._ctrl_cell(s),
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
        t.border_title = f"{self.title}  ·  {len(rows)} shown  ·  sort: {srt}{scol}{filt}"
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

    def export_to_file(self, preset):
        """Write the current (filtered + sorted) list to a .txt in the working dir."""
        import os
        import time
        rows = self._export_sids()
        slug = "".join(c if c.isalnum() else "_" for c in self.title.lower()).strip("_")[:40]
        path = os.path.join(os.getcwd(), f"bernese_{slug}_{time.strftime('%Y%m%d_%H%M%S')}.txt")
        with open(path, "w") as fh:
            for s in rows:
                fh.write(export_line(self.g, s, preset) + "\n")
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
        sid = self._current_sid()
        if not sid:
            return
        self.app.owned.discard(sid) if sid in self.app.owned else self.app.owned.add(sid)
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

    def compose(self) -> ComposeResult:
        tree = Tree("", id="tree")
        tree.show_root = True
        yield tree

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
        if sid in self.app.owned:
            t.append(f"{OWNED_TAG}  ", style=OWNED_STYLE)
        t.append_text(ntext(g, sid, priv=self.app.priv))
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
        """Map a principal sid -> sorted [(owner_name, "owned"|"start")] for every principal
        that your OWNED set (or the current start) reaches via membership — i.e. owning that
        account gives you this principal's access. Lets a view annotate a holder/group with
        the owned/start principal that already grants it, instead of a duplicate branch."""
        g = self.g
        owned = set(self.app.owned)
        sources = [(p, "owned") for p in owned]
        if self.app.start and self.app.start not in owned:
            sources.append((self.app.start, "start"))
        reach = {}
        for p, src in sources:
            pname = short(g, p)
            for member in bh._principal_closure(g, p):
                reach.setdefault(member, {}).setdefault(pname, src)
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
            if len(tgts) > 15:
                kind = g.nodes[tgts[0]].kind if g.nodes.get(tgts[0]) else "object"
                lab = Text(f"{r} -> ", style="bold magenta" if r in bh._DANGER else "yellow")
                lab.append(f"{len(tgts)} {kind.lower()}s", style="bold")
                juicy = sum(1 for x in tgts if g.nodes.get(x) and g.nodes[x].kind == "Computer"
                            and bh._computer_value(g, x, self.app.priv)[0])
                if juicy:
                    lab.append(f"   {juicy} key targets", style="bold red")
                lab.append("   (Space/Enter drops down)", style="grey50")
                leaf = node.add(lab, data={"listexpand": (f"{r} targets", tgts)})
                leaf.allow_expand = True
            else:
                for d in sorted(tgts, key=lambda s: short(g, s).lower()):
                    child = node.add(self._line(d, r), data={"sid": d, "anc": anc | {d}})
                    child.allow_expand = self._expandable(d, anc | {d})
        return len(by_right)

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

    def _add_path_hops(self, parent, src, dst):
        """Add the shortest control path src -> dst as a NESTED chain under `parent`: each
        hop is a child of the hop before it, so the route reads as one path flowing into
        itself rather than a flat broken-up list. The whole chain is auto-expanded; a hop
        opens its own node info (Enter) to branch off."""
        g, priv = self.g, self.app.priv
        path = g.bfs_path(src, dst)
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

    def _category(self, root, label, sids, style="bold", expand=False):
        g = self.g
        sids = list(dict.fromkeys(sids))
        if not sids:
            return
        cat = root.add(Text(f"{label}  ({len(sids)})", style=style), expand=expand)
        for s in sorted(sids, key=self._list_sort_key)[:INLINE_CAP]:
            child = cat.add(self._line(s), data={"sid": s, "anc": frozenset({s})})
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

    def __init__(self):
        super().__init__()
        self.current = None
        self.history = []

    def compose(self) -> ComposeResult:
        # two SEPARATE trees stacked in one scroll box: the node's own attack tree, and —
        # visually disconnected below it — the out-of-band routes to DA. A separate widget
        # (not a branch off the root) is how we say "these are NOT a path from this node".
        with VerticalScroll(id="treescroll"):
            main = Tree("", id="tree")
            main.show_root = True
            yield main
            owned = Tree("", id="ownedtree")       # your other footholds — its own tree
            owned.show_root = True
            yield owned
            other = Tree("", id="othertree")
            other.show_root = True
            yield other

    def _ctx_label(self):
        return short(self.g, self.current) if self.current else "list"

    # NOTE: no _on_sid_select override — selecting a node opens its node info (the base
    # behaviour) and NEVER re-roots. The start node changes only on Ctrl+S.

    def show_empty(self):
        self.current = None
        self.query_one("#treescroll").border_title = "attack tree — pick a start (menu: Users / Computers)"
        tree = self.query_one("#tree", Tree)
        tree.clear()
        tree.root.set_label(Text("no start node selected", style="grey62"))
        tree.root.data = None
        self.query_one("#ownedtree", Tree).clear()
        self.query_one("#ownedtree", Tree).display = False
        other = self.query_one("#othertree", Tree)
        other.clear(); other.root.set_label(Text("")); other.root.data = None
        self.app.set_detail(intro=Text(
            "Pick a start node (Users / Computers in the menu), then its attack paths appear "
            "here.\n\nSpace/Enter drops a node down; a machine or holder drills into its own "
            "tree. Mark nodes you control with Ctrl+O.", style="grey62"))

    def _fill_other_tree(self):
        """Fill the SEPARATE lower tree with the domain-wide routes to DA that need NO ACL
        chain from the start node — roastable privileged/DA accounts, AS-REP, non-default
        DCSync, ADCS ESC abusers. It is its own tree so it reads as disconnected from the
        node above (these are out-of-band wins, not a path from here)."""
        g, priv = self.g, self.app.priv
        other = self.query_one("#othertree", Tree)
        other.clear()
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

    def _fill_owned_tree(self):
        """Fill the SEPARATE owned tree with your other footholds (every owned principal
        except the current start), each with its route to high-value auto-expanded. It is
        its own tree — like OTHER ROUTES — so the owned set reads as its own thing, not a
        branch of the start node's attack tree. (Ctrl+S on one pivots to it.)"""
        g = self.g
        owned = [s for s in self.app.owned if g.nodes.get(s) and s != self.current]
        tree = self.query_one("#ownedtree", Tree)
        tree.clear()
        if not owned:                              # nothing to show -> hide the tree entirely
            tree.display = False
            return
        tree.display = True
        tree.root.data = None
        tree.root.set_label(banner(f"{OWNED} OWNED SET ({len(owned)}) — your footholds "
                                   "(Ctrl+S pivots)", bg="dark_green"))
        for s in sorted(owned, key=self._list_sort_key):
            child = tree.root.add(self._line(s), data={"sid": s, "anc": frozenset({s})})
            # pre-attach this foothold's shortest route to high-value and auto-expand it,
            # so an owned principal's path is always visible (not hidden behind a pivot).
            tgt = None
            if not g.is_highvalue(s):
                reach = g.reachable(s)
                hvs = [h for h in reach if h != s and g.is_highvalue(h)]
                tgt = min(hvs, key=lambda h: reach[h][0]) if hvs else None
            if tgt is not None:
                child.data["loaded"] = True          # path is the content; don't re-populate
                self._add_path_hops(child, s, tgt)
                child.allow_expand = True
                child.expand()
            else:
                child.allow_expand = self._expandable(s, frozenset({s}))
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
        self.query_one("#treescroll").border_title = (
            f"attack tree: {short(g, sid)}  —  Space/Enter drop down * "
            "i info * ^s set start * ^o owned * Bksp back")
        tree = self.query_one("#tree", Tree)
        tree.clear()
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
        # (the "Controlled by" list is dropped from the attack tree — it is inbound ACLs,
        # not an outbound takeover path; it still lives in node info.)

        # your other footholds + the domain-wide out-of-band wins — each its OWN tree below
        self._fill_owned_tree()
        self._fill_other_tree()
        tree.root.expand()
        kids = [c for c in tree.root.children if (c.data or {}).get("sid")]
        if len(kids) <= 20:
            for c in kids:
                self._populate(c)
                c.expand()
        self._detail(sid)
        tree.focus()

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
        # reload the tree so the OWNED SET section (top of the tree) reflects the change —
        # just relabeling the cursor node would leave the owned footholds stale.
        if self.current:
            self.load(self.current, push=False)
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
        have = "start / owned" if (self.app.owned or self.app.start) else "nothing selected yet"
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
            f"(or are a member of) is flagged {CHECK} with the owned/start principal that "
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
        launch = [n.sid for n in g.nodes.values()
                  if n.kind == "User" and not bh._is_admin(g, n.sid)]
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

    # dangerous rights that take over another account/group (even if the chain never
    # reaches a high-value target — still a privesc the operator will want to walk).
    _TAKEOVER_RIGHTS = {"ForceChangePassword", "GenericAll", "GenericWrite", "WriteDacl",
                        "WriteOwner", "Owns", "Owner", "AddMember", "AddSelf",
                        "AddKeyCredentialLink", "AllExtendedRights"}

    def _lateral_takeover(self, exclude):
        """Principals that can take over another user/group by ACL — the full privesc
        surface, NOT just the chains reaching a high-value node. Counts only DIRECT takeover
        edges on the principal itself, so a user that merely INHERITS a group's rights is not
        duplicated — it is represented by that group (annotated with the owned/start member
        instead). Returns [(sid, n_targets)] widest-first; `exclude` drops the ACL start points."""
        g = self.g
        out = []
        for n in g.nodes.values():
            if n.kind not in ("User", "Group") or bh._is_admin(g, n.sid) or n.sid in exclude:
                continue
            tgts = set()
            for (d, l) in g.ctrl.get(n.sid, []):               # DIRECT edges only
                if l in self._TAKEOVER_RIGHTS:
                    dn = g.nodes.get(d)
                    if dn and dn.kind in ("User", "Group") and d != n.sid:
                        tgts.add(d)
            if tgts:
                out.append((n.sid, len(tgts)))
        out.sort(key=lambda x: (-x[1], short(g, x[0]).lower()))
        return out

    def compose(self) -> ComposeResult:
        # each route family is its OWN tree, stacked in one scroll box — so the sections
        # read as separate, unconnected routes rather than branches off a shared root.
        with VerticalScroll(id="escscroll"):
            for tid in ("esc_cred", "esc_acl", "esc_lat", "esc_foot"):
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

        # --- CREDENTIAL WINS ---
        cred = self.query_one("#esc_cred", Tree).root
        cred.data = None
        cred.set_label(banner("CREDENTIAL WINS — no ACL chain (usually the real path)", bg="dark_red"))
        self._category(cred, "Kerberoastable privileged / DA accounts", roast_priv, "bold red", expand=True)
        self._category(cred, "DCSync-capable (non-default)", sorted(dcsync), "bold red", expand=True)
        self._category(cred, "LAPS readers → local admin", laps, "yellow", expand=True)
        self._category(cred, "ADCS ESC abusers → domain", esc_abusers, "bold red", expand=True)
        if not cred.children:
            cred.add_leaf(Text("none", style="grey50")).allow_expand = False
        cred.expand()

        # --- ACL START POINTS → high-value ---
        starts = self._acl_starts()
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
            child = acl.add(line, data={"sid": s, "anc": frozenset({s}), "loaded": True})
            self._add_path_hops(child, s, tgt)
            child.expand()
        if len(starts) > INLINE_CAP:
            acl.add(Text(f"... +{len(starts) - INLINE_CAP} more (open list)", style="grey50"),
                    data={"list": ("ACL start points", [s for s, _h, _t in starts])}).allow_expand = False
        acl.expand()

        # --- ACL CONTROL OF OTHER ACCOUNTS (lateral takeover) ---
        lateral = self._lateral_takeover(exclude={s for s, _h, _t in starts})
        lat = self.query_one("#esc_lat", Tree).root
        lat.data = None
        lat.set_label(banner(f"ACL CONTROL OF OTHER ACCOUNTS — lateral takeover  ({len(lateral)})", bg="grey30"))
        lat.add_leaf(Text("holds a dangerous right (ForceChangePassword / GenericAll / GenericWrite …) "
                          "over another account — may not reach DA directly, but chain them",
                          style="grey62")).allow_expand = False
        if not lateral:
            lat.add_leaf(Text("none", style="grey50")).allow_expand = False
        reach = self._owned_reach()
        for s, ntgt in lateral[:INLINE_CAP]:
            line = self._line(s)
            line.append(f"   controls {ntgt} account{'s' if ntgt != 1 else ''}", style="yellow")
            self._owned_tag(line, s, reach)          # name the owned/start member, if any
            child = lat.add(line, data={"sid": s, "anc": frozenset({s})})
            child.allow_expand = self._expandable(s, frozenset({s}))
        if len(lateral) > INLINE_CAP:
            lat.add(Text(f"... +{len(lateral) - INLINE_CAP} more (open list)", style="grey50"),
                    data={"list": ("lateral takeover", [s for s, _n in lateral])}).allow_expand = False
        lat.expand()

        # --- FOOTHOLDS any domain user can grab ---
        foot = self.query_one("#esc_foot", Tree).root
        foot.data = None
        foot.set_label(banner("FOOTHOLDS ANY DOMAIN USER CAN GRAB", bg="grey30"))
        self._category(foot, "Kerberoastable", kerb, "yellow")
        self._category(foot, "AS-REP roastable", asrep, "yellow")
        if not foot.children:
            foot.add_leaf(Text("none", style="grey50")).allow_expand = False
        foot.expand()

        self.app.set_detail(intro=Text(
            "Each route is a node — Space/Enter drops it down, Enter on a principal drills "
            "into its own attack tree.", style="grey62"))
        self.query_one("#esc_cred", Tree).focus()


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

    def on_mount(self):
        g = self.g
        tree = self.query_one("#tree", Tree)
        tree.border_title = "domain summary — Space/Enter drop down · Enter drills · Esc back"
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
        self._category(root, "Domain / Enterprise Admins", da, style="bold red", expand=True)
        self._category(root, "Domain controllers", sorted(dcs), style="bold red", expand=True)
        self._category(root, "Kerberoastable users", kerb, style="bold red", expand=True)
        self._category(root, "AS-REP roastable users", asrep, style="yellow")
        self._category(root, "ADCS ESC abusers → domain", esc_abusers, style="bold red", expand=True)
        self._category(root, "Non-default DCSync rights", sorted(dcsync), style="bold red", expand=True)
        self._category(root, "LAPS readers (non-admin → local admin)", laps, style="yellow")
        self._category(root, "Non-admin GPO control", sorted(gpo_ctrl), style="bold red", expand=True)
        self._category(root, "Non-default unconstrained delegation", unc, style="bold red")

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
        return f"{OWNED_TAG}  " if sid in self.app.owned else ""

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
            lab = Text(self._owned(owner), style="bold green")
            lab.append_text(ntext(g, owner, priv=self.app.priv))
            lab.append(f"   owns {len(comps)}", style="cyan")
            onode = cat.add(lab, data={"sid": owner, "comps": comps})
            onode.allow_expand = True
        tree.root.expand()
        self.app.set_detail(intro=Text(
            "Pick an owner or machine — Enter drills into its attack tree.", style="grey62"))
        tree.focus()

    def _cline(self, sid):
        g, t = self.g, Text(self._owned(sid), style="bold green")
        t.append_text(ntext(g, sid, priv=self.app.priv))
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
        reach = g.reachable(sid)
        if len(reach) > 1:
            facts.add_leaf(Text(f"controls {len(reach) - 1} node(s) downstream",
                                style="grey70")).allow_expand = False
        inbound = g.rctrl.get(sid, [])
        if inbound:
            facts.add_leaf(Text(f"controlled by {len(inbound)} principal(s)",
                                style="grey70")).allow_expand = False

    def _on_sid_select(self, sid):
        self.app.show_node_info(sid)                  # drill in place, within the box

    def on_tree_node_selected(self, event: Tree.NodeSelected):
        data = event.node.data or {}
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
        tree.border_title = f"node info: {short(g, sid)}  —  Enter/Space drill · i info on selected · Esc back"
        tree.root.set_label(self._line(sid))
        tree.root.data = {"sid": sid, "anc": frozenset({sid}), "loaded": True}
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
        self._category(tree.root, "Controlled by", [s for (s, l) in g.rctrl.get(sid, [])])
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
    """Pick the fields, then write the table's current (filtered + sorted) rows to a
    .txt in the working directory."""
    BINDINGS = [Binding("escape", "back", "Cancel")]

    def __init__(self, table):
        super().__init__()
        self.table = table

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        opts = [Option(Text(label), id=fid) for fid, label in EXPORT_PRESETS]
        ol = OptionList(*opts, id="exportlist")
        n = len(self.table._export_sids())
        ol.border_title = f"export {n} rows from “{self.table.title}” — pick fields · Enter · Esc cancel"
        yield ol
        yield Footer()

    def on_mount(self):
        self.query_one("#exportlist", OptionList).focus()

    def action_back(self):
        self.app.pop_screen()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected):
        path, count = self.table.export_to_file(event.option.id)
        self.app.pop_screen()
        self.app.notify(f"Exported {count} rows → {path}", title="Export", timeout=8)


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
        Binding("ctrl+s", "set_start", "Set as start"),
        Binding("ctrl+o", "owned", "Mark owned"),
        Binding("ctrl+c", "quit", "Quit", priority=True),
        Binding("ctrl+q", "quit", "Quit", priority=True),
    ]

    # (id, label).  COUNTABLE items grey out + read "none" at 0 instances.
    MENU = [
        ("users", "Users (browse / set start)"),
        ("computers", "Computers (browse / set start)"),
        ("groups", "Groups (browse / read into)"),
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
    def _build_start_picker(self):
        sids = [s for s, n in self.g.nodes.items() if n.kind in ("User", "Computer")]
        self._mount_aux(PrincipalTable(self.g, sids, "Set start node — users + computers",
                                       self.app.prof, show_kind=True))

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

    def action_set_start(self):
        """Set the highlighted node (in any view) as the start node and show its tree.
        In a principal list Ctrl+S cycles sort instead (handled by the list itself)."""
        sid = self._active_sid()
        if sid:
            self.app.open_start(sid)

    def action_owned(self):
        if self._tree_live():
            self._view.act_owned()
        elif isinstance(self._aux, PrincipalTable):
            self._aux.mark_owned()
        elif isinstance(self._aux, AttackTreeBase):        # node info / escalation / rights …
            self._aux.toggle_owned_cursor()
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
        if mid in g.nodes:                  # an overview row keyed by a sid (e.g. an owned
            self.open_start(mid)            # foothold's privesc row) → open that node's tree
            return
        if mid in ("start", "start_tree", "start_path", "owned_view"):
            # overview position rows: show the start's (or an owned node's) attack tree,
            # which carries the shortest-path chain + owned set; otherwise go pick one.
            tgt = self.app.start or next(iter(self.app.owned), None)
            if tgt:
                self.open_start(tgt)
            else:
                self.dispatch("users")
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
                self.show_view()
            else:
                self.dispatch("users")
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
    #jump { height: auto; background: transparent; border: none; }
    #sidedetailbox { height: 13; border: round $secondary; padding: 0 1; }
    #sidedetail { height: auto; }
    #box { width: 1fr; height: 1fr; }
    #view { height: 1fr; }
    #tree { height: 1fr; border: round $primary; padding: 0 1; }
    /* stacked section trees (attack tree + other-routes, escalation sections): the scroll
       box carries the border; each inner tree is borderless, auto-height, with a gap below
       so the separate trees read as distinct, disconnected sections. */
    #treescroll, #escscroll { height: 1fr; border: round $primary; padding: 0 1; }
    #treescroll Tree, #escscroll Tree {
        height: auto; border: none; background: transparent; margin: 0 0 1 0;
    }
    #niview { height: 1fr; }
    #exportlist { height: auto; max-height: 80%; border: round $primary; margin: 1 2; }
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
        layer: version; dock: bottom; height: 1; width: 100%;
        content-align: right middle; padding: 0 1;
        background: transparent; color: $text-muted;
    }
    """
    TITLE = "bernese"

    def __init__(self, g):
        super().__init__()
        bh.C.enabled = False      # TUI renders colour via rich, not ANSI
        self.g = g
        self.priv = bh._priv_set(g)
        self.prof = {}                      # sid -> (_user_profile) cache, shared across screens
        self.power = {}                     # has_power memo (dead-end membership pruning)
        self.owned = set()                  # sids the operator has marked as owned
        self.start = None                   # current start node (its tree is shown on Home)
        self.sub_title = (g.domain_name or "?")

    def on_mount(self):
        self.push_screen(HomeScreen(self.g))

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
