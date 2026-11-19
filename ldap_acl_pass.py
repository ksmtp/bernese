#!/usr/bin/env python3
"""Supplemental ACL collector for bernese.

Some collectors (RustHound-CE 2.5.x, for one) don't emit every ACL edge that exists in
the directory — WriteAccountRestrictions and ReadLAPSPassword are the usual casualties.
This reads the security descriptors over LDAP and writes a small BloodHound-CE-shaped
zip that you merge back in:

    python3 ldap_acl_pass.py --dc-ip 10.0.0.1 -d corp.local -u analyst -p -
    bernese.py -d corp-collection.zip -d corp.local_bernese-acl.zip

It only reads (DACL + owner); it does not touch the directory. Needs `ldap3`
(`pip install ldap3`). Run it from a host that can reach the DC, with directory-read
credentials — the same ones you'd give any BloodHound collector.

The security-descriptor parser is self-contained; `--selftest` exercises it with no DC.
"""
import argparse
import getpass
import json
import os
import struct
import sys
import zipfile

# --- access-mask bits (AD object rights) ----------------------------------- #
GENERIC_ALL   = 0x10000000
GENERIC_WRITE = 0x40000000
WRITE_DACL    = 0x00040000
WRITE_OWNER   = 0x00080000
DS_WRITE_PROP = 0x00000020
DS_READ_PROP  = 0x00000010
DS_CONTROL    = 0x00000100
DS_SELF       = 0x00000008
FULL_CONTROL  = 0x000F01FF

# --- rights-GUID map (property sets / extended rights / attributes) --------- #
ACCOUNT_RESTRICTIONS = "4c164200-20c0-11d0-a768-00aa006e0529"   # property set
FORCE_CHANGE_PW      = "00299570-246d-11d0-a768-00aa006e0529"   # extended right
MEMBER_ATTR          = "bf9679c0-0de6-11d0-a285-00aa003049e2"   # member attribute
KEYCRED_ATTR         = "5b47d60f-6090-40b2-9f37-2a4de88f3063"   # msDS-KeyCredentialLink
SPN_ATTR             = "f3a64788-5306-11d1-a9c5-0000f80367c1"   # servicePrincipalName
GET_CHANGES          = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GET_CHANGES_ALL      = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
GET_CHANGES_FILTERED = "89e95b76-444d-4c62-991a-0facbeda640c"

# ACE types we read (allow only)
ACCESS_ALLOWED      = 0x00
ACCESS_ALLOWED_OBJ  = 0x05
INHERITED_ACE       = 0x10
ACE_OBJECT_PRESENT  = 0x01

# trustees that are default/noise — their control is built in, not interesting as an edge
SKIP_SIDS = {"S-1-5-18", "S-1-5-10", "S-1-3-0", "S-1-5-20", "S-1-5-9", "S-1-5-32-548"}


def _guid_str(b):
    """16-byte GUID (mixed-endian, as stored in an SD) -> canonical string."""
    a = struct.unpack("<IHH", b[:8])
    return "%08x-%04x-%04x-%02x%02x-%s" % (
        a[0], a[1], a[2], b[8], b[9], b[10:16].hex())


def _sid_str(b):
    """Binary SID -> S-1-... string."""
    if len(b) < 8:
        return None
    rev = b[0]
    count = b[1]
    authority = int.from_bytes(b[2:8], "big")
    subs = struct.unpack("<%dI" % count, b[8:8 + 4 * count])
    return "S-%d-%d%s" % (rev, authority, "".join("-%d" % s for s in subs)), 8 + 4 * count


def ace_to_rights(ace_type, mask, obj_guid, laps_guids):
    """Map one allow-ACE to the bernese right names it grants (may be several/none)."""
    rights = []
    if (mask & GENERIC_ALL) or (mask & FULL_CONTROL) == FULL_CONTROL:
        return ["GenericAll"]                         # full control subsumes the rest
    if mask & WRITE_DACL:
        rights.append("WriteDacl")
    if mask & WRITE_OWNER:
        rights.append("WriteOwner")
    if mask & GENERIC_WRITE:
        rights.append("GenericWrite")
    g = (obj_guid or "").lower()
    if ace_type == ACCESS_ALLOWED_OBJ and g:
        if mask & DS_WRITE_PROP:
            rights.append({ACCOUNT_RESTRICTIONS: "WriteAccountRestrictions",
                           MEMBER_ATTR: "AddMember", KEYCRED_ATTR: "AddKeyCredentialLink",
                           SPN_ATTR: "WriteSPN"}.get(g, None))
        if (mask & DS_SELF) and g == MEMBER_ATTR:
            rights.append("AddSelf")
        if mask & DS_CONTROL:
            if g == FORCE_CHANGE_PW:
                rights.append("ForceChangePassword")
            elif g == GET_CHANGES:
                rights.append("GetChanges")
            elif g == GET_CHANGES_ALL:
                rights.append("GetChangesAll")
            elif g == GET_CHANGES_FILTERED:
                rights.append("GetChangesInFilteredSet")
            elif g in laps_guids:
                rights.append("ReadLAPSPassword")
        if (mask & DS_READ_PROP) and g in laps_guids:
            rights.append("ReadLAPSPassword")
    elif not g:                                       # ACE with no ObjectType = all of it
        if mask & DS_WRITE_PROP:
            rights.append("GenericWrite")
        if mask & DS_CONTROL:
            rights.append("AllExtendedRights")
    return [r for r in rights if r]


def parse_dacl(sd, laps_guids):
    """Parse a binary nTSecurityDescriptor; yield (trustee_sid, right, is_inherited)."""
    if not sd or len(sd) < 20:
        return
    offset_dacl = struct.unpack("<I", sd[16:20])[0]
    if not offset_dacl or offset_dacl + 8 > len(sd):
        return
    ace_count = struct.unpack("<H", sd[offset_dacl + 4:offset_dacl + 6])[0]
    pos = offset_dacl + 8
    for _ in range(ace_count):
        if pos + 4 > len(sd):
            break
        ace_type = sd[pos]
        ace_flags = sd[pos + 1]
        ace_size = struct.unpack("<H", sd[pos + 2:pos + 4])[0]
        body = sd[pos + 4:pos + ace_size]
        pos += ace_size
        if ace_type not in (ACCESS_ALLOWED, ACCESS_ALLOWED_OBJ) or len(body) < 4:
            continue
        mask = struct.unpack("<I", body[:4])[0]
        obj_guid = None
        off = 4
        if ace_type == ACCESS_ALLOWED_OBJ:
            if len(body) < 8:
                continue
            flags = struct.unpack("<I", body[4:8])[0]
            off = 8
            if flags & ACE_OBJECT_PRESENT:
                obj_guid = _guid_str(body[off:off + 16]); off += 16
            if flags & 0x02:                          # inherited-object-type present
                off += 16
        sid_res = _sid_str(body[off:])
        if not sid_res:
            continue
        trustee = sid_res[0]
        if trustee in SKIP_SIDS:
            continue
        inherited = bool(ace_flags & INHERITED_ACE)
        for right in ace_to_rights(ace_type, mask, obj_guid, laps_guids):
            yield trustee, right, inherited


# --- LDAP collection ------------------------------------------------------- #
BH_TYPE = {"user": "users", "computer": "computers", "group": "groups",
           "domain": "domains", "organizationalunit": "ous",
           "grouppolicycontainer": "gpos", "container": "containers"}


def _object_kind(classes):
    cl = {str(c).lower() for c in (classes or [])}
    for k in ("computer", "group", "domain", "organizationalunit",
              "grouppolicycontainer", "user", "container"):
        if k in cl:
            return k
    return "user"


def collect(args, password):
    import ldap3
    from ldap3.protocol.microsoft import security_descriptor_control

    user = "%s\\%s" % (args.domain.split(".")[0], args.user)
    server = ldap3.Server(args.dc_ip, use_ssl=args.ldaps,
                          port=636 if args.ldaps else 389, get_info=ldap3.NONE)
    conn = ldap3.Connection(server, user=user, password=password,
                            authentication=ldap3.NTLM, auto_bind=False)
    if not conn.bind():
        raise SystemExit("[!] LDAP bind failed: %s" % conn.result.get("description"))
    base = "dc=" + ",dc=".join(args.domain.split("."))

    # LAPS attribute schemaIDGUIDs (so ReadLAPSPassword ACEs can be recognised)
    laps_guids = set()
    schema = "cn=schema,cn=configuration," + base
    if conn.search(schema,
                   "(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=msLAPS-Password)"
                   "(lDAPDisplayName=msLAPS-EncryptedPassword))",
                   search_scope=ldap3.SUBTREE, attributes=["schemaIDGUID"]):
        for e in conn.entries:
            raw = e["schemaIDGUID"].raw_values[0]
            laps_guids.add(_guid_str(raw).lower())

    sd_ctrl = security_descriptor_control(sdflags=0x05)     # OWNER + DACL (no SACL)
    by_type = {}                                            # bh-type -> [objects]
    count_aces = 0
    cookie = None
    objfilter = "(|(objectClass=user)(objectClass=computer)(objectClass=group)" \
                "(objectClass=groupPolicyContainer)(objectClass=domain)" \
                "(objectClass=organizationalUnit))"
    while True:
        conn.search(base, objfilter, search_scope=ldap3.SUBTREE,
                    attributes=["objectSid", "sAMAccountName", "name", "objectClass",
                                "nTSecurityDescriptor"],
                    controls=sd_ctrl, paged_size=500, paged_cookie=cookie)
        for e in conn.entries:
            sid_vals = e["objectSid"].raw_values if "objectSid" in e else []
            if not sid_vals:
                continue
            sid = _sid_str(sid_vals[0])
            sid = sid[0] if sid else None
            if not sid:
                continue
            sd_vals = e["nTSecurityDescriptor"].raw_values if "nTSecurityDescriptor" in e else []
            if not sd_vals:
                continue
            aces = []
            seen = set()
            for trustee, right, inh in parse_dacl(sd_vals[0], laps_guids):
                key = (trustee, right)
                if key in seen:
                    continue
                seen.add(key)
                aces.append({"PrincipalSID": trustee, "PrincipalType": "Base",
                             "RightName": right, "IsInherited": inh})
            if not aces:
                continue
            count_aces += len(aces)
            kind = _object_kind(e["objectClass"].values if "objectClass" in e else [])
            name = (e["sAMAccountName"].value if "sAMAccountName" in e and e["sAMAccountName"].value
                    else (e["name"].value if "name" in e else sid))
            dom = args.domain.upper()
            disp = ("%s@%s" % (name, dom)) if "@" not in str(name) else name
            by_type.setdefault(BH_TYPE[kind], []).append(
                {"ObjectIdentifier": sid, "Properties": {"name": disp.upper()}, "Aces": aces})
        controls = conn.result.get("controls", {})
        cookie = controls.get("1.2.840.113556.1.4.319", {}).get("value", {}).get("cookie")
        if not cookie:
            break
    conn.unbind()
    return by_type, count_aces, sorted(laps_guids)


def write_zip(by_type, out_path):
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as z:
        for bh_type, objs in by_type.items():
            blob = {"data": objs,
                    "meta": {"type": bh_type, "count": len(objs), "version": 6,
                             "collectorversion": "bernese-ldap-acl 1.0"}}
            z.writestr("%s.json" % bh_type, json.dumps(blob))


# --- self-test (no DC) ----------------------------------------------------- #
def _build_object_ace(mask, obj_guid_hex, trustee_sid_bytes, inherited=False):
    flags = INHERITED_ACE if inherited else 0
    body = struct.pack("<II", mask, ACE_OBJECT_PRESENT) + bytes.fromhex(obj_guid_hex) + trustee_sid_bytes
    return bytes([ACCESS_ALLOWED_OBJ, flags]) + struct.pack("<H", 4 + len(body)) + body


def _guid_to_sd_bytes(guid):
    f = guid.split("-")
    return (struct.pack("<I", int(f[0], 16)) + struct.pack("<H", int(f[1], 16))
            + struct.pack("<H", int(f[2], 16)) + bytes.fromhex(f[3]) + bytes.fromhex(f[4]))


def _sid_to_bytes(s):
    parts = s.split("-")
    subs = [int(x) for x in parts[3:]]
    return bytes([int(parts[1]), len(subs)]) + int(parts[2]).to_bytes(6, "big") \
        + b"".join(struct.pack("<I", x) for x in subs)


def selftest():
    ok = True
    # round-trip a GUID through the SD byte layout
    assert _guid_str(_guid_to_sd_bytes(ACCOUNT_RESTRICTIONS)).lower() == ACCOUNT_RESTRICTIONS
    trustee = "S-1-5-21-1-2-3-1105"
    tb = _sid_to_bytes(trustee)
    # build a DACL with WriteAccountRestrictions + ForceChangePassword + a GenericAll
    aces = (_build_object_ace(DS_WRITE_PROP, _guid_to_sd_bytes(ACCOUNT_RESTRICTIONS).hex(), tb)
            + _build_object_ace(DS_CONTROL, _guid_to_sd_bytes(FORCE_CHANGE_PW).hex(), tb)
            + _build_object_ace(GENERIC_ALL, _guid_to_sd_bytes(MEMBER_ATTR).hex(), tb, inherited=True))
    acl = struct.pack("<BBHHH", 4, 0, 8 + len(aces), 3, 0) + aces
    sd = struct.pack("<BBH", 1, 0, 0x8004) + struct.pack("<IIII", 0, 0, 0, 20) + acl
    got = list(parse_dacl(sd, {ACCOUNT_RESTRICTIONS.lower()}))
    rights = sorted(r for _s, r, _i in got)
    expect = ["ForceChangePassword", "GenericAll", "WriteAccountRestrictions"]
    if rights != expect:
        print("  [FAIL] parsed rights %s != %s" % (rights, expect)); ok = False
    if any(s != trustee for s, _r, _i in got):
        print("  [FAIL] trustee SID mismatch"); ok = False
    if not any(i for _s, _r, i in got):
        print("  [FAIL] inherited flag lost"); ok = False
    # LAPS read via ControlAccess on the LAPS attribute GUID
    laps = "11111111-2222-3333-4444-555555555555"
    sd2aces = _build_object_ace(DS_CONTROL, _guid_to_sd_bytes(laps).hex(), tb)
    acl2 = struct.pack("<BBHHH", 4, 0, 8 + len(sd2aces), 1, 0) + sd2aces
    sd2 = struct.pack("<BBH", 1, 0, 0x8004) + struct.pack("<IIII", 0, 0, 0, 20) + acl2
    if [r for _s, r, _i in parse_dacl(sd2, {laps})] != ["ReadLAPSPassword"]:
        print("  [FAIL] LAPS-read ACE not recognised"); ok = False
    print("  [ok] SD/ACE parser maps WriteAccountRestrictions / ForceChangePassword / "
          "GenericAll / ReadLAPSPassword" if ok else "  [FAIL] selftest")
    return ok


def main():
    ap = argparse.ArgumentParser(description="Supplemental LDAP ACL collector for bernese.")
    ap.add_argument("--dc-ip", help="domain controller IP/host")
    ap.add_argument("-d", "--domain", help="FQDN, e.g. corp.local")
    ap.add_argument("-u", "--user", help="directory-read username (no domain prefix)")
    ap.add_argument("-p", "--password", help="password; omit or '-' to be prompted")
    ap.add_argument("--hashes", help="LM:NT (or :NT) for pass-the-hash instead of a password")
    ap.add_argument("--ldaps", action="store_true", help="use LDAPS (port 636)")
    ap.add_argument("-o", "--output", help="output zip (default <domain>_bernese-acl.zip)")
    ap.add_argument("--selftest", action="store_true", help="run the parser self-test and exit")
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(0 if selftest() else 1)
    if not (args.dc_ip and args.domain and args.user):
        ap.error("--dc-ip, -d/--domain and -u/--user are required (or use --selftest)")
    if args.hashes:
        password = args.hashes if ":" in args.hashes else ":" + args.hashes
    else:
        password = args.password
        if not password or password == "-":
            password = getpass.getpass("Password for %s\\%s: " % (args.domain, args.user))

    try:
        import ldap3  # noqa: F401
    except ImportError:
        raise SystemExit("[!] needs ldap3 — pip install ldap3")

    by_type, n_aces, laps = collect(args, password)
    out = args.output or (args.domain + "_bernese-acl.zip")
    write_zip(by_type, out)
    objs = sum(len(v) for v in by_type.values())
    print("[*] %d supplemental ACE(s) on %d object(s) -> %s" % (n_aces, objs, out))
    if laps:
        print("[*] LAPS attribute GUID(s): %s" % ", ".join(laps))
    print("[*] merge:  bernese.py -d <main-collection> -d %s" % out)


if __name__ == "__main__":
    main()
