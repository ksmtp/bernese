# bernese

Interactive terminal explorer for **BloodHound CE / RustHound-CE** data — triage Active
Directory attack paths and privilege-escalation routes from the command line.

One file, `bernese.py`. Python 3.8+.

## Install

With [pipx](https://pipx.pypa.io) (sets up the TUI deps in an isolated venv and puts
`bernese` on your PATH):

```bash
pipx install git+https://github.com/ksmtp/bernese
```

Update an existing install to the latest version:

```bash
pipx reinstall bernese
```

Or just copy `bernese.py` and run it — the CLI and the fallback text menu are
standard-library only. The full-screen TUI additionally needs `textual` + `rich`:

```bash
pip install textual rich
```

## Use

```bash
bernese -d <collection.zip | dir-of-json | file.json>     # interactive
bernese -d <data> summary                                 # one-off CLI output
```

`-d` accepts a SharpHound/RustHound-CE `.zip`, a directory of `*.json`, or a single
`.json`. With no subcommand you get the full-screen TUI (or a basic text menu if
`textual`/`rich` aren't installed).

In the TUI, pick a start node and drill through its attack tree, escalation routes,
rights, delegation, ADCS/ESC abuse, and node detail. **Enter/Space** expands, **i**
inspects a node, **Ctrl+S** sets the start node, **Ctrl+O** marks a node owned (the first
one you own becomes the start if none is set), **Esc** goes back. **u** / **c** / **g** /
**a** jump to Users, Computers, Groups and the attack tree.

Paths it chains:

- ACL abuse (GenericAll/Write, WriteDacl/Owner, ForceChangePassword, AddMember,
  shadow credentials, RBCD, LAPS/gMSA reads, GPO control), DCSync
- Lateral movement: local admin, RDP, WinRM, DCOM, MSSQL admin, sessions of logged-on
  users, SID history
- ADCS: ESC1/2/3/4/8/9/13/15 chained into paths (ESC6/7 flagged), with ready-to-paste
  certipy commands
- Domain trusts: forest root / child / external, and SID-history abuse across a trust
  when SID filtering allows it

Run `bernese -d <data> --help` for the full list of one-off CLI subcommands.

## License

MIT — see [LICENSE](LICENSE).
