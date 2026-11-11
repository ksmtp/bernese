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
inspects a node, **Ctrl+S** sets the start node, **Ctrl+O** marks a node owned, **Esc**
goes back.

Run `bernese -d <data> --help` for the full list of one-off CLI subcommands.

## License

MIT — see [LICENSE](LICENSE).
