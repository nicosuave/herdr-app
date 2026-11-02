# Herdr — Rex backend

Herdr is a desktop app for terminals and coding agents. Keep work in spaces, see which agents need you, and leave terminals running when you close the window.

## Why this fork exists

The [canonical Herdr app](https://github.com/herdrdev/herdr-app) runs its terminals on [herdr-core](https://github.com/herdrdev/herdr-core). This fork builds on [Nico's Rex integration](https://github.com/nicosuave/herdr-app/tree/rex-backend) to use a [Rex](https://www.superlogical.com/rex/docs) server instead. It is for people who already use Rex and want Herdr's native desktop interface over the same terminals and sessions, rather than a separate set managed by herdr-core.

The goal is to keep Herdr's UI, layouts, mods and agent workflow current with canonical Herdr while changing the terminal backend—not to replace the desktop app with a new UI. **This is an experimental integration, not full herdr-core feature parity.** The limitations below matter, especially when the app and Rex run on different computers.

| | Canonical Herdr | This fork's Rex backend |
|---|---|---|
| Runs terminals | herdr-core | Rex server |
| Connects the window | herdr-core's `hc connect` | Built-in `rex-core` bridge ([src/rex](src/rex)) |
| Spaces / tabs / terminal panes | herdr-core's shared layout | Rex sessions / windows / terminal blocks |
| Installation | Official Herdr releases | Build the `rex-backend` branch from source |

On macOS and Linux, Rex is the default backend. `HERDR_APP_BACKEND=herdr-core` selects the original herdr-core path. The Rex bridge is Unix-only; Windows uses herdr-core.

### What is shared with Rex

- Rex owns the terminals and the session/window/split structure. Existing Rex sessions appear as Herdr spaces, and structural changes are reflected between the two clients, subject to the layout limits below.
- Rex program-status reports (OSC 7501) feed Herdr's agents sidebar and peek views.
- Closing the Herdr window leaves terminals running in Rex. Closing a terminal pane or tab acts on those Rex terminals; this is not a read-only viewer.
- Herdr-specific metadata—terminal addresses and labels, a space's folder, mod panels and pane sizes—stays under `rex/` in the app's home, not in herdr-core.

### Current limitations

- **Files and Changes need the app's filesystem.** Mod commands such as `herdr.exec`, file reads and folder watches still run where the desktop app runs. Connecting to Rex through a tunnel does not route these operations to the server. A server-only repo path will not work in the laptop's Files/Changes panels; use the app on the same machine/filesystem for those features.
- **No built-in multi-machine support.** Settings → Machines and `--on` are not supported by the Rex bridge. It accepts `unix://` endpoints, not TCP or SSH addresses. A manually configured SSH Unix-socket tunnel can carry the terminal connection, but does not remove the filesystem limitation above.
- **Not an `hc` replacement.** The bridge implements the protocol the app needs, not the full herdr-core CLI. Use Rex's CLI to run and coordinate Rex programs; `hc` commands still target herdr-core.
- **Layout differences remain.** Rex cannot move a terminal between sessions, so dragging a pane to another space is reverted. Pane sizes do not sync between clients, and floating Rex panes are not shown.
- **File drops onto remote terminals are not supported.**

## Install

### Build this fork for Rex

Follow [Build from source](#build-from-source) below. The official installers do **not** install this fork or its Rex bridge.

Start Rex (`rex server start`, or open Rex for Mac), then launch the built app. It discovers the server through `rex whoami --json`; `REX_BIN_DIR` can point to the folder containing the Rex CLI. To select a socket explicitly, set `REX_SERVER=unix:///absolute/path/to/server.sock` when launching the app; this also works without the Rex CLI installed locally.

The fork uses the same app home as canonical Herdr by default. For a separate configuration while trying it, launch the installed build with:

```sh
HERDR_APP_HOME="$HOME/.config/herdr-app-rex" herdr-app
```

A separate app home keeps Herdr settings and bridge metadata apart; it does **not** isolate the Rex server or copy its sessions. Choose a separate Rex server/socket if you need isolated test terminals. No existing herdr-core terminals are migrated to Rex.

### Canonical Herdr releases (not the Rex build)

Use these only if you want the original herdr-core-backed app. Installing one over a source build replaces it with canonical Herdr.

#### Linux and macOS

```sh
curl -fsSL https://releases.herdr.dev/app/install.sh | sh
```

Linux needs a desktop session and a working Vulkan driver. macOS builds are available for Apple Silicon; Intel Mac users can [build from source](#build-from-source). Linux builds are x86-64 and ARM64.

The installer adds Herdr to your apps and puts the command in `~/.local/bin`.
Add that folder to your PATH if the installer asks.
On macOS the app lives in `~/Applications/Herdr.app`.
For drag-and-drop installation on Apple Silicon, download [Herdr.dmg](https://releases.herdr.dev/app/Herdr.dmg) and drag Herdr to Applications.

#### Windows

Run in PowerShell on x64 Windows with curl and tar installed (Windows 10 1803 or newer):

```powershell
irm https://releases.herdr.dev/app/install.ps1 | iex
```

Herdr appears in the Start menu. The installer adds `%LOCALAPPDATA%\Programs\herdr-app` to your user PATH. Open a new terminal to pick it up.

Both installers download and run code. Read the [shell installer](distribution/install.sh) or [PowerShell installer](distribution/install.ps1) first if you prefer.
They also install [herdr-core](https://github.com/herdrdev/herdr-core) if it is missing.
The app can help install or update a core it cannot use.

## Find your work

A **space** holds work on one machine, usually in one repo. Each space has **tabs**. Split a tab into **panes** to put terminals or mod panels beside each other.

An unnamed space follows its first terminal's folder. Name a space or tab when you want a label that stays.
New tabs start in the focused terminal's folder.

The agents sidebar brings agents from your spaces into one list, including workers started by another agent.
Agents that report status show as:

- **Working:** still busy.
- **Blocked:** waiting for you.
- **Done:** finished while you were looking elsewhere.
- **Idle:** not working, or a finished agent you have looked at.

Click an agent to see it. A worker without a pane opens in **peek**, over your tab. Keep it as a tab if you want it beside your other work.
Ctrl-click a live terminal address in terminal text to peek at it; use Cmd-click on macOS.
An address such as `t7` means a terminal on the same machine as the terminal showing it. `vps/t7` names one on another machine.

The window arranges terminals; the selected backend (Rex or herdr-core) runs them.
Closing the window leaves them running; closing a pane or tab ends its terminals.
With herdr-core, after a reboot or core crash, kept panes get fresh shells in their last folders, not their old programs. Rex's own persistence and recovery govern Rex terminals.

## Work on another machine

**The following built-in SSH workflow requires the herdr-core backend.** The Rex backend's socket/tunnel support and filesystem limits are described [above](#current-limitations).

Add an SSH machine from Settings → Machines or the sidebar's Add machine action.
Pick a host from your SSH config or type how SSH reaches it.
Spaces on that machine run their terminals there, not on your computer.

Each machine keeps its spaces, tabs and splits in its core. Connected screens share that structure and the live terminals, but keep their own focus and zoom.
Remote work keeps running when your local window closes or your laptop sleeps, as long as the remote machine and core stay up.

## Make it yours

Open the command palette to find an action by name, or open Settings to change fonts, colors, sounds and other preferences.
The built-in layouts include Herdr, Terminals and Herdr 98.
A **layout** arranges the window. **Mods** are small JavaScript programs that draw its panels, menus and dialogs.

Duplicate a shipped layout or mod before changing its structure or code. Your copies stay yours; Herdr updates the shipped ones on start.
Save a personal layout, mod or key file and the window reloads it.
A broken edit keeps the last good version and reports the error.

Ctrl+Shift+P shows every command and its key (Cmd+Shift+P on macOS). Change any key in `keys.json`; see [the keys section](defaults/AGENTS.md#keys-keysjson) of the mod guide for the format.

[Layouts and mods](docs/mods.md) · [Commands](docs/commands.md)

## Updates and privacy

Installed releases check for updates in the background and download a new app beside the running one. It takes over when you quit and reopen, or choose the update action. Your terminals keep running in the core.
Settings → Updates shows what is available. What's New opens after an update; you can open it again from the command palette.
Builds from source do not update themselves.

Usage telemetry is on by default in releases. Turn it off in Settings → Privacy.
Mods are trusted code, not sandboxed extensions. Read [security and privacy](docs/security.md) before installing someone else's mod.

## For agents

```sh
herdr-app --skill
```

This prints the agent guide for driving the window. Use the app to change what you see, and the selected backend's CLI to run and coordinate programs: Rex's `rex` for this fork's default backend, or `hc` for herdr-core. The inherited herdr-core examples in the guides require `HERDR_APP_BACKEND=herdr-core`; they do not become Rex commands automatically.

```sh
herdr-app ls
herdr-app status
herdr-app commands
```

The first two inspect the open window. The command list also works without one.
See the [command reference](docs/commands.md) for arguments.

## Build from source

For bugs, mod API requests and code contributions, see [Contributing](CONTRIBUTING.md).

Clone the **Rex branch**, not canonical Herdr's `master`, with its submodules. The commands below use Nico's fork; substitute your fork's URL and branch to build a downstream version. Use Rust 1.95.0 and Zig 0.16.0, the versions used in [CI](.github/workflows/ci.yml).
Linux needs the development packages listed in that workflow.

```sh
git clone --branch rex-backend --recurse-submodules https://github.com/nicosuave/herdr-app.git
cd herdr-app
just build
just test
just install
```

Install [just](https://github.com/casey/just) to use these recipes.
The tests also need [Bun](https://bun.sh).
The platform installer builds a release and adds the app to your desktop.
On Linux it links to this checkout, so keep the checkout in place.
Quit and reopen Herdr to use the new build.

Documentation checks also need [Bun](https://bun.sh): `just docs-check` checks generated pages and CLI examples; `just docs-generate` refreshes the reference pages.

To compare drawing changes on Windows, Linux or macOS, run the same fixed workloads against each build:

```sh
python scripts/bench.py --bin <app executable> --set spinners --seconds 20
```

The runner requires the herdr-core backend (`HERDR_APP_BACKEND=herdr-core`) and `hc` on PATH; it does not benchmark the Rex bridge. It uses the Python executable running the script. It prints a unique artifact folder with the run settings, counters and results, then stops its private app, terminals and core. Both sets use Python fixture programs; the default set’s TUI workload replaces historical `btop` measurements. `--only spinners` measures just the quiet native spinner scenario. Keep the window visible and the display awake, and compare the same window activity and display settings; inactive windows may draw at a lower rate. Windows records visibility, foreground activity and display Hz at each measurement boundary; other platforms mark these observations unavailable. Visibility does not establish occlusion. Draws are window render calls. Render-to-paint elapsed time stops before scene finalization, backend drawing, uploads and presentation; it is separate from OS process CPU time. Neither measures physical presentation or the FPS HUD’s derived MAX FPS.

`python scripts/bench_compare.py ghostty --root <artifact folder>` reuses a run’s fake agent for the macOS comparison. Benchmark checks: `python -m unittest discover -s scripts -p test_bench.py`.
