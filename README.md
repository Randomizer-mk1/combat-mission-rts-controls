# Combat Mission RTS Controls

Camera Control Fix **2.04** brings RTS-style camera controls and more readable battle UI to Combat Mission games using the CMx2 engine.

Install once, then launch through Steam and press **Play** in the normal Slitherine launcher. Nothing starts at Windows login, and the game-local helper exits when the game closes.

## What it changes

- Constant-speed WASD movement, Q/E orbit, middle-mouse camera dragging, and cursor-directed mouse-wheel movement.
- Camera fixes for map-edge scrolling, mouse-drag delay, and the unwanted facing reset after selecting a unit with Tab.
- Uniform enlargement of the bottom combat HUD, preserving the panel proportions and matching mouse hit areas. The final HUD size is 30% smaller in each dimension than the earlier enlarged candidate.
- More readable briefing text and corrected HUD lifecycle handling.

Shadow experiments, font replacement packs, and an unfinished troop-selection-list redesign are not included. This mod does not promise a frame-rate improvement.

## Install and play

1. Close the game and its Slitherine launcher.
2. Run `Camera-Control-Fix-Installer-v2.04.exe` and choose **Install listed games**. You can also drag a game folder or game EXE onto the installer icon or into its window; only the dropped games are installed in that case.
3. Start the game through Steam as usual and press **Play**. Choose **RTS** camera mode in the game options.

The installer backs up `Launcher.exe.config`, changes its game-launch target, and places a small `CameraControlFix` folder beside it. It does not replace the game EXE or Slitherine launcher EXE. The helper starts the original game and applies the camera and HUD code to that game process after the supported engine layout is recognized.

The automatic connection requires the Slitherine launcher. Starting a clean game EXE directly bypasses it. No Windows login entry, scheduled task, service, or global background monitor is installed.

### Restore or update

Use **Restore listed games** with the game and launcher closed to restore the original launcher connection. The installer preserves its removed files in `CameraControlFixBackups` and refuses to overwrite conflicting files or settings.

Restoring the launcher connection does not remove a separately installed permanent EXE patch, such as the older SF2 1.62 release. Steam's **Verify integrity of game files** can restore modified original game files; added mod files may remain on disk. If Steam restores or updates the launcher configuration, run the installer again to reconnect it.

## Supported games and verification

The common resolver recognizes these seven CMx2 titles:

- Battle for Normandy
- Shock Force 2
- Cold War
- Black Sea
- Red Thunder
- Fortress Italy
- Final Blitzkrieg

Executable recognition alone is insufficient: the native signatures and relationships must match before a patch is written. An unknown or ambiguous engine layout is rejected.

Version 2.04's Steam-to-Slitherine-to-game launch flow and automatic camera/HUD state were checked in **Battle for Normandy** and **Shock Force 2**. Game exit also stopped the helper. Cold War installation, restoration, and reinstall checks passed; its engine mapping was checked offline. The earlier SF2 controls/HUD and combined Normandy runtime were confirmed in actual play.

These are representative checks, not individual gameplay validation of all seven titles or every game update. Multiplayer/PBEM compatibility has not been established.

## Build from this repository

Requires Windows, Python 3, and the .NET Framework C# compiler. The main build uses Python's standard library and framework assemblies; it does not download dependencies or require a game installation.

```text
python build.py
python build.py --test
```

The build produces `build/Camera-Control-Fix-Host-v2.04.exe` and `build/Camera-Control-Fix-Installer-v2.04.exe`. The x86 host is embedded in the AnyCPU installer; the installer is the only file an end user needs. Use `--csc` to specify a compiler and `--out` to select an output folder. Build and automated checks do not launch or modify a game.

When switching between a downloaded installer and a locally rebuilt copy of the same version, restore the existing launcher connection first. The installer deliberately refuses to replace an installed host with different bytes under the same version.

The C# sources build against the checked-in native payloads and matching specifications in `resources/`. Their SHA-256 hashes are checked before building. This rebuilds the host and installer, but does **not** regenerate the native payloads; [native implementation notes](native-reference/README.md) explain the separate generators and required external inputs. Rebuilt EXE hashes can differ from a previously distributed build because of compiler-generated metadata.

## Source layout

| Path | Contents |
| --- | --- |
| `src/` | Installer, game host, process transport, resolvers, receipts, and transaction handling |
| `tests/` | Isolated checks for installation, restoration, arguments, and patch transactions |
| `resources/` | Frozen mod payloads, native matching specifications, and hashes |
| `native-reference/` | Native assembly and generator sources, with regeneration requirements |
| `CHANGELOG.md` | Public release history |

Build output, private game inputs, process dumps, and local logs are excluded from version control. No complete game executables, game assets, credentials, or development memory dumps are included.

## Reporting an issue

Include the game title and build, mod version, Windows version, resolution, camera mode, and steps to reproduce the problem. For automatic-launch failures, check `%LOCALAPPDATA%/CombatMissionControlFix/launches/`; review paths and other personal details before sharing a log.

## License

Project-authored code is available under the [MIT license](LICENSE). Combat Mission names, game code, and assets remain the property of their respective owners; this license does not grant rights to those materials. This is an unofficial community project.
