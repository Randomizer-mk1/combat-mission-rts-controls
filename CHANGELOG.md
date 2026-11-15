# Changelog

Changes are listed newest first. The SF2-only versions below precede the common runtime launcher; their version numbers do not identify separate releases for every game.

## 2.04 — 2026-11-15

- Added MIT-licensed source, a portable Windows build script, and isolated automated checks.
- Added a one-time installer that connects the Slitherine launcher's normal Play button to Camera Control Fix. After installation, start through Steam as usual and select RTS camera mode.
- Kept the original game and launcher executables unchanged. The installer backs up the launcher configuration, changes its game-launch target, and provides an exact configuration restore. Externally changed configurations and unrecognized installation files are preserved.
- Limited the helper to the launched game's lifetime. No Windows login startup entry, service, or global game watcher is installed.
- Added HUD registration for a battle that is already open when the runtime fix attaches. Kept the accepted camera and HUD implementation, including verification of components that are already active.
- Added folder discovery, installation from dropped game folders or executables, and command-line install/restore. Dropping onto the installer icon or its open window applies only to the dropped targets.

**Coverage:** the installer recognizes Shock Force 2, Battle for Normandy, Cold War, Black Sea, Red Thunder, Fortress Italy, and Final Blitzkrieg. Runtime application still requires matching native code and layout checks. The Steam/Slitherine launch flow was checked in Normandy and SF2; Normandy applied the combined runtime fix, while SF2 recognized the accepted disk patch without applying it twice. Cold War also has offline mapping checks. These checks do not establish gameplay compatibility for every build of all seven titles.

## 1.94

- Combined the common camera controls, scaled HUD, and larger briefing text in one runtime launcher.
- Verified camera and HUD components separately, skipped components already active, and rolled back newly applied components if the combined operation failed.
- Kept game executables unchanged on disk; runtime changes last until the game closes. Applying to an open battle required reloading that battle for HUD registration.

The combined runtime was tested and user-accepted in Normandy. The existing SF2 1.62 disk patch remained a separately installed, recognized implementation.

## 1.83

- Introduced common runtime camera matching across supported CMx2 layouts, with constant-speed WASD movement, Q/E orbit, middle-mouse dragging, and cursor-directed wheel movement.
- Added guarded application, verification, and rollback without replacing the game executable.

Camera behavior was checked in Normandy. Offline resolver checks covered SF2, Normandy captures, and Cold War; this version did not yet include the common HUD component.

## SF2 1.62

- Reduced HUD width and height to approximately 70% of the 1.61 size while preserving panel arrangement and matching click coordinates.
- Retained the HUD lifecycle/loading-crash correction and larger briefing text from the earlier SF2 implementation.
- Provided exact-build installation, upgrade, and original-restoration patches for Steam build 21967996.

This SF2 version was tested and user-accepted.

## SF2 1.61

- Improved HUD clarity by preferring whole-number scaling when it fit without making the panel noticeably larger. Other screen sizes retained proportional scaling.
- Used the same scale for drawing and mouse-coordinate conversion.

## SF2 1.55

- Combined constant WASD movement at 60% of native speed, full native Q/E yaw speed, and removal of the selected-unit camera heading reset.
- Included native middle-mouse camera dragging and cursor-terrain wheel movement with bounded terrain searches and a map-edge fallback.
- Included a centered, uniformly enlarged HUD with matching click coordinates, larger briefing text, and the HUD lifecycle crash correction.

Experimental shadow changes were excluded from this package.

## SF2 1.43

- Combined native middle-mouse camera dragging, Q/E ground orbit, and cursor-directed wheel movement in the earlier SF2 camera implementation.
- Kept a wheel hit on the UI from falling through to optical zoom.
