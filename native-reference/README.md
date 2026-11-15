# Native implementation reference

These Python generators and assembly files expose the camera, HUD, briefing and matching implementation used by Camera Control Fix 2.04. The accepted native payloads are unchanged from runtime 1.94. They are reference sources, not a portable one-command native rebuild pipeline.

Development used exact original SF2 and Cold War executables, locally patched SF2 intermediate files, a mapped Normandy image and Ghidra assembly tooling. Proprietary executables, mapped images and generated intermediate executables are not included. Some scripts read inputs at import time. These are offline development tools, not installers.

The top-level build compiles the C# game host and installer against frozen resources. Editing these reference files alone does not change the embedded payload. Both final resource generators were run from a separate copy with explicitly supplied development inputs: all four generated payload/spec files matched the published resource hashes exactly. This verifies regeneration **from the required intermediate executables**, not an end-to-end rebuild starting only with stock games. That full historical assembly/composition chain has not been verified from this public folder.

- `engine/camera_native_v1.43.py`, its assembly, and the orbit/wheel generators form the camera baseline.
- `engine/camera_yaw_v1.0.py`, `engine/camera_selected_orbit_v1.0.py`, `input/wheel_cursor_edge_v1.0.py` and `input/mmb_deadzone_v1.0.py` provide later corrections integrated by `planning/compose_sf2_ui_v1.10.py`. `input/qe_ground_orbit_v1.0.py` is an earlier ground-orbit reference; it is not the selected-unit correction accepted by the composer's `--orbit-module` argument.
- `engine/hud_scale_v1.55.py`, `engine/hud_scale_v1.61.py` and `engine/hud_scale_v1.62.py` contain HUD layout and subsequent scaling changes. `input/ui_readability_v1.0.py` contains briefing code.
- `planning/build_engine_runtime_v1.83.py` and `engine/build_hud_runtime_v1.0.py` generate native resources from development inputs.

Component filenames retain their original versions because older components are reused in the current 2.04 host; they are not separate current releases.

## Supplying local inputs

`native_paths.py` resolves these environment variables. Relative values resolve from this directory, independently of the current working directory. Original/intermediate SHA-256 guards remain enabled.

| Variable | Required input |
|---|---|
| `CCF_SF2_ORIGINAL` | Original SF2 Steam build 21967996 executable |
| `CCF_COLDWAR_ORIGINAL` | Original Cold War executable matching `CW_HASH` in the mapper |
| `CCF_NORMANDY_IMAGE` | Unpacked, RVA-indexed x86 Normandy module image; a packed disk EXE is not interchangeable |
| `CCF_INTERMEDIATES` | Directory containing the exact SF2 v1.55 and v1.62 intermediate executables for the final generators; earlier HUD stages also consume v1.43/v1.61 |
| `CCF_PYTHON_LIBS` | Optional directory containing Capstone; otherwise use the normal Python package environment |

After supplying those inputs and installing Capstone in the Python environment:

```text
python native-reference/planning/build_engine_runtime_v1.83.py
python native-reference/engine/build_hud_runtime_v1.0.py
```

Outputs go to `native-reference/planning/runtime` and `native-reference/engine/hud_runtime`, respectively. They do not replace `resources/`. Compare each generated payload/spec with `resources/SHA256.json` before considering an update. Generated correspondence JSON can contain local input paths and is a private development artifact; do not publish it or the input images.

## Historical assembly dependencies

The authored Ghidra scripts are included in `assembler/`:

- `AssembleMmbV153.java`: 16-byte NOP-padded instruction slots; arguments are assembly input and binary output. Used for the camera/HUD/selected-orbit slot listings.
- `AssembleSlotsV11.java`: explicitly addressed variable slots; arguments are input, output, allowed start and allowed end (hex). Its input requires a final `VA<TAB>END` row.

They require an external Ghidra installation and an x86 analysis program imported from the correct original SF2 executable. Generated `.bin` files consumed beside Python generators are assembly outputs, not omitted proprietary inputs. The Ghidra installation and its project are not bundled.

`native_orbit_v1.33.py` now derives its reachable instruction listing directly from the hash-guarded original using Capstone. It no longer needs a private Ghidra text export. All 722 generated instruction rows and returned binary fields were compared with the historical generator and matched after normalizing branch aliases and hexadecimal formatting. This removes that listing dependency without changing the frozen resources.
