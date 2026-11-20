# Fallout 3 decompilation: custom exe

Tools that build a custom Fallout 3 executable on your own machine, from the source code in
[f3_decomp](https://github.com/momusdigital/f3_decomp) and your own copy of the game. Windows only for now.

- **Kept apart on purpose.** f3_decomp holds source code only and proves that it matches the original. Building an
  executable from that source lives here, in its own repository.
- **The decomp is a submodule.** It sits in `decomp/`, pinned to a commit of f3_decomp's main. Clone with
  `git clone --recurse-submodules`, or run `git submodule update --init` after cloning.
- **Nothing of the game is here.** No executables, no game files, no game data. What the build needs from the game is
  read from your own copy on your own machine, and everything it produces stays in the git-ignored `.local/` folder.
  **Never share the executable, or anything else the build produces.**
- **No copy-protection removal.** The tools need a plain 1.7.0.3 executable from your own copy and contain no
  decryption.
- **You need the game.** You need your own legally obtained copy of Fallout 3 for PC, with its executable at version
  1.7.0.3.

These tools are the Fallout 3 port of [fnv_decomp_exe](https://github.com/momusdigital/fnv_decomp_exe), the same
build for Fallout: New Vegas.

## Building a custom exe

You can turn the [f3_decomp](https://github.com/momusdigital/f3_decomp) source into a working `Fallout3.exe` on your
own machine and play the game with it. f3_decomp itself only produces object files to compare; this repository adds
the build that turns them into an executable.

**Why build one.** It is the same approach other decompilation projects use for console games: the repository holds
only reconstructed code, and your own copy of the game supplies everything else when you build. A custom exe lets you
change the game's code and see the effect in the game, add logging or debug checks, test fixes, and step through
readable source in a debugger. Every compiled function in it is the byte-matching code checked by f3_decomp.

**What it is not.** It is not a replacement you can share, and it does not remove the need to own the game: the
build reads your own copy, and the exe runs only with your installed game and its data. The part of the exe that is
not yet source (some data tables, resources and runtime code) is taken from your copy at build time and never leaves
your machine.

**How finished it is.** Not tested yet for Fallout 3. The New Vegas version of these tools builds an exe that starts,
reaches the main menu, loads saves and has been played; the Fallout 3 port has the same pipeline with the Fallout 3
names, the Visual C++ 2005 SP1 compiler and linker, and Fallout 3's save folder. Some connections between rebuilt code
and data (links) may point at the wrong thing; they usually show up as a crash or as something behaving differently
from the original game. Mods and the script extender (FOSE and its plugins) are untested. Please report problems: see
[Reporting crashes and bad links](#reporting-crashes-and-bad-links).

### What you need

- Windows 10 or 11. Wine is untested for building. The built exe has also been started on Linux under Proton
  (intros, main menu, loading a save, a new game); there it must be copied into the game folder as `Fallout3.exe`,
  because Proton picks its graphics settings by the executable's name (under another name it stops at a black screen).
- 64-bit Python 3.10 or newer, with `capstone` and `psutil` (`python -m pip install capstone psutil`).
- Visual C++ 2005 SP1, unpacked as f3_decomp's [What you need](https://github.com/momusdigital/f3_decomp#what-you-need)
  describes (`decomp/tools/get_vs2005.py`): the compiler, the linker and the Windows SDK libraries in one folder.
- The `Fallout3.exe` of version 1.7.0.3 from your own copy of Fallout 3 for PC: the GOG release, or the Steam release
  (which installs 1.7.0.4) downgraded to 1.7.0.3 with the Fallout Anniversary Patcher the modding community uses. These
  tools contain no decryption or copy-protection bypass. Your exe is checked against `decomp/build/image_check.json`
  before anything is extracted. The two copies differ only in a few places where the patcher put its own code
  (`patcher_sites` in that file); the custom exe keeps whatever your copy has there.
- About 5 GB of free disk space and at least 3 GB of free memory while building.

### Get it

```powershell
git clone --recurse-submodules https://github.com/momusdigital/f3_decomp_exe.git
cd f3_decomp_exe
```

In an existing clone, `git pull` followed by `git submodule update --init` brings `decomp/` to the commit this
repository is pinned to. The tools only read `decomp/`; they never change it.

### Build it

From the repository root, in PowerShell (replace the example paths with your own):

```powershell
$env:F3_MSVC_ROOT = 'C:/compilers/vs2005'        # VC/ and SDK/, as get_vs2005.py unpacks them
python tools/custom_exe.py extract --image 'C:/my-own-copy/Fallout3.exe' --jobs 4
python tools/custom_exe.py build
```

1. `extract` compiles every unit (like a full `build_and_match.py` run, so expect it to take a while), checks that all
   of them still match, and then takes from your exe only what the source does not provide yet: data tables (written
   out as C++), the remaining runtime code, and resources. Run it again whenever source, headers or the recipe change.
2. `build` compiles that, links everything with the Visual C++ 2005 SP1 linker, and checks the result (imports,
   pointers, data, TLS, resources, loader settings). Only if every check passes does it write
   `.local/custom-exe/Fallout3_src.exe`.

Everything generated lives in the git-ignored `.local/custom-exe/` folder. The tools never write into your game
folder and never replace your original exe. They use at most eight compiler processes and pause if free memory drops
below 3 GB. If `extract` or `build` reports a failure, do not use the output; see the reporting section below.

**Never share the custom exe, object files or anything under `.local/`.** They contain parts of your game. None of it
belongs in a commit, an issue or a crash report.

### Play it

```powershell
python tools/custom_exe.py run --game-dir 'C:/Games/Fallout 3' --timeout 14400
```

This starts the custom exe with your game folder as its working directory, under a small debugger that records
crashes. `--timeout` is in seconds (at most 14400, four hours); quit the game normally before it runs out, or the
launcher closes it. During the run your installed game files are opened read-only, and afterwards the launcher checks
that none of them changed.

**Your saves.** Before the run the launcher backs up the fixed-name saves (`autosave` and `quicksave`) and restores
them afterwards, so a crash cannot leave you with a broken autosave. That also means autosaves and quicksaves made
during the run are put back to what they were. **Use normal (numbered) saves to keep progress made with the custom
exe.** The run's own versions are kept in that run's report folder.

The launcher only starts the game once it is sure the backup is safe. It refuses to start, with an error saying why,
when:

- your saves are not in the default folder (`Documents/My Games/Fallout3/Saves`): any `SLocalSavePath` other than
  `Saves\`, or `bUseMyGamesDirectory=0`, in `Fallout_default.ini`, `FALLOUT.INI` or `FalloutPrefs.ini`. Custom save folders are not supported yet. Mod managers that redirect saves without changing
  these files (for example a virtual file system) are not detected, so run the custom exe without them;
- `My Games/Fallout3` does not exist yet (start the original game once first);
- a backed-up file cannot be read back with the same contents.

If putting the saves back fails after a run, the launcher says so (`RESTORE FAILED`) and names the folder that holds
your original files. That folder is never deleted; copy the files back from it yourself before playing.

When the game exits, the launcher prints the path of the run report (`.local/custom-exe/runs/<time>/`). If the game
crashed, it also prints a line like:

```
UNHANDLED 0xc0000005 at 0x00a1b2c3: ?SomeFunction@SomeClass@@QAEXXZ+0x4f
```

That is the exception code, the address, and the function plus offset where it happened, looked up in the build's
`Fallout3.map`. Lines starting with `first chance` are usually normal (the game handles them itself); the
`UNHANDLED` line is the crash.

To check that the build tools themselves work, without the game or the compilers:

```powershell
python -m unittest discover -s tools/tests -v
```

### Reporting crashes and bad links

A crash or wrong behaviour in the custom exe that does not happen with the original exe usually means a bad link:
rebuilt code connected to the wrong function or data. These are found by people playing, so reports help a lot.

**Before reporting:**

1. Update to the latest `main` (`git pull` and `git submodule update --init`), run `extract` and `build` again, and
   check that the problem still happens.
2. Turn off all mods and script extenders (FOSE and its plugins).
3. Try the same thing with your **original** exe from the same save. If it happens there too, it is a bug in the game,
   not in the custom exe.

**Open a GitHub issue** titled `Custom exe: <what happened>` and include:

- the revisions: the output of `git rev-parse HEAD` and `git -C decomp rev-parse HEAD`;
- the `UNHANDLED` line the launcher printed (exception code, address, function and offset), if it crashed;
- what you did, step by step, starting from where (main menu, a new game, or a save and the place in the world);
- what you expected and what happened instead, if it did not crash (for example: wrong text, missing sound or
  texture, an item or quest behaving differently from the original);
- whether it happens every time, and whether it happens with the original exe;
- your Windows version, and the game version and store (for example GOG 1.7.0.3, or Steam downgraded to 1.7.0.3).

`debug_report.json` from the run folder is useful too. Read it before attaching it: it should contain only addresses,
exception codes and function names. **Do not attach** the custom exe, files from `.local/`, memory dumps, game files
or screenshots of disassembly. Do not attach a save unless a maintainer asks for one.

**For contributors fixing a report:** the function and offset point at the code that was running. Check it in
`decomp/` with `python tools/build_and_match.py --image <your Fallout3.exe> --only <unit>`. If the function still matches, the
problem is usually not that function's code but a link: a call, global, vtable or data reference that the custom
build connects to a different address than the original. A fix that changes compiled bytes must still pass the full
match check.

### Where changes go

- **Game code, headers and the build recipe** belong in [f3_decomp](https://github.com/momusdigital/f3_decomp),
  where the automatic check proves every function still matches. This repository then moves `decomp/` to the new
  commit.
- **The exe build itself** (extraction, linking, audits, the launcher and its guards, `tools/tests`) belongs here.
  Run `python -m unittest discover -s tools/tests -v` before sending a change, and for changes to extraction or linking
  also a full `extract` and `build`.


## Legal

Fallout, Fallout 3, Bethesda, Bethesda Softworks, Bethesda Game Studios and ZeniMax are trademarks or registered
trademarks of ZeniMax Media Inc., a Microsoft company, in the U.S. and/or other countries. The game was developed by
Bethesda Game Studios and published by Bethesda Softworks. Steam is a trademark of Valve Corporation; GOG is a
trademark of GOG sp. z o.o. All other trademarks belong to their respective holders. This project is not affiliated
with or endorsed by any of them.

You need your own legally obtained copy of the game, and you are responsible for following its licence terms and the
law where you live.

If you hold rights in this material and want something changed or removed, write to contact@f3decomp.com. We will
respond promptly and comply.

No licence is granted for this repository; see `LICENSE`.
