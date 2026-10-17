# Installation

Install the CLI and the standalone TUI together. Static and active HTTP scans
need no browser. Dynamic scanning requires an installed Chrome/Chromium; set
`CHROME` to its executable if automatic discovery fails.

## From this source checkout

Windows PowerShell:

```powershell
./scripts/install.ps1
# Optional: add the installation directory to your user PATH
./scripts/install.ps1 -AddToPath
```

Linux/macOS:

```sh
sh scripts/install.sh
```

Each script builds both binaries once using `Cargo.lock`, installs them in a
user-owned directory, then checks `--version`. No administrator access is needed
for installing the binaries. Windows defaults to `~/.cargo/bin`, Unix to
`~/.local/bin`. The Unix script prints the PATH line to add to your shell profile.
Choose another directory with `-InstallDir DIR` / `--install-dir DIR`.

Build requirements: Rust 1.89+ with Cargo, a C compiler and CMake. On Windows,
install Visual Studio Build Tools with the C++ workload and Windows SDK, plus
CMake. NASM is recommended for the TLS dependency's assembly; supported builds
can also use its bundled assembly objects. See the
[official aws-lc-rs Windows requirements](https://aws.github.io/aws-lc-rs/requirements/windows.html).
On Debian/Ubuntu the native build packages are `build-essential` and `cmake`;
on macOS use Xcode Command Line Tools and CMake. OpenSSL is not required.

If the build succeeded earlier, install those binaries without rebuilding:

```powershell
./scripts/install.ps1 -BinaryDir ./target/release
```

```sh
sh scripts/install.sh --binary-dir ./target/release
```

## Portable bundles (no Rust compiler)

The `Portable bundles` GitHub Actions workflow builds Windows x64, Linux x64
(Ubuntu 24.04 / glibc), macOS Intel and macOS Apple Silicon archives. Run it
manually, or push a version tag to generate downloadable workflow artifacts.
This workflow prepares artifacts; it does not publish a GitHub Release. Only
the local Windows bundle has been validated in the development workspace.

Each archive contains `bin/webrev`, `bin/webrev-tui` (with `.exe` on Windows),
install scripts, this guide, the license and `SHA256SUMS`. An adjacent `.sha256`
file covers the archive itself. Verify that outer checksum before extracting:

```powershell
Get-FileHash ./webrev-0.1.0-x86_64-pc-windows-msvc.zip -Algorithm SHA256
Get-Content ./webrev-0.1.0-x86_64-pc-windows-msvc.zip.sha256
```

```sh
sha256sum -c webrev-0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256
# macOS: shasum -a 256 -c <archive>.sha256
```

Extract the archive, enter its directory, then run the same install command
above. The scripts detect `bin/` automatically and verify both binary checksums
before replacing an installation. Checksums detect corruption, not publisher
identity. You can also run the binaries directly from `bin/`.

For maintainers, package locally after a release build:

```sh
python scripts/package.py --target x86_64-pc-windows-msvc
```

## Verify and start

```sh
webrev --version
webrev-tui --version
webrev scan --seed https://your-authorized-target.example/
webrev tui --seed https://your-authorized-target.example/
```

Default scans show a prioritized triage summary and save the full `webrev-report.json`. For active
checks use `scan --active` or press `a` in the TUI. IDOR signals need mission
authentication (`--cookie`, `--bearer` or `--header`). XSS/SQLi/IDOR findings are
signals requiring manual verification. No RCE detector is implemented.

Reports can be sent directly to another tool without creating a file:

```sh
webrev scan --seed https://your-authorized-target.example/ --format jsonl --report -
webrev scan --seed https://your-authorized-target.example/ --format urls --report - | httpx
```

For missing browser errors, install Chrome/Chromium and set `CHROME`. For a
missing command after installation, open a new terminal and check PATH. For a
build error, check the native requirements above and the original Cargo error.
