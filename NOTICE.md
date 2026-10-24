# Provenance and license boundaries

The base OpenWrt/NPU reference is
`https://github.com/iscle/openwrt`, commit
`30b833ae5b8a6ba94149268c47a8493308a0ee04` (`be5000-npu`). The related public review
is `https://github.com/iscle/openwrt/pull/2`. This is a reference implementation,
not proof that routed NAT offload is available on the BE6L Pro.

The two `patches/openwrt-*.patch` files are independent deltas against that same
commit. Apply the ARM32 patch to the ARM32 checkout and the ARM64 COMPAT patch
to the ARM64 checkout; do not apply them as a two-patch series to one tree.
Upstream code and patch contexts retain their original copyright and licenses.
Linux changes use their corresponding Linux file licenses, including SPDX
declarations where present. Third-party package recipes and software retain
their upstream licenses; this repository does not relicense them.

## Telnet-only RAM-boot project

`tools/build_split_loader.py` was adapted from the existing loader generator in
`https://github.com/YangZJ781/Tenda-BE6L-Pro-Telnet-only-ramboot`,
`tools/build_split_loader.py`. The local reference source used for comparison
has SHA256 `aedde6db97e9cab5166a66c61b5bae042bdecb0300540ef595b6d97055c58140`.
The derivative adds payload-directory selection, optional early-boot diagnostics
and board-specific DT preparation while retaining the split ARM kexec approach.
The first line of the derivative also records this attribution.

`tools/prepare_ramboot.py` contains this bring-up project's FIT validation and
payload preparation. Its optional executable payload-preparation path expects
separately verified kexec/musl/zlib inputs from the earlier RAM-boot workflow.
Those inputs, the Telnet/password implementation, the single-file PowerShell
distribution and the X-WRT image are not included here. Building and validating
an initramfs only imports its FIT parsing helpers and does not require those
external binary payloads.

The earlier project's NOTICE states that no additional repository-wide license
was chosen for its new wrapper/research sources. Attribution here does not grant
an additional license to that code. No blanket license is asserted over the
combined repository. Preserve original notices when reusing any component.
The independently written experimental headers/tests with an MIT SPDX label
retain that label; it does not apply to unrelated files.

## Excluded private inputs

Raw device backups, original vendor modules, disassemblies of private backups,
the reverse-engineered specification archive, raw runtime logs, configuration
secrets and device identities are excluded. Published status summaries describe
test outcomes without copying those private artifacts.

Source revisions, selected sparse paths and feed links are recorded in
`sources.json`. Source-built third-party programs are not claimed as original
work of this project.
