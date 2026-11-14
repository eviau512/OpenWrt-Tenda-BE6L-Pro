# Signed unchanged native ARM32 SSH component

The [new builder](../tools/package_native_arm32_dropbear_v1.py) creates and
normally verifies `be6l-arm32-dropbear=2026.94-r103`, architecture
`arm_cortex-a7`, with the single exact dependency
`be6l-arm32-runtime=1.0.137005195660218-r1`. It provides no generic package/ABI
identity. [Evidence](evidence/native-arm32-dropbear-20261113.json) records actual
signed extraction, installed P/V/A/D and file ownership. This is a component
receipt; the complete main root remains unqualified.

The source is the installed `dropbear=2026.94-r3` in
`/root/be6l-kernel-apk-xz-20261113-r1/root`. Its ARM32 Dropbear ELF, two aliases,
configuration, init/preinit/upgrade scripts and alternatives contents retain
their exact source bytes/targets and modes at canonical paths. Only the four
package-specific `lib/apk/packages/dropbear.*` metadata paths acquire the private
package name. The `.list` is regenerated from the complete destination payload,
including metadata; `.conffiles_static` hashes are verified against the actual
packaged configuration. The unchanged `.conffiles` also declares user key paths
outside this package's ownership; those declarations do not package the keys.

The unchanged ELF uses `/lib/ld-musl-arm.so.1`; both direct `DT_NEEDED` names
resolve to the signed ARM32 runtime's private loader paths. This is a static
ELF/runtime closure check, not execution, plugin/VM isolation or a standard A53
ABI claim. No `passwd`, root password, SSH key, port configuration or host trust
was changed. No target executable or installation script ran.

An accompanying **private** `be6l-ram-access=1.0.0-r2` package retains all three
current access payload files byte-for-byte with their modes. Its only dependency
changes to `be6l-arm32-dropbear=2026.94-r103`. Source credentials, individual
credential hashes and the access APK are not published. Both packages and their
public signing trust are retained under
`/root/be6l-native-dropbear-20261113-r1`; the temporary signing key was deleted.

## Actual normal transaction results

In a fresh isolated root, normal signed APK installation of runtime plus SSH
succeeds. Querying the installed database verifies exact P/V/A/D, empty provides,
and ownership of every payload path. A missing-runtime negative transaction is
rejected. A subsequent normal access-package install verifies its exact metadata
and all three private payload files/modes/owners. Signed extraction of all three
packages equals the prepared payloads.

In a private copy of the full source root, the normal three-package add attempts
runtime, SSH and access. It returns **one error**: the runtime's canonical
`lib/ld-musl-arm.so.1` would overwrite the path still owned by
`libc=1.2.6-r5`. No force, untrusted mode, database edit or expanded `replaces`
is used. The SSH package's narrow `replaces:dropbear` does transfer its exact
canonical payload to the new installed owner, and access metadata upgrades;
those observations do not turn the partial transaction into success. Its root
must not be used as a candidate. All existing source files/aliases remain
unchanged in that copy except normal APK installed-database/world updates.

Normal old-Dropbear removal simulation separately reports that
`be6l-recovery-guard` still requires the old identity. The builder therefore does
not remove the old package/world entry. A matching new guard component is being
coordinated separately; this receipt does not claim it was composed here.
No protected config `.apknew` merge was needed for these byte-identical source
payloads. The source root itself remains completely unchanged.

## Remaining combined-root gate

Complete canonical ARM32 loader ownership withdrawal through the normal libc
package migration, install the matching guard/access metadata, then perform and
verify the **whole** ordinary APK transaction including old Dropbear/world
removal. Recheck every service payload, user datum, owner, exact dependency and
interpreter in that resulting root. The isolated success and partially installed
full copy do not substitute for that proof. Native shell selection and V2 guard
composition belong to the separate main-root builder. No DUT, route, candidate,
host network setting or Git commit was changed by this work.
