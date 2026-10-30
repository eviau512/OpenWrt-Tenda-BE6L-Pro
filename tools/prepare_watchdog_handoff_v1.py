# SPDX-License-Identifier: MIT
"""Prepare a pinned, isolated watchdog fix; never patch an SDK or contact DUT."""
from pathlib import Path
import argparse
import difflib
import hashlib
import json

PIN = 'a92d8dac1d7f3aaf9e1fc8aa81630940f626ebd74abd982537029f496a78c955'
SDKROOT = Path('/root/be6l-openwrt')
SOURCES = {
    'arm': SDKROOT / 'source/build_dir/target-arm_cortex-a7_musl_eabi/linux-airoha_an7563/linux-6.18.55',
    'arm64': SDKROOT / 'arm64-source/build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55',
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(work):
    assert work.parent == SDKROOT and work.name.startswith('wdt-handoff-v1-')
    assert not work.exists()
    originals = {arch: root / 'drivers/watchdog/airoha_wdt.c' for arch, root in SOURCES.items()}
    assert all(digest(p) == PIN for p in originals.values())
    old = originals['arm'].read_text()
    new = old.replace('#include <linux/kernel.h>', '#include <linux/kernel.h>\n#include <linux/kexec.h>', 1)
    needle = '\twritel(val, airoha_wdt->base + TIMER_CTRL);\n\n\treturn 0;\n}\n\nstatic int airoha_wdt_ping'
    replacement = '\twritel(val, airoha_wdt->base + TIMER_CTRL);\n\n\t/* Read back the same documented enable bits; a posted write is not proof. */\n\tval = readl(airoha_wdt->base + TIMER_CTRL);\n\treturn val & (WDT_ENABLE | WDT_TIMER_ENABLE) ? -EIO : 0;\n}\n\nstatic int airoha_wdt_ping'
    assert new.count(needle) == 1
    new = new.replace(needle, replacement)
    begin = new.index('static int airoha_wdt_set_timeout(')
    end = new.index('static unsigned int airoha_wdt_get_timeleft(', begin)
    new = new[:begin] + '''static int airoha_wdt_set_timeout(struct watchdog_device *wdog_dev, unsigned int timeout)
{
	int ret;

	if (watchdog_active(wdog_dev)) {
		ret = airoha_wdt_stop(wdog_dev);
		if (ret)
			return ret;
		wdog_dev->timeout = timeout;
		return airoha_wdt_start(wdog_dev);
	}

	wdog_dev->timeout = timeout;
	return 0;
}

''' + new[end:]
    anchor = 'static int airoha_wdt_suspend(struct device *dev)'
    shutdown = '''/* Standard kexec sets kexec_in_progress before device_shutdown().
 * Do not alter the ordinary reboot watchdog policy or override NOWAYOUT.
 * This void callback cannot veto kexec: a failure log must fail boot admission,
 * and the external UART monitor must retain reset evidence and stop autoboot.
 */
static void airoha_wdt_shutdown(struct platform_device *pdev)
{
	struct airoha_wdt_desc *wdt = platform_get_drvdata(pdev);

	if (!kexec_in_progress || !wdt)
		return;
	if (test_bit(WDOG_NO_WAY_OUT, &wdt->wdog_dev.status)) {
		dev_err(&pdev->dev, "BE6L_WDT_KEXEC_REFUSED nowayout=1\\n");
		return;
	}
	if (airoha_wdt_stop(&wdt->wdog_dev)) {
		dev_err(&pdev->dev, "BE6L_WDT_KEXEC_STOP_FAILED\\n");
		return;
	}
	dev_info(&pdev->dev, "BE6L_WDT_KEXEC_STOPPED enable_readback=0\\n");
}

'''
    assert new.count(anchor) == 1
    new = new.replace(anchor, shutdown + anchor)
    needle = '\tif (watchdog_active(&airoha_wdt->wdog_dev))\n\t\tairoha_wdt_stop(&airoha_wdt->wdog_dev);'
    assert new.count(needle) == 1
    new = new.replace(needle, needle.replace('\t\tairoha_wdt_stop', '\t\treturn airoha_wdt_stop'))
    needle = '\t.probe = airoha_wdt_probe,'
    assert new.count(needle) == 1
    new = new.replace(needle, needle + '\n\t.shutdown = airoha_wdt_shutdown,')
    work.mkdir()
    (work / 'airoha_wdt.c').write_text(new)
    patch = ''.join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                    fromfile='a/drivers/watchdog/airoha_wdt.c', tofile='b/drivers/watchdog/airoha_wdt.c'))
    (work / '976-watchdog-checked-kexec-handoff.patch').write_text(patch)
    receipt = dict(schema=1, source_sha256=PIN, patched_source_sha256=digest(work / 'airoha_wdt.c'),
        patch_sha256=digest(work / '976-watchdog-checked-kexec-handoff.patch'),
        builder_sha256=digest(Path(__file__)), sdk_sources_unchanged=all(digest(p) == PIN for p in originals.values()),
        kernel_objects_compiled=False, actual_functions_tested=False, target_executed=False,
        image_built=False, shutdown_can_abort_kexec=False,
        inherited_timer_adoption_implemented=False, reset_cause_proven=False)
    (work / 'preparation.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.work.resolve()), indent=2))
