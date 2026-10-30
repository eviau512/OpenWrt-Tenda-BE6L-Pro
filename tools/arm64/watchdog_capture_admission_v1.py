# SPDX-License-Identifier: MIT
"""Pure evidence checks: no serial, device, network or build operations."""
import re

STOPPED = 'BE6L_WDT_KEXEC_STOPPED enable_readback=0'
FAILED = ('BE6L_WDT_KEXEC_STOP_FAILED', 'BE6L_WDT_KEXEC_REFUSED')


def check_capture(raw):
    text=raw.decode('utf-8',errors='replace').replace('\r','')
    assert not any(marker in text for marker in FAILED), 'Outgoing watchdog shutdown reported refusal/failure'
    stopped=[m.start() for m in re.finditer(re.escape(STOPPED),text)]
    assert len(stopped)==1, 'Exactly one real checked watchdog shutdown marker is required'
    boot=re.search(r'(?m)^.*Booting Linux on physical CPU[^\n]*$',text)
    assert boot and stopped[0]<boot.start(), 'Checked stop must precede the new kernel'
    assert not re.search(r'U-Boot 2014\.04|Hit ctrl\+c to stop autoboot|Linux version 5\.4',text), 'Unexpected reset/stock boot'
    return dict(outgoing_watchdog_checked_stop_observed=True,
                marker_precedes_new_kernel=True, reset_observed=False,
                stop_callback_can_abort_kexec=False, xz_failure_cause_proven=False)
