"""Bounded UART boot observation with timestamped, private evidence.

Importing this module performs no I/O. The only transmitted bytes, when the
observed autoboot prompt requires them, are Ctrl-C, Ctrl-C and carriage return.
An attempted transmission never counts as an observed stopped bootloader.
"""
from pathlib import Path
import hashlib
import json
import time


AUTOBOOT = b'Hit ctrl+c to stop autoboot'
ECNT = b'ECNT> '
RESET = b'U-Boot 2014.04'
STOCK = b'Linux version 5.4'
MAX_CAPTURE_BYTES = 16 * 1024 * 1024


class BootObserver:
    """Recognize complete markers across chunks; retain bounded lookbehind."""
    def __init__(self):
        self.offset = 0
        self.tail = b''
        self.interrupt_after_offset = None
        self.interrupt_attempted = False
        self.interrupt_write_completed = False
        self.bootloader_prompt_confirmed = False
        self.autoboot_observed = False
        self.reset_observed = False
        self.stock_kernel_observed = False
        self._seen = set()

    def feed(self, block):
        assert isinstance(block, bytes) and block
        start = self.offset - len(self.tail)
        data = self.tail + block
        self.offset += len(block)
        events = []
        for name, marker in (('reset_banner', RESET), ('autoboot_prompt', AUTOBOOT),
                             ('ecnt_prompt', ECNT), ('stock_kernel', STOCK)):
            at = 0
            while (at := data.find(marker, at)) >= 0:
                absolute = start + at
                identity = (name, absolute)
                if identity not in self._seen:
                    self._seen.add(identity)
                    events.append(dict(event=name, offset=absolute))
                at += len(marker)
        events.sort(key=lambda item: item['offset'])
        for event in events:
            name = event['event']
            if name == 'reset_banner':
                self.reset_observed = True
            elif name == 'autoboot_prompt':
                self.autoboot_observed = True
            elif name == 'stock_kernel':
                self.stock_kernel_observed = True
            elif name == 'ecnt_prompt':
                # Bytes already read before Ctrl-C do not confirm its effect.
                # A wholly new prompt, after successful writes, is required.
                if (self.interrupt_write_completed and
                        event['offset'] >= self.interrupt_after_offset):
                    self.bootloader_prompt_confirmed = True
                    event['after_completed_interrupt'] = True
                else:
                    event['after_completed_interrupt'] = False
        self.tail = data[-(max(map(len, (AUTOBOOT, ECNT, RESET, STOCK))) - 1):]
        # This evidence needs only a bounded number of marker identities.
        self._seen = {item for item in self._seen if item[1] >= self.offset - 256}
        return events

    def mark_interrupt_attempt(self):
        assert self.autoboot_observed and not self.interrupt_attempted
        self.interrupt_attempted = True
        self.interrupt_after_offset = self.offset

    def report(self, end_reason):
        return dict(version=1, end_reason=end_reason,
                    bytes_received=self.offset,
                    reset_banner_observed=self.reset_observed,
                    autoboot_prompt_observed=self.autoboot_observed,
                    interrupt_attempted=self.interrupt_attempted,
                    interrupt_write_completed=self.interrupt_write_completed,
                    bootloader_prompt_confirmed=self.bootloader_prompt_confirmed,
                    stock_kernel_observed=self.stock_kernel_observed,
                    autoboot_interception_confirmed=(self.bootloader_prompt_confirmed and
                                                    not self.stock_kernel_observed),
                    capture_timeout_is_containment_proof=False,
                    boot_success_qualified=False,
                    flash_unchanged_qualified=False)


def capture_boot(uart, raw_path, events_path, *, seconds=120,
                 confirmation_seconds=8, monotonic_ns=time.monotonic_ns,
                 utc_ns=time.time_ns, sleep=time.sleep, on_chunk=None):
    """Observe an already started boot; never open a port or initiate a boot.

    `uart` must have bounded/nonblocking read_all and write operations. Caller
    retains port ownership and all image/route/flash/kexec admission checks.
    Returns evidence only. A caller must treat every unexpected reset as a
    failure even when an actual post-interrupt ECNT prompt has been observed.
    """
    assert 0 < seconds <= 180 and 0 < confirmation_seconds <= 15
    raw_path, events_path = Path(raw_path), Path(events_path)
    assert raw_path != events_path and not raw_path.exists() and not events_path.exists()
    observer = BootObserver()
    began = monotonic_ns()
    deadline = began + int(seconds * 1e9)
    confirmation_deadline = None
    end_reason = 'capture_deadline'
    error = None
    with raw_path.open('xb') as raw, events_path.open('x', encoding='utf-8') as events:
        def record(event):
            event = dict(event, host_monotonic_ns=monotonic_ns(), host_utc_ns=utc_ns())
            events.write(json.dumps(event, separators=(',', ':')) + '\n')
            events.flush()

        record(dict(event='capture_begin', limit_seconds=seconds,
                    host_timestamps_are_uart_receive_times=True))
        try:
            while monotonic_ns() < deadline:
                if confirmation_deadline is not None and monotonic_ns() >= confirmation_deadline:
                    end_reason = 'interrupt_confirmation_deadline'
                    break
                before = monotonic_ns()
                block = uart.read_all()
                after = monotonic_ns()
                assert isinstance(block, bytes)
                if block:
                    offset = observer.offset
                    raw.write(block)
                    raw.flush()
                    record(dict(event='rx_chunk', offset=offset, size=len(block),
                                read_before_monotonic_ns=before, read_after_monotonic_ns=after,
                                sha256=hashlib.sha256(block).hexdigest()))
                    for event in observer.feed(block):
                        record(event)
                    if observer.autoboot_observed and not observer.interrupt_attempted:
                        observer.mark_interrupt_attempt()
                        record(dict(event='interrupt_attempt', after_rx_offset=observer.offset,
                                    control_bytes_only=True))
                        # Match the previously used bounded two-Ctrl-C sequence.
                        assert uart.write(b'\x03') == 1, 'Short first Ctrl-C write'
                        sleep(.04)
                        assert uart.write(b'\x03\r') == 2, 'Short second Ctrl-C write'
                        observer.interrupt_write_completed = True
                        record(dict(event='interrupt_writes_completed', total_bytes=3))
                        confirmation_deadline = min(deadline, monotonic_ns() + int(confirmation_seconds * 1e9))
                    if on_chunk is not None:
                        on_chunk(block)
                    if observer.bootloader_prompt_confirmed:
                        end_reason = 'post_interrupt_ecnt_prompt_observed'
                        break
                    if observer.offset >= MAX_CAPTURE_BYTES:
                        end_reason = 'capture_byte_limit'
                        break
                sleep(.04)
        except Exception as problem:
            error = problem
            end_reason = 'capture_error'
            record(dict(event='capture_error', error_type=type(problem).__name__))
        result = observer.report(end_reason)
        result['elapsed_host_monotonic_ns'] = monotonic_ns() - began
        result['capture_error_type'] = type(error).__name__ if error else None
        record(dict(event='capture_end', result=result))
    if error is not None:
        # Preserve the evidence before propagating a serial/read/write error.
        error.capture_result = result
        raise error
    return result
