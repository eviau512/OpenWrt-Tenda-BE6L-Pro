# SPDX-License-Identifier: MIT
"""Prepare isolated N1 identity ABI and real driver taps, never deploy.

The cached SDK and all accepted images are immutable inputs. The resulting
patch changes internal kernel layouts and requires a complete matched build
before any target use. Its root-only interface arms CPU observation, not UNB.
"""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import shutil

BASE = Path(__file__).resolve().parents[1]
SDK = Path('/root/be6l-openwrt/arm64-source')
K = SDK / 'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def once(text, old, new):
    assert text.count(old) == 1, old[:100]
    return text.replace(old, new, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    assert work.parent == Path('/root/be6l-openwrt') and work.name.startswith('n1-identity-v2-')
    assert not work.exists()
    names = ['include/net/flow_offload.h', 'include/net/netfilter/nf_flow_table.h',
             'net/netfilter/nf_flow_table_core.c', 'net/netfilter/nf_flow_table_offload.c',
             'drivers/net/ethernet/airoha/airoha_ppe.c',
             'drivers/net/ethernet/airoha/airoha_eth.h',
             'drivers/net/ethernet/airoha/Makefile', 'drivers/net/ethernet/airoha/airoha_eth.c',
             'net/core/flow_offload.c']
    assert sha(K / names[4]) == '39b585e3b1f2bc808e19ebdffd5dc53e34feac4558f76336b024b58aae676e35'
    originals = {name: (K / name).read_text() for name in names}
    changed = dict(originals)
    header = changed[names[0]]
    header = once(header, '#define FLOW_RULE_CT_CONTEXT_VERSION 1', '#define FLOW_RULE_CT_CONTEXT_VERSION 2')
    header = once(header, '\tu32 reserved;\n};\n\nstruct flow_rule {', '''\tu32 reserved;
\t/* Diagnostic scalar cookies only; never dereference or use as admission. */
\tu64 generation, ct_cookie, flow_cookie, tuple_cookie[2];
};

struct flow_rule {''')
    header = once(header, '\tunsigned long cookie;\n\tstruct flow_rule *rule;',
                  '\tunsigned long cookie;\n\tstruct flow_rule_ct_context ct_context;\n\tstruct flow_rule *rule;')
    header = once(header, 'struct flow_rule *flow_rule_alloc(unsigned int num_actions);',
                  'u64 flow_offload_diag_next_generation(void);\n\nstruct flow_rule *flow_rule_alloc(unsigned int num_actions);')
    changed[names[0]] = header
    changed[names[1]] = once(changed[names[1]],
        '\tstruct nf_conn\t\t\t\t*ct;\n',
        '\tstruct nf_conn\t\t\t\t*ct;\n\tu64\t\t\t\t\tdiag_generation;\n')
    core = changed[names[2]]
    core = once(core, '#include <linux/kernel.h>', '#include <linux/kernel.h>\n#include <net/flow_offload.h>')
    core = once(core, '\tflow->ct = ct;\n',
                '\tflow->ct = ct;\n\t/* Zero on serial wrap makes diagnostics invalid, never hardware success. */\n\tflow->diag_generation = flow_offload_diag_next_generation();\n')
    changed[names[2]] = core
    generic = once(changed[names[8]], '#include <linux/kernel.h>',
                   '#include <linux/kernel.h>\n#include <linux/atomic.h>\n#include <linux/export.h>')
    generic = once(generic, 'struct flow_rule *flow_rule_alloc(unsigned int num_actions)', '''/* Kernel-lifetime serial: unloading nf_flow_table must not reset identities. */
static atomic64_t flow_diag_serial = ATOMIC64_INIT(0);

u64 flow_offload_diag_next_generation(void)
{
\treturn atomic64_inc_return(&flow_diag_serial);
}
EXPORT_SYMBOL_GPL(flow_offload_diag_next_generation);

struct flow_rule *flow_rule_alloc(unsigned int num_actions)''')
    changed[names[8]] = generic
    nf = changed[names[3]]
    nf = once(nf, 'nf_flow_rule_set_ct_context(struct flow_rule *rule, const struct net *net,',
              'nf_flow_rule_set_ct_context(struct flow_rule_ct_context *context, const struct net *net,')
    nf = once(nf, '\tstruct flow_rule_ct_context *context = &rule->ct_context;\n', '')
    nf = once(nf, '\t    !net_eq(nf_ct_net(flow->ct), net))',
              '\t    !net_eq(nf_ct_net(flow->ct), net) || !flow->diag_generation)')
    nf = once(nf, '\tcontext->reserved = 0;\n\tcontext->valid = 1;', '''\tcontext->reserved = 0;
\tcontext->generation = flow->diag_generation;
\tcontext->ct_cookie = (unsigned long)flow->ct;
\tcontext->flow_cookie = (unsigned long)flow;
\tcontext->tuple_cookie[0] = (unsigned long)&flow->tuplehash[0].tuple;
\tcontext->tuple_cookie[1] = (unsigned long)&flow->tuplehash[1].tuple;
\tcontext->valid = 1;''')
    nf = once(nf, 'nf_flow_rule_set_ct_context(flow_rule->rule, net, flow, dir)',
              'nf_flow_rule_set_ct_context(&flow_rule->rule->ct_context, net, flow, dir)')
    nf = once(nf, '\tif (cmd == FLOW_CLS_REPLACE)\n\t\tcls_flow.rule = flow_rule->rule;', '''\t/* Preserve producer identity for DESTROY/STATS as well as REPLACE.
\t * The flow-table worker still owns the flow and its CT reference here.
\t */
\tif (!nf_flow_rule_set_ct_context(&cls_flow.ct_context,
\t\t\t\t       read_pnet(&flowtable->net), flow, dir))
\t\treturn 0;
\tif (cmd == FLOW_CLS_REPLACE)
\t\tcls_flow.rule = flow_rule->rule;''')
    changed[names[3]] = nf
    eth = changed[names[5]]
    pos = eth.index('struct airoha_ppe {')
    eth = eth[:pos] + 'struct be6l_diag;\n\n' + eth[pos:]
    eth = once(eth, 'struct airoha_ppe {', '''struct airoha_ppe {
\t/* CPU observer only; the control mutex serializes publication/removal. */
\tstruct mutex diag_mutex;
\tstruct be6l_diag __rcu *route_diag;
\tbool diag_spent;''')
    changed[names[5]] = eth
    ppe = changed[names[4]]
    ppe = once(ppe, '#include "airoha_eth.h"', '#include "airoha_eth.h"\n#include "diag.h"')
    ppe = once(ppe, '\tswitch (f->command) {\n\tcase FLOW_CLS_REPLACE:',
               '\tbe6l_diag_driver_command(eth->ppe, f);\n\tswitch (f->command) {\n\tcase FLOW_CLS_REPLACE:')
    ppe = once(ppe, '\tif (state != AIROHA_FOE_STATE_UNBIND)\n\t\tgoto unlock;\n', '''\tif (state != AIROHA_FOE_STATE_UNBIND)
\t\tgoto unlock;

\t/* Observe only the existing CPU copy under ppe_lock. No new SRAM request,
\t * DMA ownership or atomic hardware snapshot is implied by this tap.
\t */
\tif (airoha_is_7563(ppe->eth) && !rx_wlan)
\t\tbe6l_diag_driver_rx(ppe, skb, (const u32 *)hwe);
''')
    ppe = once(ppe, '\tppe->eth = eth;\n', '\tppe->eth = eth;\n\tmutex_init(&ppe->diag_mutex);\n')
    ppe = once(ppe, '\t\tairoha_ppe_an7563_init(ppe);\n\n\treturn 0;',
               '\t\tairoha_ppe_an7563_init(ppe);\n\n\tbe6l_diag_debugfs_init(ppe);\n\treturn 0;')
    ppe = once(ppe, '\tif (eth->ppe->netdevice_registered)\n',
               '\tbe6l_diag_driver_stop(eth->ppe);\n\n\tif (eth->ppe->netdevice_registered)\n')
    changed[names[4]] = ppe
    changed[names[6]] = once(changed[names[6]], 'airoha-eth-y := airoha_eth.o airoha_ppe.o',
                            'airoha-eth-y := airoha_eth.o airoha_ppe.o diag.o')
    ethernet = once(changed[names[7]], '#include "airoha_eth.h"', '#include "airoha_eth.h"\n#include "diag.h"')
    begin = ethernet.index('static netdev_tx_t airoha_an7563_dev_xmit(')
    end = ethernet.index('static netdev_tx_t airoha_dev_xmit(', begin)
    transmit = ethernet[begin:end]
    transmit = once(transmit, '\tu16 index;\n', '\tu16 index;\n\tbool diag_was_gso;\n\tu8 diag_summed_before;\n')
    transmit = once(transmit, '\t/* These helpers may rewrite skb data; reserve capacity first. */',
        '\tdiag_was_gso = skb_is_gso(skb);\n\tdiag_summed_before = skb->ip_summed;\n\t/* These helpers may rewrite skb data; reserve capacity first. */')
    transmit = once(transmit, '\ttag = airoha_get_dsa_tag(skb, dev);', '''\ttag = airoha_get_dsa_tag(skb, dev);
\tbe6l_diag_driver_tx(((struct airoha_gdm_dev *)netdev_priv(dev))->eth->ppe,
\t\t\t    skb, dev, tag, diag_was_gso, diag_summed_before);''')
    changed[names[7]] = ethernet[:begin] + transmit + ethernet[end:]
    work.mkdir()
    for name, text in changed.items():
        p = work / 'tree' / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    driver = work / 'tree/drivers/net/ethernet/airoha'
    for source in (K / 'drivers/net/ethernet/airoha').glob('*'):
        if source.suffix in ('.c', '.h') and not (driver / source.name).exists():
            shutil.copyfile(source, driver / source.name)
    for name in ('diag.c', 'diag.h', 'epoch.h'):
        shutil.copyfile(BASE / 'experiments/wired-kernel-diag-v1' / name, driver / name)
    adapter = (driver / 'diag.c').read_text()
    adapter = once(adapter, '#include "epoch.h"', '#include "epoch.h"\n#include "record.h"')
    adapter = once(adapter, '#include <net/ip.h>', '#include <net/ip.h>\n#include <net/netfilter/nf_conntrack.h>\n#include <net/netfilter/nf_conntrack_zones.h>')
    adapter = once(adapter, '#include <linux/err.h>', '#include <linux/err.h>\n#include <linux/debugfs.h>\n#include <linux/seq_file.h>\n#include <linux/uaccess.h>\n#include <linux/module.h>')
    adapter = adapter.replace('/* Caller must first unpublish/drain its CT/RX taps. No live tap is installed. */',
                              '/* The owning driver must first unpublish and drain its CT/RX taps. */')
    adapter = once(adapter, 'return c->valid == 1 && c->version == FLOW_RULE_CT_CONTEXT_VERSION &&',
                   'return bd_identity_valid(c) && c->version == FLOW_RULE_CT_CONTEXT_VERSION &&')
    adapter = once(adapter, 'int i, slot = -1, redirects = 0, error = -EOPNOTSUPP;',
                   'int i, redirects = 0, error = -EOPNOTSUPP;')
    adapter = once(adapter, '\t\td->snapshot.reason = reason;\n', '''\t\td->snapshot.reason = reason;
\t\tfor (i = 0; i < BD_SLOTS; i++) {
\t\t\tif (d->snapshot.rows[i].used) {
\t\t\t\td->snapshot.rows[i].used = false;
\t\t\t\td->snapshot.rows[i].revoked = true;
\t\t\t}
\t\t}
''')
    adapter = once(adapter, '\td->snapshot.active = d->snapshot.spent = true;',
                   '\td->snapshot.version = 2;\n\td->snapshot.active = d->snapshot.spent = true;')
    adapter = once(adapter, '\tmemset(out, 0, sizeof(*out));',
                   '\tint i;\n\tmemset(out, 0, sizeof(*out));\n\tout->version = 2;')
    adapter = once(adapter, '\tout->unresolved = 0x3f;', '''\tout->unresolved = 0x3f;
\tif (!out->active)
\t\tfor (i = 0; i < BD_SLOTS; i++)
\t\t\tif (out->rows[i].used) {
\t\t\t\tout->rows[i].used = false;
\t\t\t\tout->rows[i].revoked = true;
\t\t\t}''')
    start = adapter.index('\tfor (i = 0; i < BD_SLOTS; i++) {', adapter.index('int be6l_diag_note_ct('))
    end = adapter.index('\nout:\n', start)
    adapter = adapter[:start] + '''\trow.used = true;
\trow.observed_ns = ktime_get_ns();
\terror = bd_record_replace(d->snapshot.rows, &row);
\tif (error > 0) {
\t\td->snapshot.accepted++;
\t\tif (error == 2)
\t\t\td->snapshot.replaced++;
\t\terror = 0;
\t}
''' + adapter[end:]
    (driver / 'diag.c').write_text(adapter)
    diag_header = (driver / 'diag.h').read_text()
    diag_header = once(diag_header, '\tu64 generation, created_ns, deadline_ns, accepted, rejected;',
                       '\tu64 generation, created_ns, deadline_ns, accepted, rejected, replaced, destroyed;\n\tu64 egress_accepted, egress_rejected, ct_callbacks, ct_callback_rejected;\n\ts32 last_ct_errno;')
    diag_header = once(diag_header, 'struct bd_snapshot {', 'struct bd_snapshot {\n\tu32 version;')
    diag_header = once(diag_header, 'struct bd_row {', '''struct bd_egress {
\tu64 observed_ns, ct_cookie;
\tu32 key[3], actual_ifindex, logical_output_ifindex, tag, frame_bytes, seq, ack_seq;
\tu8 direction, summed_before, summed_after, ttl, src_mac[6], dst_mac[6];
\tbool was_gso, format_complete, delivered;
};
struct bd_row {''')
    diag_header = once(diag_header, '\tbool used, rx_matched;', '\tbool used, rx_matched, revoked;')
    diag_header = once(diag_header, '\tstruct bd_action_copy actions[BD_ACTIONS];',
                       '\tstruct bd_action_copy actions[BD_ACTIONS];\n\tstruct bd_egress egress;')
    begin = diag_header.index('/* Internal library API only:')
    end = diag_header.index(' */', begin) + 3
    diag_header = diag_header[:begin] + '/* CPU diagnostic API with root-only finite observation control. No hardware\n * publisher exists. The driver drains readers before destroy.\n */' + diag_header[end:]
    (driver / 'diag.h').write_text(diag_header)
    # The v2 adapter and tests are separate from the frozen v1 experiment.
    for name in ('diag-v2.c.inc', 'diag-v2.h.inc', 'record.h'):
        source = BASE / 'experiments/wired-kernel-diag-v2' / name
        assert source.is_file(), name
        if name.endswith('.inc'):
            target = driver / ('diag.c' if '.c.' in name else 'diag.h')
            if target.suffix == '.h':
                target.write_text(once(target.read_text(), '\n#endif\n', '\n' + source.read_text() + '\n#endif\n'))
            else:
                with target.open('a') as output:
                    output.write('\n' + source.read_text())
        else:
            shutil.copyfile(source, driver / name)
    with (driver / 'diag.c').open('a') as target:
        target.write('\n' + (BASE / 'experiments/wired-kernel-diag-v2/tx.c.inc').read_text())
        target.write('\n' + (BASE / 'experiments/wired-kernel-diag-v2/control.c.inc').read_text())
    patch = ''.join(''.join(difflib.unified_diff(originals[name].splitlines(True), changed[name].splitlines(True),
                    fromfile='a/' + name, tofile='b/' + name)) for name in names)
    for name in ('diag.c', 'diag.h', 'epoch.h', 'record.h'):
        relative = 'drivers/net/ethernet/airoha/' + name
        assert not (K / relative).exists()
        patch += ''.join(difflib.unified_diff([], (driver / name).read_text().splitlines(True),
                          fromfile='/dev/null', tofile='b/' + relative))
    (work / '977-n1-identity-and-inert-driver-taps.patch').write_text(patch)
    receipt = dict(schema=1, sdk=str(SDK), work=str(work), source_files={name: sha(K / name) for name in names},
        changed_files={name: sha(work / 'tree' / name) for name in names},
        kernel_internal_abi_changed=True, full_matched_kernel_and_consumers_required=True,
        sdk_modified=False, target_executed=False, userspace_arming_interface=True,
        arming_controls_cpu_observation_only=True, automatic_unb_classification_change=False,
        can_publish=False, software_egress_implemented=True, software_egress_target_qualified=False,
        direct_ct_destroy_notifier=False)
    (work / 'preparation.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print('N1_V2_ISOLATED_TREE_PREPARED', work)


if __name__ == '__main__':
    main()
