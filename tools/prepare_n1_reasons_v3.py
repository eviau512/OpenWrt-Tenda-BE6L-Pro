"""Create an isolated counters-only delta over the exact running N1 sources."""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import shutil
from test_routed_context_functions import function

base=Path(__file__).resolve().parents[1]
sdk=Path('/root/be6l-openwrt/arm64-source')
k=sdk/'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);a=p.parse_args()
work=a.work.resolve()
assert work.parent==Path('/root/be6l-openwrt') and work.name.startswith('n1-reasons-v3-') and not work.exists()
prefix='drivers/net/ethernet/airoha/'
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
pins={'diag.c':'1613f84fa0fc2fbd2e85feb6ae9a675ef8bc4367132ebfbe348b999aed547301',
      'diag.h':'bb900fd3efa64812e4a730e4ed16b30c12e6e0128266fd8135ad3541caab5007'}
originals={name:(k/prefix/name).read_text() for name in pins}
for name,digest in pins.items():assert sha(k/prefix/name)==digest
def once(text,old,new):
 assert text.count(old)==1,old[:100]
 return text.replace(old,new)
c=originals['diag.c'];header=originals['diag.h']
header=once(header,'#include <net/flow_offload.h>','#include <net/flow_offload.h>\n#include "reasons.h"')
header=once(header,'\ts32 last_ct_errno;','\ts32 last_ct_errno;\n\tstruct bd_reasons reasons;')
helpers='''
/* Only a live CPU lease may count; no packet or hardware state is changed. */
static bool bd_count(struct be6l_diag *d, unsigned int reason)
{
 spin_lock_bh(&d->lock);
 if (bd_epoch_live(&d->epoch, ktime_get_ns()))
  bd_reason_add(&d->snapshot.reasons, reason);
 spin_unlock_bh(&d->lock);
 return false;
}
#define BD_REASON_NAME(name) #name,
static const char *const bd_reason_names[] = {
 BD_REASON_LIST(BD_REASON_NAME)
};
#undef BD_REASON_NAME
'''
c=once(c,'static bool bd_registered(',helpers+'\nstatic bool bd_registered(')
rx=function(c,'bool be6l_diag_note_rx(')
new=once(rx,'if (IS_ERR_OR_NULL(d) || !skb || !unbound || skb_vlan_tag_present(skb) ||',
 '''if (IS_ERR_OR_NULL(d))
  return false;
 bd_count(d, BD_REASON_RX_SEEN);
 if (!skb || !unbound || skb_vlan_tag_present(skb) ||''')
reasons=['RX_BASIC','RX_OFFSET','RX_ETH','RX_IPV4','RX_LENGTH','RX_TCP','RX_CSUM_OPTIONS','RX_UNB_KEY']
# Keep the first invalid-observer return; each original packet refusal retains
# its exact predicate and false result, with one finite CPU counter added.
first=new.index('return false;')+len('return false;')
left,right=new[:first],new[first:]
assert right.count('return false;')==len(reasons)
for reason in reasons:
 right=right.replace('return false;','return bd_count(d, BD_REASON_'+reason+');',1)
new=left+right
new=once(new,'out:\n\tspin_unlock_bh(&d->lock);',
 ''' if (bd_epoch_live(&d->epoch, ktime_get_ns()))
  bd_reason_add(&d->snapshot.reasons,
                matched ? BD_REASON_RX_ACCEPTED : BD_REASON_RX_NO_ROW);
out:
 spin_unlock_bh(&d->lock);''')
c=once(c,rx,new)
tx=function(c,'void be6l_diag_driver_tx(')
new=once(tx,'''\tif (!skb || skb_vlan_tag_present(skb))
\t\treturn;
\trcu_read_lock();
\td = rcu_dereference(ppe->route_diag);
\tif (!d)
\t\tgoto out;''',''' rcu_read_lock();
 d = rcu_dereference(ppe->route_diag);
 if (!d)
  goto out;
 bd_count(d, BD_REASON_TX_SEEN);
 if (!skb || skb_vlan_tag_present(skb)) {
  bd_count(d, BD_REASON_TX_BASIC);
  goto out;
 }''')
new=once(new,'''\tif (!ct || !net_eq(nf_ct_net(ct), &init_net))
\t\tgoto out;''',''' if (!ct) {
  bd_count(d, BD_REASON_TX_NO_CT);
  goto out;
 }
 if (!net_eq(nf_ct_net(ct), &init_net)) {
  bd_count(d, BD_REASON_TX_NETNS);
  goto out;
 }''')
checks=[
 ('if (zone->id || zone->flags || zone->dir != 3)','TX_ZONE'),
 ('if (!eth || eth->h_proto != htons(ETH_P_IP))','TX_ETH'),
 ('if (!ip || ip->version != 4 || ip->ihl != 5 || ip->protocol != IPPROTO_TCP ||\n\t    (ntohs(ip->frag_off) & 0x3fff))','TX_IPV4'),
 ('if (length < sizeof(ib) + sizeof(tb) || skb->len < ETH_HLEN || length > skb->len - ETH_HLEN)','TX_LENGTH'),
 ('if (!tcp || tcp->doff < 5 || tcp->doff * 4 > length - sizeof(ib) ||\n\t    !bd_options(skb, ETH_HLEN + sizeof(ib) + sizeof(tb), tcp->doff * 4 - sizeof(tb)))','TX_TCP_OPTIONS'),
]
for check,reason in checks:
 new=once(new,'\t'+check+'\n\t\tgoto out;',
          '\t'+check+' {\n\t\tbd_count(d, BD_REASON_'+reason+');\n\t\tgoto out;\n\t}')
new=once(new,'''\telse
\t\tgoto unlock;
\tif (bd_record_egress(d->snapshot.rows, &sample))
\t\td->snapshot.egress_accepted++;
\telse
\t\td->snapshot.egress_rejected++;''',''' else {
  bd_reason_add(&d->snapshot.reasons, BD_REASON_TX_OUTPUT);
  goto unlock;
 }
 if (bd_record_egress(d->snapshot.rows, &sample)) {
  d->snapshot.egress_accepted++;
  bd_reason_add(&d->snapshot.reasons, BD_REASON_TX_ACCEPTED);
 } else {
  d->snapshot.egress_rejected++;
  bd_reason_add(&d->snapshot.reasons, BD_REASON_TX_NO_PAIR);
 }''')
c=once(c,tx,new)
show=function(c,'static int bd_control_show(')
show_new=once(show,'\tfor (i = 0; i < BD_SLOTS; i++) {',
 ''' for (i = 0; i < BD_REASON_COUNT; i++)
  seq_printf(seq, "stage=%s count=%llu last=%u\\n",
             bd_reason_names[i], s->reasons.count[i], i == s->reasons.last);
\tfor (i = 0; i < BD_SLOTS; i++) {''')
c=once(c,show,show_new)
for old,new in [('d->snapshot.version = 2','d->snapshot.version = 3'),
                ('out->version = 2','out->version = 3'),('s->version = 2','s->version = 3')]:
 c=once(c,old,new)
# No producer/admission/TC/RX ownership/flow core/record function is rewritten.
for marker in ('int be6l_diag_note_ct(', 'int be6l_diag_driver_arm(',
               'void be6l_diag_driver_command(', 'void be6l_diag_driver_stop('):
 assert function(c,marker)==function(originals['diag.c'],marker),marker
work.mkdir()
tree=work/'tree';driver=tree/prefix;driver.mkdir(parents=True)
for source in (k/prefix).iterdir():
 if source.suffix in ('.c','.h') or source.name=='Makefile':
  shutil.copyfile(source,driver/source.name)
(driver/'diag.c').write_text(c)
(driver/'diag.h').write_text(header)
shutil.copyfile(base/'experiments/wired-kernel-diag-v3/reasons.h',driver/'reasons.h')
names=['include/net/flow_offload.h','include/net/netfilter/nf_flow_table.h',
       'net/core/flow_offload.c','net/netfilter/nf_flow_table_core.c',
       'net/netfilter/nf_flow_table_offload.c',prefix+'airoha_eth.h',
       prefix+'airoha_eth.c',prefix+'airoha_ppe.c',prefix+'Makefile',prefix+'diag.c',prefix+'diag.h',
       prefix+'epoch.h',prefix+'record.h']
for name in names:
 path=tree/name
 if not path.exists():
  path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(k/name,path)
changed={prefix+'diag.c':c,prefix+'diag.h':header}
patch=''.join(''.join(difflib.unified_diff(originals[Path(name).name].splitlines(True),
     value.splitlines(True),fromfile='a/'+name,tofile='b/'+name)) for name,value in changed.items())
patch+=''.join(difflib.unified_diff([], (driver/'reasons.h').read_text().splitlines(True),
     fromfile='/dev/null',tofile='b/'+prefix+'reasons.h'))
(work/'978-n1-bounded-refusal-reasons.patch').write_text(patch)
receipt=dict(schema=3,sdk=str(sdk),work=str(work),source_files={name:sha(k/name) for name in names},
    changed_files={name:sha(tree/name) for name in changed},
    producer_context_version=2,context_bytes=56,diagnostic_snapshot_version=3,
    global_kernel_internal_abi_changed=False,full_matched_driver_kernel_package_build_required=True,
    sdk_modified=False,target_executed=False,can_publish=False,
    admission_and_identity_predicates_preserved=True,automatic_unb_classification_change=False)
(work/'preparation.json').write_text(json.dumps(receipt,indent=2)+'\n')
print('N1_V3_COUNTERS_ONLY_ISOLATED_TREE_PREPARED',work)
