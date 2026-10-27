"""Compile the real snapshot helpers and selected kernel objects; no DUT access."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import subprocess
import time

BASE = Path(__file__).resolve().parents[1]
SDK = Path('/root/be6l-openwrt/arm64-source')
K = SDK / 'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--kernel', type=Path, default=K)
parser.add_argument('--output', type=Path)
args = parser.parse_args()
K = args.kernel.resolve()
OUT = args.output or BASE / 'logs' / time.strftime('routed-context-test-%Y%m%d-%H%M%S')
OUT.mkdir(parents=True, exist_ok=False)
BUILD = Path('/root/be6l-openwrt') / OUT.name
BUILD.mkdir(exist_ok=True)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def function(text, marker):
    start = text.index(marker)
    opening = text.index('{', start)
    depth = 0
    for i in range(opening, len(text)):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if not depth:
                return text[start:i + 1]
    raise AssertionError('Unclosed source function: ' + marker)

header = (K / 'include/net/flow_offload.h').read_text()
nf = (K / 'net/netfilter/nf_flow_table_offload.c').read_text()
ppe = (K / 'drivers/net/ethernet/airoha/airoha_ppe.c').read_text()
zones = (K / 'include/net/netfilter/nf_conntrack_zones.h').read_text()
common = (K / 'include/linux/netfilter/nf_conntrack_zones_common.h').read_text()
context = function(header, 'struct flow_rule_ct_context {') + ';'
assert '*' not in context, 'Context must not retain any pointer'
setter = function(nf, 'static bool\nnf_flow_rule_set_ct_context(')
reason = function(ppe, 'static const char *\nairoha_ppe_routed_context_error(')
zone_id = function(zones, 'static inline u16 nf_ct_zone_id(')
zone_matches = function(zones, 'static inline bool nf_ct_zone_matches_dir(')
zone_struct = function(common, 'struct nf_conntrack_zone {') + ';'
assert 'FLOW_DISSECTOR_KEY_CT' not in nf
assert re.search(r'if \(airoha_is_7563\(eth\) && addr_type\) \{[^}]+return -EOPNOTSUPP;', ppe)
assert 'PPE_PKT_TYPE_BRIDGE ||\n\t     !airoha_ppe_native_bridge_match' in ppe
alloc = function(nf, 'static struct nf_flow_rule *\nnf_flow_offload_rule_alloc(')
assert alloc.index('nf_flow_rule_set_ct_context(') < alloc.index('flowtable->type->action(')
assert 'GFP_KERNEL' in (K / 'net/core/flow_offload.c').read_text()
assert 'rule = kzalloc(struct_size(rule, action.entries, num_actions),' in (K / 'net/core/flow_offload.c').read_text()
assert setter.index('context->valid = 1;') > setter.index('context->reserved = 0;')
assert 'nf_ct_zone_id(zone, ct_dir)' in setter
assert 'IP_CT_DIR_ORIGINAL : IP_CT_DIR_REPLY' in setter

source = '''#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef uint16_t u16;
typedef uint8_t u8;
typedef uint32_t u32;
#define FLOW_RULE_CT_CONTEXT_VERSION 1
#define FLOW_RULE_CT_CONTEXT_NF_FLOWTABLE 1
#define NF_CT_DEFAULT_ZONE_ID 0
enum ip_conntrack_dir { IP_CT_DIR_ORIGINAL, IP_CT_DIR_REPLY };
enum flow_offload_tuple_dir { FLOW_OFFLOAD_DIR_ORIGINAL, FLOW_OFFLOAD_DIR_REPLY, FLOW_OFFLOAD_DIR_MAX };
struct net { unsigned int id; };
static struct net init_net = { 1 };
static bool net_eq(const struct net *a, const struct net *b) { return a == b; }
''' + zone_struct + '\n' + context + '''
struct nf_conn { const struct net *net; struct nf_conntrack_zone zone; };
struct flow_offload { struct nf_conn *ct; };
struct flow_rule { struct flow_rule_ct_context ct_context; };
static const struct net *nf_ct_net(const struct nf_conn *ct) { return ct->net; }
static const struct nf_conntrack_zone *nf_ct_zone(const struct nf_conn *ct) {
#ifdef CONFIG_NF_CONNTRACK_ZONES
 return &ct->zone;
#else
 static const struct nf_conntrack_zone default_zone = { .id = 0, .flags = 0, .dir = 3 };
 (void)ct;
 return &default_zone;
#endif
}
''' + zone_matches + '\n' + zone_id + '\n' + setter + '\n' + reason + '''
int main(void)
{
 struct net other = { 2 };
 struct nf_conn ct = { .net = &init_net, .zone = { .id = 0, .flags = 0, .dir = 3 } };
 struct flow_offload flow = { .ct = &ct };
 struct flow_rule rule = { 0 };
 unsigned int cases = 0;
 _Static_assert(sizeof(struct flow_rule_ct_context) == 16, "snapshot layout changed");
 _Static_assert(offsetof(struct flow_rule_ct_context, reserved) == 12, "snapshot padding changed");
 assert(strstr(airoha_ppe_routed_context_error(&rule.ct_context), "lacks explicit"));
 cases++;
 for (unsigned int id_index = 0; id_index < 3; id_index++) {
  unsigned int id = id_index == 2 ? 65535 : id_index;
  for (unsigned int mask = 0; mask < 4; mask++)
   for (unsigned int flags = 0; flags < 2; flags++)
    for (unsigned int direction = 0; direction < 2; direction++) {
     ct.zone = (struct nf_conntrack_zone){ .id = id, .dir = mask, .flags = flags };
     assert(nf_flow_rule_set_ct_context(&rule, &init_net, &flow, direction));
     const struct nf_conntrack_zone *zone = nf_ct_zone(&ct);
     struct flow_rule_ct_context *c = &rule.ct_context;
     assert(c->valid == 1 && c->producer == FLOW_RULE_CT_CONTEXT_NF_FLOWTABLE);
     assert(c->version == FLOW_RULE_CT_CONTEXT_VERSION && c->initial_netns == 1);
     assert(c->direction == direction && c->zone_raw_id == zone->id);
     assert(c->zone_dir == zone->dir && c->zone_flags == zone->flags);
#ifdef CONFIG_NF_CONNTRACK_ZONES
     assert(c->zone_id == ((mask & (1U << direction)) ? id : 0));
     bool default_zone = !id && !flags && mask == 3;
#else
     assert(c->zone_id == 0);
     bool default_zone = true;
#endif
     const char *error = airoha_ppe_routed_context_error(c);
     assert(strstr(error, default_zone ? "not implemented" : "default CT zone"));
     struct flow_rule_ct_context saved = *c;
     ct.zone.id ^= 1;
     assert(!memcmp(c, &saved, sizeof(saved)));
     cases++;
    }
 }
 ct.zone = (struct nf_conntrack_zone){ .id = 0, .dir = 3 };
 ct.net = &other;
 assert(nf_flow_rule_set_ct_context(&rule, &other, &flow, FLOW_OFFLOAD_DIR_REPLY));
 assert(!rule.ct_context.initial_netns);
 assert(strstr(airoha_ppe_routed_context_error(&rule.ct_context), "initial network namespace"));
 cases++;
 memset(&rule.ct_context, 0xa5, sizeof(rule.ct_context));
 assert(!nf_flow_rule_set_ct_context(&rule, &init_net, &flow, FLOW_OFFLOAD_DIR_ORIGINAL));
 struct flow_rule_ct_context zero = { 0 };
 assert(!memcmp(&rule.ct_context, &zero, sizeof(zero)));
 cases++;
 ct.net = &init_net;
 for (unsigned int i = 0; i < 2; i++) {
  memset(&rule.ct_context, 0xa5, sizeof(rule.ct_context));
  assert(!nf_flow_rule_set_ct_context(&rule, &init_net, &flow, i ? -1 : FLOW_OFFLOAD_DIR_MAX));
  assert(!memcmp(&rule.ct_context, &zero, sizeof(zero)));
  cases++;
 }
 assert(nf_flow_rule_set_ct_context(&rule, &init_net, &flow, FLOW_OFFLOAD_DIR_ORIGINAL));
 struct flow_rule_ct_context good = rule.ct_context;
 for (unsigned int i = 0; i < 7; i++) {
  struct flow_rule_ct_context bad = good;
  switch (i) {
   case 0: bad.valid = 2; break;
   case 1: bad.version++; break;
   case 2: bad.producer++; break;
   case 3: bad.direction = 2; break;
   case 4: bad.reserved = 1; break;
   case 5: bad.initial_netns = 2; break;
   default: bad.valid = 0; break;
  }
  assert(strstr(airoha_ppe_routed_context_error(&bad), "lacks explicit"));
  cases++;
 }
 printf("SOURCE_CONTEXT_TEST_PASS cases=%u zones=%u routed_success=0\\n", cases,
#ifdef CONFIG_NF_CONNTRACK_ZONES
 1U
#else
 0U
#endif
 );
 return 0;
}
'''
(OUT / 'source-helper-test.c').write_text(source)
(BUILD / 'source-helper-test.c').write_text(source)
tests = []
for enabled in (False, True):
    binary = BUILD / ('context-test-zones-' + str(int(enabled)))
    command = ['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
               '-Wno-unused-parameter', '-fsanitize=undefined']
    if enabled:
        command.append('-DCONFIG_NF_CONNTRACK_ZONES=1')
    subprocess.run(command + [str(BUILD / 'source-helper-test.c'), '-o', str(binary)], check=True)
    result = subprocess.check_output([str(binary)], text=True).strip()
    print(result, flush=True)
    tests.append(dict(zones_enabled=enabled, result=result, ubsan=True))

config_before = sha(K / '.config')
image = K / 'arch/arm64/boot/Image'
image_before = sha(image)
module_paths = sorted(K.rglob('*.ko'))
module_before = {str(p.relative_to(K)): sha(p) for p in module_paths}
targets = ['net/core/flow_offload.o', 'net/netfilter/nf_flow_table_offload.o',
           'drivers/net/ethernet/airoha/airoha_ppe.o']
objects_before = {name: sha(K / name) for name in targets}
source_before = {name: sha(K / Path(name).with_suffix('.c')) for name in targets}
# Kbuild recurses into subdirectories, where GNU make's relative -W paths no
# longer identify the same header. Touch only the three owned source mtimes;
# verify their contents afterward and force actual compiler runs on repeats.
for name in targets:
    os.utime(K / Path(name).with_suffix('.c'), None)
gcc, = SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
env = dict(os.environ)
env.update(PATH='/root/be6l-openwrt/host/bin:' + env['PATH'],
           STAGING_DIR=str(SDK / 'staging_dir'), KCONFIG_NOSILENTUPDATE='1')
with (OUT / 'kernel-objects-compile.txt').open('wb') as log:
    subprocess.run(['make', '-C', str(K), '-j4', 'ARCH=arm64',
                    'CROSS_COMPILE=' + str(gcc)[:-3],
                    'SHELL=/root/be6l-openwrt/host/bin/bash', *targets],
                   env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
objects_after = {name: sha(K / name) for name in targets}
compile_log = (OUT / 'kernel-objects-compile.txt').read_text()
for name in targets:
    assert re.search(r'CC(?: \[M\])?\s+' + re.escape(name), compile_log), name + ' was not rebuilt'
    data = (K / name).read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01' and data[18:20] == b'\xb7\0'
assert sha(K / '.config') == config_before
assert sha(image) == image_before
assert {name: sha(K / Path(name).with_suffix('.c')) for name in targets} == source_before
assert {str(p.relative_to(K)): sha(p) for p in K.rglob('*.ko')} == module_before
patch_name = 'target/linux/airoha/patches-6.18/973-net-flowtable-preserve-explicit-ct-context-for-admission.patch'
patch = BASE / 'overlay' / patch_name
if not patch.is_file():
    patch = SDK / patch_name
subprocess.run(['patch', '--dry-run', '--reverse', '-p1', '-d', str(K)],
               input=patch.read_bytes(),
               check=True)
report = dict(source_provenance_tests=tests, real_source_helpers_compiled=True,
              explicit_directional_zone_tested=True, namespace_mismatch_tested=True,
              invalid_producer_version_reserved_tested=True, routed_successes=0,
              compiled_targets=targets, object_before=objects_before, object_after=objects_after,
              kernel_config_sha256=config_before, unchanged_image_sha256=image_before,
              unchanged_module_count=len(module_before), module_bytes_unchanged=True,
              hardware_access=False, classifier_changed=False, image_built=False,
              modules_installed=False, internal_flow_rule_abi_changed=True,
              requires_matching_full_kernel_and_modules_before_future_image=True)
(OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2), flush=True)
