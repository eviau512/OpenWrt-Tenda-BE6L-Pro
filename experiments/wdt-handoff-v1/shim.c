/* SPDX-License-Identifier: MIT */
/* Linux API boundary doubles. The watchdog functions are extracted unchanged. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
#define __iomem
#define BIT(n) (1U << (n))
#define GENMASK(h,l) ((UINT32_MAX >> (31-(h))) & (UINT32_MAX << (l)))
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define WDOG_NO_WAY_OUT 0
struct watchdog_device { unsigned int timeout; unsigned long status; bool active; void *data; };
struct device { void *data; };
struct platform_device { struct device dev; };
static u32 registers[32];
static bool sticky_enable, kexec_in_progress;
static unsigned reads, writes, infos, errors;
static void *watchdog_get_drvdata(struct watchdog_device *w) { return w->data; }
static bool watchdog_active(struct watchdog_device *w) { return w->active; }
static void *platform_get_drvdata(struct platform_device *p) { return p->dev.data; }
static void *dev_get_drvdata(struct device *d) { return d->data; }
static bool test_bit(unsigned bit, unsigned long *value) { return (*value >> bit) & 1; }
static u32 readl(void *p) { reads++; return *(u32 *)p; }
static void writel(u32 v, void *p) {
    assert(p >= (void *)registers && p < (void *)(registers+32)); writes++;
    if (sticky_enable && p == (void *)registers) v |= BIT(25)|BIT(5);
    *(u32 *)p = v;
}
#define dev_err(device,...) do { (void)(device); errors++; } while (0)
#define dev_info(device,...) do { (void)(device); infos++; } while (0)

/* ACTUAL_FUNCTIONS */

static void reset(struct airoha_wdt_desc *d, struct platform_device *p) {
    memset(registers,0,sizeof(registers)); memset(d,0,sizeof(*d));
    d->base=registers; d->wdt_freq=150000000; d->wdog_dev.timeout=24;
    d->wdog_dev.data=d; p->dev.data=d;
    sticky_enable=false; kexec_in_progress=false; reads=writes=infos=errors=0;
}
int main(void) {
    struct airoha_wdt_desc d; struct platform_device p; unsigned cases=0;
    const u32 unrelated=BIT(21)|BIT(7)|BIT(3), enabled=WDT_ENABLE|WDT_TIMER_ENABLE;
    reset(&d,&p); registers[0]=unrelated|enabled;
    assert(airoha_wdt_stop(&d.wdog_dev)==0 && registers[0]==unrelated && reads==2 && writes==1); cases++;
    reset(&d,&p); registers[0]=unrelated;
    assert(airoha_wdt_stop(&d.wdog_dev)==0 && registers[0]==unrelated); cases++;
    reset(&d,&p); sticky_enable=true; registers[0]=unrelated|enabled;
    assert(airoha_wdt_stop(&d.wdog_dev)==-EIO && registers[0]==(unrelated|enabled)); cases++;
    reset(&d,&p); d.wdog_dev.active=true; registers[0]=enabled|unrelated;
    assert(airoha_wdt_set_timeout(&d.wdog_dev,12)==0 && d.wdog_dev.timeout==12);
    assert(registers[WDT_TIMER_LOAD_VALUE/4]==1800000000U && (registers[0]&enabled)==enabled); cases++;
    reset(&d,&p); sticky_enable=true; d.wdog_dev.active=true; registers[0]=enabled;
    assert(airoha_wdt_set_timeout(&d.wdog_dev,12)==-EIO && d.wdog_dev.timeout==24 && writes==1); cases++;
    reset(&d,&p); assert(airoha_wdt_set_timeout(&d.wdog_dev,12)==0 && writes==0); cases++;
    reset(&d,&p); registers[0]=enabled; airoha_wdt_shutdown(&p);
    assert(registers[0]==enabled && writes==0 && infos==0 && errors==0); cases++;
    reset(&d,&p); kexec_in_progress=true; d.wdog_dev.status=1; registers[0]=enabled;
    airoha_wdt_shutdown(&p); assert(registers[0]==enabled && writes==0 && errors==1 && infos==0); cases++;
    reset(&d,&p); kexec_in_progress=true; registers[0]=unrelated|enabled;
    airoha_wdt_shutdown(&p); assert(registers[0]==unrelated && infos==1 && errors==0); cases++;
    reset(&d,&p); kexec_in_progress=true; sticky_enable=true; registers[0]=enabled;
    airoha_wdt_shutdown(&p); assert(errors==1 && infos==0 && registers[0]==enabled); cases++;
    reset(&d,&p); kexec_in_progress=true; p.dev.data=NULL;
    airoha_wdt_shutdown(&p); assert(writes==0 && infos==0); cases++;
    reset(&d,&p); d.wdog_dev.active=true; sticky_enable=true; registers[0]=enabled;
    assert(airoha_wdt_suspend(&p.dev)==-EIO); cases++;
    reset(&d,&p); assert(airoha_wdt_suspend(&p.dev)==0 && writes==0); cases++;
    reset(&d,&p); d.wdog_dev.active=true;
    assert(airoha_wdt_resume(&p.dev)==0 && (registers[0]&enabled)==enabled && (registers[WDT_RELOAD/4]&WDT_RLD)); cases++;
    reset(&d,&p); registers[WDT_TIMER_CUR_VALUE/4]=150000001;
    assert(airoha_wdt_get_timeleft(&d.wdog_dev)==2); cases++;
    printf("{\"passed\":true,\"actual_function_cases\":%u,\"hardware_access\":false}\n",cases);
}
