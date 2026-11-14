/* SPDX-License-Identifier: MIT */
/* Native integer-only early root gate and shared recovery heartbeat protocol.
 * Generated manifests are compiled in; production accepts no alternate root,
 * manifest, interpreter, binfmt flags or successful-trust bypass option.
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/mount.h>
#include <sys/file.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include "sha256.h"

#define PRIVATE_FLAGS 0xbe6a0001U
#define ROLE_DATA 0
#define ROLE_PRIVATE 1
#define ROLE_STANDARD 2
#define ROLE_ARM32 3
#define ROLE_SELF 4
#define ROLE_LINK 5
#define ROOT_RAMFS 0x858458f6UL
#define ROOT_TMPFS 0x01021994UL
#define PROC_FS 0x9fa0UL
#define SYS_FS 0x62656572UL
#define BINFMT_FS 0x42494e4dUL
#define GUARD_NAME "be6l-recovery-state"
#define GUARD_DIR "/" GUARD_NAME
#define MAX_ENTRIES 4096
struct manifest_entry { const char *path,*digest,*link; uint64_t size; unsigned mode,role,static_native; };
#include "bootstrap_manifest.h"
static const char *failure="unknown";
static unsigned char seen[MAX_ENTRIES];
static unsigned visited;

static int bad(const char *why) { failure=why; return -1; }
static uint16_t le16(const unsigned char *p) { return p[0]|(uint16_t)p[1]<<8; }
static uint32_t le32(const unsigned char *p) { return p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static uint64_t le64(const unsigned char *p) { return le32(p)|(uint64_t)le32(p+4)<<32; }
static int same_stat(const struct stat *a,const struct stat *b)
{
 return a->st_dev==b->st_dev && a->st_ino==b->st_ino && a->st_size==b->st_size &&
  a->st_mtim.tv_sec==b->st_mtim.tv_sec && a->st_mtim.tv_nsec==b->st_mtim.tv_nsec &&
  a->st_ctim.tv_sec==b->st_ctim.tv_sec && a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
static int protected_dir(int fd)
{
 struct stat st;
 return fstat(fd,&st)||!S_ISDIR(st.st_mode)||st.st_uid||st.st_mode&0022 ? bad("writable or unowned ancestor") : 0;
}
static int parent_fd(int root,const char *name,char leaf[NAME_MAX+1])
{
 char path[PATH_MAX],*part,*save; int dir=dup(root),next;
 if(dir<0||strlen(name)>=sizeof(path)||!name[0]||name[0]=='/') { if(dir>=0)close(dir);return bad("invalid manifest path"); }
 strcpy(path,name);part=strtok_r(path,"/",&save);
 while(part) {
  if(!strcmp(part,".")||!strcmp(part,"..")||strlen(part)>NAME_MAX||protected_dir(dir))goto fail;
  char *following=strtok_r(NULL,"/",&save);
  if(!following){strcpy(leaf,part);return dir;}
  next=openat(dir,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);close(dir);dir=next;
  if(dir<0)goto fail;
  part=following;
 }
fail:
 if(dir>=0)close(dir);return bad("symlink, missing or writable ancestor");
}
static int safe_open(int root,const char *name)
{
 char leaf[NAME_MAX+1];int parent=parent_fd(root,name,leaf),fd;
 if(parent<0)return -1;
 fd=openat(parent,leaf,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);close(parent);
 if(fd<0)return bad("missing or symlink manifest file");
 return fd;
}
static int hash_fd(int fd,char hex[65],struct stat *initial)
{
 unsigned char buffer[16384],digest[32];struct be6l_sha256 sha;struct stat after;ssize_t n;
 if(fstat(fd,initial)||!S_ISREG(initial->st_mode)||initial->st_uid||initial->st_mode&0022||lseek(fd,0,SEEK_SET)<0)
  return bad("unowned, writable or nonregular file");
 be6l_sha256_init(&sha);
 while((n=read(fd,buffer,sizeof(buffer)))!=0){if(n<0){if(errno==EINTR)continue;return bad("hash read failed");}be6l_sha256_update(&sha,buffer,(size_t)n);}
 if(fstat(fd,&after)||!same_stat(initial,&after))return bad("file changed during hash");
 be6l_sha256_final(&sha,digest);
 static const char digits[]="0123456789abcdef";
 for(unsigned i=0;i<32;i++){hex[i*2]=digits[digest[i]>>4];hex[i*2+1]=digits[digest[i]&15];}hex[64]=0;
 return 0;
}
static int elf_info(int fd,unsigned role,unsigned require_static)
{
 unsigned char h[64],ph[56];ssize_t n=pread(fd,h,sizeof(h),0);struct stat st;
 if(n!=64||memcmp(h,"\177ELF",4)||h[5]!=1||h[6]!=1||fstat(fd,&st))return bad("bad ELF header");
 if(role==ROLE_ARM32) return h[4]==1&&le16(h+18)==40 ? 0 : bad("ARM32 role mismatch");
 if(h[4]!=2||le16(h+18)!=183||(le16(h+16)!=2&&le16(h+16)!=3))return bad("A64 role mismatch");
 if(le32(h+48)!=(role==ROLE_STANDARD?0:PRIVATE_FLAGS))return bad("wrong private/standard ELF marker");
 if(require_static){
  uint64_t offset=le64(h+32);unsigned count=le16(h+56),stride=le16(h+54);
  if(stride!=56||!count||count>128||offset>(uint64_t)st.st_size||count*56ULL>(uint64_t)st.st_size-offset)return bad("invalid static ELF program headers");
  for(unsigned i=0;i<count;i++)if(pread(fd,ph,56,(off_t)(offset+i*56))!=56||le32(ph)==2||le32(ph)==3)return bad("native bootstrap helper is dynamic");
 }
 return 0;
}
static int entry_index(const char *name)
{
 for(unsigned i=0;i<MANIFEST_COUNT;i++)if(!strcmp(manifest[i].path,name))return (int)i;
 return -1;
}
static int checked_entry(int root,unsigned i,int keep)
{
 const struct manifest_entry *e=&manifest[i];char digest[65];struct stat st;int fd;
 if(e->role==ROLE_LINK){
  char leaf[NAME_MAX+1],target[PATH_MAX];int dir=parent_fd(root,e->path,leaf);ssize_t n;
  if(dir<0)return -1;
  n=readlinkat(dir,leaf,target,sizeof(target)-1);
  if(fstatat(dir,leaf,&st,AT_SYMLINK_NOFOLLOW)||!S_ISLNK(st.st_mode)||n<0||(size_t)n!=strlen(e->link)||memcmp(target,e->link,(size_t)n)||st.st_uid){close(dir);return bad("critical symlink changed");}
  close(dir);return 0;
 }
 fd=safe_open(root,e->path);if(fd<0)return -1;
 if(hash_fd(fd,digest,&st)||((st.st_mode&07777)!=e->mode)||
    (e->role!=ROLE_SELF&&((uint64_t)st.st_size!=e->size||strcmp(digest,e->digest)))||
    (e->role!=ROLE_DATA&&elf_info(fd,e->role,e->static_native))){close(fd);return bad("manifest hash/mode/ELF mismatch");}
 if(keep)return fd;
 close(fd);return 0;
}
static int inventory_walk(int dir,const char *prefix,unsigned depth)
{
 DIR *stream;struct dirent *d;int copy=dup(dir);
 if(depth>64||copy<0)return bad("inventory depth");
 stream=fdopendir(copy);if(!stream){close(copy);return bad("inventory directory");}
 while((d=readdir(stream))){
  struct stat st;char path[PATH_MAX];int fd;
  if(!strcmp(d->d_name,".")||!strcmp(d->d_name,".."))continue;
  if(++visited>65536||snprintf(path,sizeof(path),"%s%s%s",prefix,prefix[0]?"/":"",d->d_name)>=(int)sizeof(path))goto fail;
  if(fstatat(dir,d->d_name,&st,AT_SYMLINK_NOFOLLOW))goto fail;
  if(S_ISDIR(st.st_mode)){
   struct statfs fs;
   fd=openat(dir,d->d_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)goto fail;
   if(fstatfs(fd,&fs)){close(fd);goto fail;}
   if((unsigned long)fs.f_type==PROC_FS||(unsigned long)fs.f_type==SYS_FS){close(fd);continue;}
   if(inventory_walk(fd,path,depth+1)){close(fd);goto fail;}close(fd);
  }else if(S_ISREG(st.st_mode)){
   unsigned char h[64];int index;
   fd=openat(dir,d->d_name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)goto fail;
   ssize_t n=pread(fd,h,sizeof(h),0);close(fd);
   if(n<0)goto fail;
   if(n>=52&&!memcmp(h,"\177ELF",4)&&h[5]==1&&((h[4]==2&&le16(h+18)==183)||(h[4]==1&&le16(h+18)==40))&&(le16(h+16)==2||le16(h+16)==3)){
    index=entry_index(path);
    if(index<0||manifest[index].role<ROLE_PRIVATE||manifest[index].role>ROLE_SELF||seen[index])goto fail;
    seen[index]=1;
   }
  }
 }
 closedir(stream);return 0;
fail:
 closedir(stream);return bad("unexpected, duplicate or unreadable A64 inventory");
}
static int verify_root(int root)
{
 if(MANIFEST_COUNT>MAX_ENTRIES||protected_dir(root))return bad("manifest count/root");
 memset(seen,0,sizeof(seen));visited=0;
 for(unsigned i=0;i<MANIFEST_COUNT;i++)if(checked_entry(root,i,0)<0)return -1;
 if(inventory_walk(root,"",0))return -1;
 for(unsigned i=0;i<MANIFEST_COUNT;i++)if((manifest[i].role==ROLE_PRIVATE||manifest[i].role==ROLE_STANDARD||manifest[i].role==ROLE_ARM32||manifest[i].role==ROLE_SELF)&&!seen[i])return bad("missing ELF inventory entry");
 /* Self bytes are authenticated by the enclosing Image/CPIO/package admission.
  * These two copies must remain identical; embedding their own hash is circular.
  */
 char a[65],b[65];struct stat st;int first=safe_open(root,"init"),second=safe_open(root,BOOTSTRAP_PATH);
 if(first<0||second<0){if(first>=0)close(first);if(second>=0)close(second);return -1;}
 int failed=hash_fd(first,a,&st)||hash_fd(second,b,&st)||strcmp(a,b);close(first);close(second);
 return failed?bad("bootstrap self copies differ"):0;
}
static int number(const char *s,unsigned long *value)
{
 unsigned long n=0;size_t length=strlen(s);
 if(!length||length>9||(length>1&&s[0]=='0'))return -1;
 for(size_t i=0;i<length;i++){if(s[i]<'0'||s[i]>'9')return -1;n=n*10+(unsigned)(s[i]-'0');}*value=n;return 0;
}
static unsigned long clock_seconds(void)
{
#ifdef BE6L_BOOTSTRAP_HOST_TEST
 const char *test=getenv("BE6L_TEST_BOOTTIME");unsigned long simulated;
 if(test)return number(test,&simulated)?ULONG_MAX:simulated;
#endif
 struct timespec t;if(clock_gettime(CLOCK_BOOTTIME,&t)||t.tv_sec<0)return ULONG_MAX;return (unsigned long)t.tv_sec;
}
static void delay(unsigned seconds)
{
#ifdef BE6L_BOOTSTRAP_HOST_TEST
 if(getenv("BE6L_TEST_ACTIONS")){dprintf(1,"WAIT %u\n",seconds);return;}
#endif
 struct timespec t={.tv_sec=seconds};while(nanosleep(&t,&t)&&errno==EINTR){}
}
_Noreturn static void native_reboot(const char *why,unsigned wait)
{
 dprintf(2,"BE6L_NATIVE_FAILURE %s errno=%d\n",why,errno);
#ifdef BE6L_BOOTSTRAP_HOST_TEST
 if(getenv("BE6L_TEST_ACTIONS"))dprintf(1,"SYNC\n");else sync();
#else
 sync();
#endif
 delay(wait);
#ifndef BE6L_BOOTSTRAP_HOST_TEST
 reboot(RB_AUTOBOOT);
 for(;;)pause();
#else
 if(getenv("BE6L_TEST_ACTIONS"))dprintf(1,"REBOOT_SYSCALL\n");
 _exit(120);
#endif
}
_Noreturn static void emergency(const char *why){native_reboot(why,2);}
static int read_text(const char *path,char *out,size_t capacity)
{
 int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);ssize_t n;
 if(fd<0)return -1;n=read(fd,out,capacity-1);if(n<0||read(fd,out+capacity-1,1)!=0){close(fd);return -1;}
 close(fd);out[n]=0;return (int)n;
}
static int boot_uuid(char out[37])
{
 char b[64];if(read_text("/proc/sys/kernel/random/boot_id",b,sizeof(b))!=37||b[36]!='\n')return -1;
 for(unsigned i=0;i<36;i++)if((i==8||i==13||i==18||i==23)?b[i]!='-':!((b[i]>='0'&&b[i]<='9')||(b[i]>='a'&&b[i]<='f')))return -1;
 memcpy(out,b,36);out[36]=0;return 0;
}
static int mount_checked(const char *type,const char *path,unsigned long magic)
{
 struct statfs fs;
 if(mount(type,path,type,MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL)&&errno!=EBUSY)return -1;
 return statfs(path,&fs)||(unsigned long)fs.f_type!=magic ? -1:0;
}
static int platform(void)
{
 struct statfs fs;char compatible[1024],flags[64];int fd;
 if(geteuid()||statfs("/",&fs)||((unsigned long)fs.f_type!=ROOT_RAMFS&&(unsigned long)fs.f_type!=ROOT_TMPFS))return -1;
 int n=read_text("/sys/firmware/devicetree/base/compatible",compatible,sizeof(compatible));bool board=false;
 if(n<0)return -1;
 for(int p=0;p<n;){size_t length=strnlen(compatible+p,(size_t)(n-p));if(length==(size_t)(n-p))return -1;if(!strcmp(compatible+p,"tenda,be6l-pro"))board=true;p+=(int)length+1;}
 if(!board)return -1;
 fd=open(BMT_PROPERTY_PATH,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return -1;close(fd);
 for(unsigned i=0;i<10;i++){
  char path[128],*end;snprintf(path,sizeof(path),"/sys/class/mtd/mtd%u/flags",i);
  if(read_text(path,flags,sizeof(flags))<0)return -1;errno=0;unsigned long value=strtoul(flags,&end,0);
  if(errno||end==flags||(*end&&strcmp(end,"\n"))||value&0x400UL)return -1;
 }
 return 0;
}
static int write_all(int fd,const void *buffer,size_t size)
{
 const char *p=buffer;while(size){ssize_t n=write(fd,p,size);if(n<0){if(errno==EINTR)continue;return -1;}if(!n)return -1;p+=n;size-=(size_t)n;}return 0;
}
static int rule_readback(const char *entry,const char *interp)
{
 char expected[256],magic[105],mask[105];static const char digits[]="0123456789abcdef";
 for(unsigned i=0;i<52;i++){
  magic[i*2]=digits[rule_magic[i]>>4];magic[i*2+1]=digits[rule_magic[i]&15];
  mask[i*2]=digits[rule_mask[i]>>4];mask[i*2+1]=digits[rule_mask[i]&15];
 }
 magic[104]=mask[104]=0;
 int n=snprintf(expected,sizeof(expected),"enabled\ninterpreter %s\nflags: POFX\noffset 0\n",interp);
 if(n<0||n>=(int)sizeof(expected)||strncmp(entry,expected,(size_t)n))return -1;
 const char *tail=entry+n;
 n=snprintf(expected,sizeof(expected),"magic %s\nmask %s\n",magic,mask);
 return n<0||n>=(int)sizeof(expected)||strcmp(tail,expected)?-1:0;
}
static int register_binfmt(int root)
{
 int index=entry_index(EMULATOR_PATH);if(index<0)return bad("missing emulator role");
 int executable=checked_entry(root,(unsigned)index,1);if(executable<0)return -1;
 struct stat st;if(fstat(executable,&st)||st.st_mode&0222||st.st_nlink!=1){close(executable);return bad("emulator not read-only/single-linked");}
 DIR *dir=opendir("/proc/sys/fs/binfmt_misc");struct dirent *d;bool empty=true;
 if(!dir){close(executable);return -1;}
 while((d=readdir(dir)))if(strcmp(d->d_name,".")&&strcmp(d->d_name,"..")&&strcmp(d->d_name,"register")&&strcmp(d->d_name,"status"))empty=false;
 closedir(dir);if(!empty){close(executable);return bad("existing binfmt registry");}
 char status[32];if(read_text("/proc/sys/fs/binfmt_misc/status",status,sizeof(status))<0||strcmp(status,"enabled\n")){close(executable);return bad("binfmt disabled");}
 char rule[1024],magic[209],mask[209],interp[64];static const char digits[]="0123456789abcdef";
 for(unsigned i=0;i<52;i++)for(unsigned which=0;which<2;which++){
  char *out=which?mask:magic;unsigned char byte=which?rule_mask[i]:rule_magic[i];
  out[i*4]='\\';out[i*4+1]='x';out[i*4+2]=digits[byte>>4];out[i*4+3]=digits[byte&15];out[208]=0;
 }
 snprintf(interp,sizeof(interp),"/proc/self/fd/%d",executable);
 int n=snprintf(rule,sizeof(rule),":be6l-a53-main:M::%s:%s:%s:POFX\n",magic,mask,interp);
 int fd=open("/proc/sys/fs/binfmt_misc/register",O_WRONLY|O_CLOEXEC);
 if(fd<0||n<0||n>=(int)sizeof(rule)||write_all(fd,rule,(size_t)n)){if(fd>=0)close(fd);close(executable);return bad("POFX registration failed");}close(fd);
 char entry[2048];
 if(read_text("/proc/sys/fs/binfmt_misc/be6l-a53-main",entry,sizeof(entry))<0){close(executable);return bad("POFX readback failed");}
 if(rule_readback(entry,interp)){close(executable);return bad("POFX readback differs");}
 /* F opened /proc/self/fd while this verified inode was held. Subsequent
  * exec never resolves the now-closed descriptor pathname again.
  */
 close(executable);return 0;
}
struct timings {unsigned long grace,timeout,poll,force;int enabled;};
static int valid_timings(const struct timings *t)
{
 return t->grace>=60&&t->grace<=3600&&t->timeout>=60&&t->timeout<=3600&&t->poll>=1&&t->poll<=30&&t->force>=5&&t->force<=30&&t->poll<t->timeout;
}
static int recovery_config(struct timings *t)
{
 char data[4096],*line,*save;unsigned options=0;int root=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC),fd;
 *t=(struct timings){600,300,5,30,1};if(root<0)return -1;fd=safe_open(root,"etc/config/be6l-recovery");close(root);if(fd<0)return -1;
 struct stat st;if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_mode&0022){close(fd);return -1;}
 ssize_t n=read(fd,data,sizeof(data)-1);close(fd);if(n<0||n==(ssize_t)sizeof(data)-1)return -1;data[n]=0;
 for(line=strtok_r(data,"\n",&save);line;line=strtok_r(NULL,"\n",&save)){
  while(*line==' '||*line=='\t')line++;if(!*line||*line=='#')continue;
  char key[64],value[64],extra[64];
  if(!strncmp(line,"config ",7))continue;
  if(sscanf(line,"option %63s %63s %63s",key,value,extra)!=2)return -1;
  size_t length=strlen(value);if(length>1&&(value[0]=='\''||value[0]=='\"')){if(value[length-1]!=value[0])return -1;memmove(value,value+1,length-2);value[length-2]=0;}
  unsigned long integer;if(number(value,&integer))return -1;unsigned bit;
  if(!strcmp(key,"enabled")){bit=1;if(integer>1)return -1;t->enabled=(int)integer;}
  else if(!strcmp(key,"boot_grace")){bit=2;t->grace=integer;}
  else if(!strcmp(key,"disconnect_timeout")){bit=4;t->timeout=integer;}
  else if(!strcmp(key,"poll_interval")){bit=8;t->poll=integer;}
  else if(!strcmp(key,"force_after")){bit=16;t->force=integer;}
  else return -1;
  if(options&bit)return -1;options|=bit;
 }
 return valid_timings(t)?0:-1;
}
static int guard_state_open(int root,int create)
{
 struct stat st,parent;
 if(protected_dir(root)||fstat(root,&parent))return -1;
 if(create&&mkdirat(root,GUARD_NAME,0700))return -1; /* only fresh stage two creates it */
 int fd=openat(root,GUARD_NAME,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 if(fd<0||fstat(fd,&st)||st.st_uid||st.st_dev!=parent.st_dev||(st.st_mode&07777)!=0700){if(fd>=0)close(fd);return -1;}return fd;
}
static int guard_directory(void)
{
 int root=open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(root<0)return -1;
 int fd=guard_state_open(root,0);close(root);return fd;
}
static int private_file(int directory,const char *name,int flags)
{
 struct stat st;int fd=openat(directory,name,flags|O_NOFOLLOW|O_CLOEXEC,0600);
 if(fd<0)return -1;
 if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid||(st.st_mode&07777)!=0600||st.st_nlink!=1){close(fd);return -1;}return fd;
}
static int write_heartbeat(int directory,const char *boot,unsigned long now)
{
 char name[64],data[128];snprintf(name,sizeof(name),"heartbeat.%ld.tmp",(long)getpid());
 int fd=private_file(directory,name,O_WRONLY|O_CREAT|O_EXCL);if(fd<0)return -1;
 int n=snprintf(data,sizeof(data),"%s %lu\n",boot,now);int result=write_all(fd,data,(size_t)n);close(fd);
 if(result||renameat(directory,name,directory,"heartbeat")){unlinkat(directory,name,0);return -1;}return 0;
}
static long heartbeat_stamp(int directory,const char *boot,unsigned long now)
{
 int fd=private_file(directory,"heartbeat",O_RDONLY);if(fd<0)return -1;
 char data[128],id[64],stamp[64],extra[2];ssize_t n=read(fd,data,sizeof(data)-1);close(fd);if(n<=0||n==(ssize_t)sizeof(data)-1)return -1;data[n]=0;
 unsigned long value;if(sscanf(data,"%63s %63s %1s",id,stamp,extra)!=2||strcmp(id,boot)||number(stamp,&value)||value>now)return -1;return (long)value;
}
static unsigned long deadline(unsigned long grace,unsigned long timeout,long last)
{
 unsigned long end=grace;if(last>=0&&(unsigned long)last+timeout>end)end=(unsigned long)last+timeout;return end;
}
static int marked(int directory,const char *name)
{
 struct stat st;return !fstatat(directory,name,&st,AT_SYMLINK_NOFOLLOW)&&st.st_uid==0&&
  ((S_ISREG(st.st_mode)&&!(st.st_mode&0022))||S_ISDIR(st.st_mode));
}
static int guard_identity(int root,int directory,int lock)
{
 struct stat held,named,held_lock,named_lock;
 return fstat(directory,&held)||fstatat(root,GUARD_NAME,&named,AT_SYMLINK_NOFOLLOW)||
  !S_ISDIR(named.st_mode)||named.st_uid||(named.st_mode&07777)!=0700||held.st_dev!=named.st_dev||held.st_ino!=named.st_ino||
  fstat(lock,&held_lock)||fstatat(directory,"native-watch.lock",&named_lock,AT_SYMLINK_NOFOLLOW)||
  !S_ISREG(named_lock.st_mode)||named_lock.st_uid||(named_lock.st_mode&07777)!=0600||named_lock.st_nlink!=1||
  held_lock.st_dev!=named_lock.st_dev||held_lock.st_ino!=named_lock.st_ino ? -1:0;
}
static int pulse_lock(int directory)
{
 int fd=private_file(directory,"pulse.lock",O_RDWR|O_CREAT);
 if(fd<0)return -1;
 if(flock(fd,LOCK_EX|LOCK_NB)){int saved=errno;close(fd);errno=saved;return -1;}return fd;
}
static int guard_loop(int ready_fd)
{
 char boot[37];int root,directory,lock;struct timings t;long last=-1;
 if(platform()||boot_uuid(boot)||recovery_config(&t))return -1;
 root=open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(root<0)return -1;
 directory=guard_state_open(root,ready_fd>=0);if(directory<0)return -1;
 lock=private_file(directory,"native-watch.lock",O_RDWR|O_CREAT);if(lock<0)return -1;
 signal(SIGTERM,SIG_IGN);signal(SIGINT,SIG_IGN);signal(SIGHUP,SIG_IGN);
 for(;;){
  /* /tmp and /run are remounted by procd. This lease lives on the final
   * root instead; replacing its directory/lock fails closed, never migrates
   * a live timer onto a second independent inode. */
  if(guard_identity(root,directory,lock))return -1;
  if(flock(lock,LOCK_EX|LOCK_NB)){if(errno!=EWOULDBLOCK&&errno!=EAGAIN)return -1;delay(1);continue;}
  if(ready_fd>=0){if(write_all(ready_fd,"R",1))return -1;close(ready_fd);ready_fd=-1;}
  if(recovery_config(&t))return -1;
  unsigned long now=clock_seconds();if(now==ULONG_MAX||now>999999999)return -1;
  long stamp=heartbeat_stamp(directory,boot,now);if(stamp>last)last=stamp;
  if(t.enabled&&!marked(directory,"disarmed")&&!marked(directory,"fired")&&now>=deadline(t.grace,t.timeout,last)){
   int pulse=pulse_lock(directory);
   if(pulse<0){
    if((errno==EWOULDBLOCK||errno==EAGAIN)&&now<deadline(t.grace,t.timeout,last)+t.force){delay(1);continue;}
    return -1;
   }
   now=clock_seconds();stamp=heartbeat_stamp(directory,boot,now);if(stamp>last)last=stamp;
   if(now>=deadline(t.grace,t.timeout,last)&&!marked(directory,"disarmed")&&!marked(directory,"fired")){
    if(guard_identity(root,directory,lock)){close(pulse);return -1;}
    if(mkdirat(directory,"fired",0700)){close(pulse);return -1;}
    close(pulse);
    dprintf(2,"BE6L_NATIVE_GUARD_EXPIRED %s %lu\n",boot,now);
    /* procd STATE_HALT sends SIGKILL to all userspace after SIGTERM. Do
     * not start that path and thereby destroy this forced fallback. This
     * RAM-only emergency waits force_after then calls the native syscall.
     * Attached-NPU driver quiescence/restart success is NOT established. */
    native_reboot("native heartbeat expiry",(unsigned)t.force);
   }
   close(pulse);
  }
  delay((unsigned)t.poll);
 }
}
static int guard_command(int argc,char **argv)
{
 char boot[37];int directory;unsigned long now;
 if(platform()||boot_uuid(boot)||argc<2)return 1;
 if(!strcmp(argv[1],"run")){
  struct timings configured,requested={.enabled=1};
  if(argc!=6||number(argv[2],&requested.grace)||number(argv[3],&requested.timeout)||number(argv[4],&requested.poll)||number(argv[5],&requested.force)||!valid_timings(&requested)||recovery_config(&configured)||requested.grace!=configured.grace||requested.timeout!=configured.timeout||requested.poll!=configured.poll||requested.force!=configured.force)return 1;
  if(guard_loop(-1))emergency("native guard failed");return 1;
 }
 if(argc!=2||(directory=guard_directory())<0)return 1;
 int pulse=-1;
 if(strcmp(argv[1],"status")){pulse=pulse_lock(directory);if(pulse<0){close(directory);return 1;}}
 int result=0;
 if(!strcmp(argv[1],"heartbeat")||!strcmp(argv[1],"arm")){
  const char *ssh=getenv("SSH_CONNECTION");now=clock_seconds();
  if(!ssh||!*ssh||strlen(ssh)>256||strchr(ssh,'\n')||now>999999999||marked(directory,"fired")||
     (!strcmp(argv[1],"heartbeat")&&marked(directory,"disarmed"))||write_heartbeat(directory,boot,now))result=1;
  else{if(!strcmp(argv[1],"arm"))unlinkat(directory,"disarmed",0);printf("BE6L_HEARTBEAT %s %lu\n",boot,now);}
 }else if(!strcmp(argv[1],"disarm")){
  int fd=private_file(directory,"disarmed",O_WRONLY|O_CREAT|O_TRUNC);if(fd<0)result=1;else close(fd);
 }else if(!strcmp(argv[1],"status")){
  printf("boot_id=%s\nstate=%s\n",boot,marked(directory,"fired")?"fired":marked(directory,"disarmed")?"disarmed":"armed");
 }else result=1;
 if(pulse>=0)close(pulse);close(directory);return result;
}
static int native_shell(int argc,char **argv)
{
 int root=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC),index=entry_index(NATIVE_BUSYBOX_PATH);
 if(geteuid()||root<0||index<0)return 126;
 int fd=checked_entry(root,(unsigned)index,1);close(root);if(fd<0)return 126;
 char **args=calloc((size_t)argc+1,sizeof(char*));if(!args){close(fd);return 126;}args[0]="sh";
 for(int i=1;i<argc;i++)args[i]=argv[i];
 char ssh[280];char *environment[]={"PATH=/usr/sbin:/usr/bin:/sbin:/bin","HOME=/root","USER=root","LOGNAME=root","SHELL=/usr/libexec/be6l/native-recovery-shell",NULL,NULL};
 const char *connection=getenv("SSH_CONNECTION");if(connection&&*connection&&strlen(connection)<=256&&!strchr(connection,'\n')){snprintf(ssh,sizeof(ssh),"SSH_CONNECTION=%s",connection);environment[5]=ssh;}
 syscall(SYS_execveat,fd,"",args,environment,AT_EMPTY_PATH);close(fd);free(args);return 126;
}
static int phase_zero_watch(int input)
{
 signal(SIGTERM,SIG_IGN);signal(SIGHUP,SIG_IGN);signal(SIGINT,SIG_IGN);
 for(;;){
  struct pollfd p={.fd=input,.events=POLLIN};int result=poll(&p,1,1000);
  if(result<0&&errno!=EINTR)return -1;
  if(result>0){char c;if(read(input,&c,1)==1&&c=='H')return 0;return -1;}
  unsigned long now=clock_seconds();if(now==ULONG_MAX||now>=600)return -1;
 }
}
static int early_main(int argc,char **argv)
{
 if(getpid()!=1||geteuid())return 64;
 if(argc==2&&!strcmp(argv[1],"--early-failure"))emergency("native init root-copy failure");
 bool second=argc==2&&!strcmp(argv[1],"--post-switch-root");
 if(argc!=1&&!second)emergency("invalid bootstrap stage");
 struct statfs fs;if(statfs("/",&fs)||((unsigned long)fs.f_type!=ROOT_RAMFS&&(unsigned long)fs.f_type!=ROOT_TMPFS))emergency("not a RAM root");
 int root=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(root<0||verify_root(root))emergency(failure);
 if(!second){
  struct stat st;if(!fstatat(root,"new_root",&st,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)emergency("preexisting root-copy destination");
  if(!fstatat(root,GUARD_NAME,&st,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)emergency("old guard state before root copy");
  int pipefd[2];if(pipe2(pipefd,O_CLOEXEC))emergency("phase pipe");pid_t watcher=fork();if(watcher<0)emergency("phase watcher fork");
  if(!watcher){close(pipefd[1]);if(phase_zero_watch(pipefd[0]))emergency("early stage timeout or lost handoff");_exit(0);}
  close(pipefd[0]);if(fcntl(pipefd[1],F_SETFD,0))emergency("phase descriptor");
  int index=entry_index(NATIVE_BUSYBOX_PATH),fd=index<0?-1:checked_entry(root,(unsigned)index,1);if(fd<0)emergency("native BusyBox trust");
  char ack[64],pid[64];snprintf(ack,sizeof(ack),"BE6L_EARLY_ACK_FD=%d",pipefd[1]);snprintf(pid,sizeof(pid),"BE6L_EARLY_WATCH_PID=%ld",(long)watcher);
  char *args[]={"sh","/" NATIVE_INIT_PATH,NULL};char *environment[]={"PATH=/usr/sbin:/usr/bin:/sbin:/bin","INITRAMFS=1",ack,pid,NULL};
  close(root);syscall(SYS_execveat,fd,"",args,environment,AT_EMPTY_PATH);emergency("native init exec");
 }
 struct stat old_state;
 if(!fstatat(root,GUARD_NAME,&old_state,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)emergency("copied guard state on final root");
 if(mount_checked("proc","/proc",PROC_FS)||mount_checked("sysfs","/sys",SYS_FS)||platform()||mount_checked("binfmt_misc","/proc/sys/fs/binfmt_misc",BINFMT_FS)||register_binfmt(root))emergency(failure);
 int ready[2];if(pipe2(ready,O_CLOEXEC))emergency("native guard readiness");pid_t guard=fork();if(guard<0)emergency("native guard fork");
 if(!guard){
  close(root);close(ready[0]);unsigned long inherited;const char *ack=getenv("BE6L_EARLY_ACK_FD");
  if(!ack||number(ack,&inherited)||inherited<3||inherited>1024)emergency("guard inherited descriptor");
  close((int)inherited);if(guard_loop(ready[1]))emergency("native guard unavailable");_exit(1);
 }
 close(ready[1]);struct pollfd wait={.fd=ready[0],.events=POLLIN};char token;
 if(poll(&wait,1,5000)!=1||read(ready[0],&token,1)!=1||token!='R')emergency("native guard not ready");close(ready[0]);
 unsigned long descriptor,watcher;const char *ack=getenv("BE6L_EARLY_ACK_FD"),*pid=getenv("BE6L_EARLY_WATCH_PID");
 if(!ack||!pid||number(ack,&descriptor)||descriptor<3||descriptor>1024||number(pid,&watcher)||watcher<2||watcher>INT_MAX||write_all((int)descriptor,"H",1))emergency("phase handoff authentication");
 close((int)descriptor);int status;if(waitpid((pid_t)watcher,&status,0)!=(pid_t)watcher||!WIFEXITED(status)||WEXITSTATUS(status))emergency("phase watcher did not exit");
 close(root);
 /* First normal A64 shell is only reached after final-root trust, F pin and
  * native guard readiness. The original root-copy work is already complete.
  */
 char *args[]={"sh","-c","exec /sbin/init",NULL};char *environment[]={"PATH=/usr/sbin:/usr/bin:/sbin:/bin","INITRAMFS=1",NULL};
 execve("/bin/sh",args,environment);emergency("normal init handoff");return 1;
}

#ifdef BE6L_BOOTSTRAP_HOST_TEST
int main(int argc,char **argv)
{
 if(argc==3&&!strcmp(argv[1],"--verify-root")){int fd=open(argv[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);int result=fd<0?-1:verify_root(fd);if(fd>=0)close(fd);printf("VERIFY %s %s\n",result?"FAIL":"PASS",result?failure:MANIFEST_ID);return result?1:0;}
 if(argc==3&&!strcmp(argv[1],"--hash")){int fd=open(argv[2],O_RDONLY|O_NOFOLLOW);struct stat st;char h[65];if(fd<0||hash_fd(fd,h,&st))return 1;puts(h);close(fd);return 0;}
 if(argc==5&&!strcmp(argv[1],"--deadline")){unsigned long grace,timeout,last;if(number(argv[2],&grace)||number(argv[3],&timeout))return 1;long value=-1;if(strcmp(argv[4],"-1")){if(number(argv[4],&last))return 1;value=(long)last;}printf("%lu\n",deadline(grace,timeout,value));return 0;}
 if(argc==4&&!strcmp(argv[1],"--rule-readback")){char data[2048];if(read_text(argv[2],data,sizeof(data))<0)return 1;return rule_readback(data,argv[3])?1:0;}
 if(argc==5&&!strcmp(argv[1],"--heartbeat-parse")){unsigned long now;if(number(argv[4],&now))return 1;int fd=open(argv[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(fd<0)return 1;long stamp=heartbeat_stamp(fd,argv[3],now);close(fd);if(stamp<0)return 1;printf("%ld\n",stamp);return 0;}
 if(argc==3&&!strcmp(argv[1],"--phase-handshake")){int p[2];if(pipe(p))return 1;if(!strcmp(argv[2],"H"))write_all(p[1],"H",1);else if(!strcmp(argv[2],"bad"))write_all(p[1],"X",1);if(strcmp(argv[2],"timeout"))close(p[1]);int result=phase_zero_watch(p[0]);close(p[0]);if(!strcmp(argv[2],"timeout"))close(p[1]);return result?1:0;}
 if(argc==3&&!strcmp(argv[1],"--expiry-actions")){unsigned long force;if(number(argv[2],&force)||force<5||force>30||!getenv("BE6L_TEST_ACTIONS"))return 1;native_reboot("host expiry action sequence",(unsigned)force);}
 if(argc==4&&!strcmp(argv[1],"--lease-check")){
  int root=open(argv[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW),directory,lock,other;
  if(root<0||(directory=guard_state_open(root,1))<0||(lock=private_file(directory,"native-watch.lock",O_RDWR|O_CREAT))<0||flock(lock,LOCK_EX|LOCK_NB))return 1;
  other=private_file(directory,"native-watch.lock",O_RDWR|O_CREAT);
  if(other<0||flock(other,LOCK_EX|LOCK_NB)==0||(errno!=EWOULDBLOCK&&errno!=EAGAIN)||guard_identity(root,directory,lock))return 1;close(other);
  /* WSL may deny renaming an open directory. Supply a second named inode
   * to the actual identity predicate; live replacement still needs a DUT
   * RAMFS fixture and is not claimed by this host check. */
  if(!strcmp(argv[3],"different-directory-inode")){if(mkdirat(root,"alternate",0700))return 1;int alternate=openat(root,"alternate",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(alternate<0||mkdirat(alternate,GUARD_NAME,0700))return 1;return guard_identity(alternate,directory,lock)?0:1;}
  if(!strcmp(argv[3],"different-lock-inode")){other=private_file(directory,"other-watch.lock",O_RDWR|O_CREAT);if(other<0)return 1;return guard_identity(root,directory,other)?0:1;}
  if(!strcmp(argv[3],"preexisting-state"))return guard_state_open(root,1)<0?0:1;
  if(strcmp(argv[3],"same-state"))return 1;return guard_identity(root,directory,lock)?1:0;
 }
 return 64;
}
#else
int main(int argc,char **argv)
{
 const char *name=strrchr(argv[0],'/');name=name?name+1:argv[0];
 if(!strcmp(name,"be6l-recovery-guard"))return guard_command(argc,argv);
 if(!strcmp(name,"native-recovery-shell"))return native_shell(argc,argv);
 return early_main(argc,argv);
}
#endif
