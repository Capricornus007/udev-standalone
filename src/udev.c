#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/sysmacros.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>

/* pidfile: conventional udev location. On the target systemd-free system there
   is nothing else to collide with, and keeping the standard path maximizes
   drop-in compatibility with scripts/tools that expect udev's runtime layout. */
#define UDEV_PIDFILE "/run/udev.pid"

/* rundir: where the daemon persists its runtime state (device DB + queue).
   This is the same env var libudev-standalone reads (UDEV_RUNDIR, default
   /run/udev), so both projects share one test/fake-root surface for an
   end-to-end daemon→libudev test without root or a real kernel netlink. */
static char g_rundir[256];
static const char *rundir(void){ return g_rundir[0] ? g_rundir : "/run/udev"; }

/* ===================== uevent ===================== */
#define UE_MAX_ENV 96
#define UE_ENV_LEN 160
typedef struct {
    char action[32];
    char devpath[320];
    char subsys[64];
    char devname[128];
    int  major, minor;
    char tags[16][64];
    int  ntags;
    int  nenv;
    char env[UE_MAX_ENV][UE_ENV_LEN];
} uevent_t;

static const char *ue_getenv(uevent_t *ue, const char *key) {
    size_t kl = strlen(key);
    for (int i = 0; i < ue->nenv; i++)
        if (strncmp(ue->env[i], key, kl) == 0 && ue->env[i][kl] == '=')
            return ue->env[i] + kl + 1;
    return NULL;
}

/* read a sysfs attribute relative to the device: /sys<devpath>/<attr> */
static const char *read_sysattr(uevent_t *ue, const char *attr, char *out, size_t sz) {
    char p[512]; snprintf(p,sizeof p,"/sys%s/%s",ue->devpath,attr);
    FILE *f=fopen(p,"r"); if(!f) return NULL;
    size_t n=fread(out,1,sz-1,f); if(n>0 && out[n-1]=='\n') n--; out[n]=0; fclose(f);
    return out[0]? out : NULL;
}

/* buf is a sequence of NUL-separated strings:
   "action@devpath" then "KEY=VALUE" pairs (kernel uevent format). */
static int ue_parse(const char *buf, ssize_t len, uevent_t *ue) {
    memset(ue, 0, sizeof(*ue));
    const char *p = buf, *end = buf + len;
    const char *nl = memchr(p, '\0', end - p);
    if (!nl) return -1;
    size_t fl = nl - p;
    const char *at = memchr(p, '@', fl);
    if (at) {
        size_t al = at - p; if (al > sizeof(ue->action)-1) al = sizeof(ue->action)-1;
        memcpy(ue->action, p, al); ue->action[al] = 0;
        size_t dl = fl - al - 1; if (dl > sizeof(ue->devpath)-1) dl = sizeof(ue->devpath)-1;
        memcpy(ue->devpath, at+1, dl); ue->devpath[dl] = 0;
    } else {
        strncpy(ue->action, p, sizeof(ue->action)-1);
    }
    p = nl + 1;
    while (p < end && *p) {
        const char *nnl = memchr(p, '\0', end - p);
        if (!nnl) break;
        size_t l = nnl - p;
        if (ue->nenv < UE_MAX_ENV && l < UE_ENV_LEN) {
            memcpy(ue->env[ue->nenv], p, l); ue->env[ue->nenv][l] = 0;
            ue->nenv++;
        }
        p = nnl + 1;
    }
    const char *s;
    if ((s = ue_getenv(ue,"SUBSYSTEM"))) strncpy(ue->subsys, s, sizeof(ue->subsys)-1);
    if ((s = ue_getenv(ue,"DEVNAME")))   strncpy(ue->devname, s, sizeof(ue->devname)-1);
    if ((s = ue_getenv(ue,"MAJOR"))) ue->major = atoi(s);
    if ((s = ue_getenv(ue,"MINOR"))) ue->minor = atoi(s);
    return 0;
}

/* ===================== rules ===================== */
#define RL_MAX_MATCH 16
#define RL_MAX_ASG   16
typedef struct {
    int  nmatch;
    char m_key[RL_MAX_MATCH][40];
    char m_op [RL_MAX_MATCH][3];
    char m_val[RL_MAX_MATCH][160];
    int  nasg;
    char a_key[RL_MAX_ASG][40];
    char a_op [RL_MAX_ASG][3];
    char a_val[RL_MAX_ASG][160];
    /* action extensions (milestone 6) */
    char program[160];               /* PROGRAM="..."  -> capture stdout into RESULT */
    char run[RL_MAX_ASG][160];       /* RUN+="..."     -> execute on event */
    int  nrun;
    char imp_kind[RL_MAX_ASG][16];   /* IMPORT{program|file} */
    char imp_val[RL_MAX_ASG][160];
    int  nimp;
    char label[40];                  /* LABEL="x" */
    char goto_l[40];                 /* GOTO="x" */
} rule_t;

typedef struct { rule_t *r; int n, cap; } ruleset_t;
static ruleset_t RS;
static char g_rulesdir[512] = "rules";

/* split "KEY OP VALUE" into pieces; OP is one of == != := += = */
static int split_tok(const char *tok, char *key, char *op, char *val) {
    static const char *ops[] = {"==","!=",":=","+=","=",NULL};
    const char *best=NULL, *bop=NULL;
    for (int i=0; ops[i]; i++) {
        const char *f = strstr(tok, ops[i]);
        if (f && (!best || f < best)) { best=f; bop=ops[i]; }
    }
    if (!best) return -1;
    size_t kl = best - tok; if (kl>=40) kl=39; memcpy(key,tok,kl); key[kl]=0;
    snprintf(op,3,"%s",bop);
    const char *v = best + strlen(bop);
    size_t vl = strlen(v);
    if (vl>=2 && v[0]=='"' && v[vl-1]=='"') { v++; vl-=2; }
    if (vl>=160) vl=159;
    memcpy(val, v, vl);
    val[vl] = 0;
    return 0;
}

static void rules_add(rule_t *r) {
    if (RS.n >= RS.cap) { RS.cap = RS.cap? RS.cap*2 : 16; RS.r = realloc(RS.r, RS.cap*sizeof(rule_t)); }
    RS.r[RS.n++] = *r;
}

/* tokenize a rule line into NUL-terminated tokens, respecting double quotes so
   values containing spaces/commas (e.g. RUN+="/bin/echo hi there") stay whole.
   quote characters are stripped from the returned token. */
static char *next_tok(char *p, char **save) {
    while (*p==' '||*p=='\t'||*p==',') p++;
    if (*p==0) return NULL;
    char *out = p, *w = p; int inq = 0;
    for (char *q = p; *q; q++) {
        if (*q=='"') { inq = !inq; continue; }
        if (!inq && (*q==' '||*q=='\t'||*q==',')) { *w=0; *save=q+1; return out; }
        *w++ = *q;
    }
    *w = 0; *save = w;
    return out;
}

static void load_file(const char *path);
static int cmp_str(const void *a, const void *b) {
    return strcmp(*(const char * const *)a, *(const char * const *)b);
}
static void load_dir(const char *dir) {
    DIR *d = opendir(dir); if (!d) return;
    char *names[256]; int n=0;
    struct dirent *e;
    while ((e = readdir(d)) && n<256) {
        size_t L = strlen(e->d_name);
        if (L>6 && !strcmp(e->d_name+L-6, ".rules"))
            names[n++] = strdup(e->d_name);
    }
    closedir(d);
    qsort(names, n, sizeof(char*), cmp_str);
    char path[1024];
    for (int i=0;i<n;i++) {
        snprintf(path,sizeof path,"%s/%s",dir,names[i]);
        load_file(path);
        free(names[i]);
    }
}
static void load_file(const char *path) {
    FILE *f = fopen(path,"r"); if (!f) return;
    char line[1024];
    while (fgets(line,sizeof line,f)) {
        size_t L = strlen(line);
        while (L && (line[L-1]=='\n' || line[L-1]=='\r')) line[--L]=0;
        char *s = line; while (*s==' '||*s=='\t') s++;
        if (*s==0 || *s=='#') continue;
        rule_t cur; memset(&cur,0,sizeof cur);
        char *p = s, *tok;
        while ((tok = next_tok(p,&p)) != NULL) {
            char key[40],op[3],val[160];
            if (split_tok(tok,key,op,val)==0) {
                if (!strcmp(op,"==") || !strcmp(op,"!=")) {
                    if (cur.nmatch<RL_MAX_MATCH){
                        snprintf(cur.m_key[cur.nmatch],40,"%s",key);
                        snprintf(cur.m_op[cur.nmatch],3,"%s",op);
                        snprintf(cur.m_val[cur.nmatch],160,"%s",val);
                        cur.nmatch++;
                    }
                } else {
                    if (!strcmp(key,"MODE")||!strcmp(key,"OWNER")||!strcmp(key,"GROUP")
                     || !strcmp(key,"SYMLINK")||!strcmp(key,"TAG")) {
                        if (cur.nasg<RL_MAX_ASG){
                            snprintf(cur.a_key[cur.nasg],40,"%s",key);
                            snprintf(cur.a_op[cur.nasg],3,"%s",op);
                            snprintf(cur.a_val[cur.nasg],160,"%s",val);
                            cur.nasg++;
                        }
                    } else if (!strcmp(key,"PROGRAM")) {
                        snprintf(cur.program,sizeof cur.program,"%s",val);
                    } else if (!strcmp(key,"RUN")) {
                        if (cur.nrun<RL_MAX_ASG) snprintf(cur.run[cur.nrun++],160,"%s",val);
                    } else if (!strncmp(key,"IMPORT",6)) {
                        char kind[16]="";
                        const char *ob=strchr(key,'{'), *cb=strchr(key,'}');
                        if (ob && cb && cb>ob) { size_t kl=cb-ob-1; if(kl>=16)kl=15; memcpy(kind,ob+1,kl); kind[kl]=0; }
                        if (cur.nimp<RL_MAX_ASG){ snprintf(cur.imp_kind[cur.nimp],16,"%s",kind); snprintf(cur.imp_val[cur.nimp],160,"%s",val); cur.nimp++; }
                    } else if (!strcmp(key,"LABEL")) {
                        snprintf(cur.label,sizeof cur.label,"%.*s",(int)sizeof cur.label-1,val);
                    } else if (!strcmp(key,"GOTO")) {
                        snprintf(cur.goto_l,sizeof cur.goto_l,"%.*s",(int)sizeof cur.goto_l-1,val);
                    }
                    /* other keys (NAME/OPTIONS/...) ignored for now */
                }
            }
        }
        if (cur.nmatch || cur.nasg || cur.label[0] || cur.goto_l[0] || cur.nrun || cur.nimp || cur.program[0]) rules_add(&cur);
    }
    fclose(f);
}
static void rules_reload(const char *dir) {
    free(RS.r); RS.r=NULL; RS.n=0; RS.cap=0;
    load_dir(dir);
}

static const char *kernel_name(uevent_t *ue) {
    const char *b = strrchr(ue->devpath,'/'); return b? b+1 : ue->devpath;
}
static int tok_matches(const char *key, const char *op, const char *val, uevent_t *ue) {
    const char *actual=NULL;
    if (!strcmp(key,"SUBSYSTEM")) actual=ue->subsys;
    else if (!strcmp(key,"KERNEL")) actual=kernel_name(ue);
    else if (!strcmp(key,"ACTION")) actual=ue->action;
    else if (!strncmp(key,"ENV{",4)) {
        char ek[64]; snprintf(ek,sizeof ek,"%s",key+4);
        char *c=strchr(ek,'}'); if(c)*c=0;
        actual=ue_getenv(ue,ek);
    } else if (!strncmp(key,"ATTR{",5)) {
        char ak[128]; snprintf(ak,sizeof ak,"%s",key+5);
        char *c=strchr(ak,'}'); if(c)*c=0;
        static char buf[256];
        actual = read_sysattr(ue,ak,buf,sizeof buf);
    }
    if (!actual) actual="";
    int eq = !strcmp(actual,val);
    if (!strcmp(op,"==")) return eq;
    if (!strcmp(op,"!=")) return !eq;
    return 0;
}
static int rule_matches(rule_t *r, uevent_t *ue) {
    for (int i=0;i<r->nmatch;i++)
        if (!tok_matches(r->m_key[i],r->m_op[i],r->m_val[i],ue)) return 0;
    return 1;
}

/* set or replace an env entry (KEY=VALUE) in the uevent */
static void ue_setenv(uevent_t *ue, const char *key, const char *val) {
    size_t kl = strlen(key);
    for (int i=0;i<ue->nenv;i++)
        if (strncmp(ue->env[i],key,kl)==0 && ue->env[i][kl]=='='){
            snprintf(ue->env[i],UE_ENV_LEN,"%s=%s",key,val); return;
        }
    if (ue->nenv < UE_MAX_ENV) { snprintf(ue->env[ue->nenv],UE_ENV_LEN,"%s=%s",key,val); ue->nenv++; }
}

/* run a shell command, capture its stdout (capped) into out */
static int run_capture(const char *cmd, char *out, size_t outsz) {
    int p[2]; if (pipe(p)<0) return -1;
    pid_t pid = fork();
    if (pid<0){ close(p[0]); close(p[1]); return -1; }
    if (pid==0){
        close(p[0]); dup2(p[1],1); close(p[1]);
        execl("/bin/sh","sh","-c",cmd,(char*)NULL);
        _exit(127);
    }
    close(p[1]);
    size_t got=0;
    for (;;){
        if (got>=outsz-1) break;
        ssize_t r = read(p[0], out+got, outsz-1-got);
        if (r<=0) break;
        got += (size_t)r;
    }
    out[got]=0;
    while (got>0 && (out[got-1]=='\n'||out[got-1]=='\r')) out[--got]=0;
    close(p[0]);
    int st; waitpid(pid,&st,0);
    return 0;
}

/* fire-and-forget: run a shell command detached (used for RUN) */
static void run_exec(const char *cmd) {
    pid_t pid = fork();
    if (pid<0) return;
    if (pid==0){ setsid(); execl("/bin/sh","sh","-c",cmd,(char*)NULL); _exit(127); }
    /* parent does not wait; the detached child reaps itself */
}

/* find a rule index by its LABEL (for GOTO) */
static int find_label(const char *lbl) {
    for (int i=0;i<RS.n;i++)
        if (RS.r[i].label[0] && !strcmp(RS.r[i].label,lbl)) return i;
    return -1;
}

/* ===================== hwdb (unifies udev-hwdb / udevadm hwdb) =====================
   Clean-room TEXT-mode hwdb: parse the hwdb.d database files (modalias/property entries);
   match a query by glob, and import matched properties. We query the text files
   directly (no binary hwdb.bin index) — sufficient for a drop-in replacement of
   `udevadm hwdb --query`. */
typedef struct {
    char match[256];
    char prop[32][256];
    int  nprop;
} hwdb_entry_t;
static hwdb_entry_t *HW=NULL; static int HWn=0, HWcap=0, HWloaded=0;
static const char *g_hwdbdir=NULL;   /* optional override (testing / staging) */

/* glob matcher supporting '*' (systemd hwdb match keys use shell-style globs) */
static int glob_match(const char *pat, const char *str) {
    while (*pat && *str) {
        if (*pat=='*') {
            if (!*++pat) return 1;
            while (*str) { if (glob_match(pat,str)) return 1; str++; }
            return 0;
        }
        if (*pat != *str) return 0;
        pat++; str++;
    }
    while (*pat=='*') pat++;          /* trailing stars match anything */
    return *pat==0 && *str==0;
}

static void hwdb_load_file(const char *path) {
    FILE *f=fopen(path,"r"); if(!f) return;
    char line[1024]; hwdb_entry_t cur; memset(&cur,0,sizeof cur); int have=0;
    while (fgets(line,sizeof line,f)) {
        size_t L=strlen(line); while(L&&(line[L-1]=='\n'||line[L-1]=='\r')) line[--L]=0;
        char *raw=line; while(*raw==' '||*raw=='\t') raw++;
        if (*raw==0 || *raw=='#') continue;
        int indented = (raw != line);          /* property lines are indented */
        if (!indented && strchr(raw,'=')==NULL) {
            if (have) {
                if (HWn>=HWcap){ HWcap=HWcap?HWcap*2:16; HW=realloc(HW,HWcap*sizeof(hwdb_entry_t)); }
                HW[HWn++]=cur;
            }
            memset(&cur,0,sizeof cur); snprintf(cur.match,sizeof cur.match,"%s",raw); have=1;
        } else if (have && strchr(raw,'=')) {
            if (cur.nprop<32) snprintf(cur.prop[cur.nprop++],256,"%s",raw);
        }
    }
    if (have) {
        if (HWn>=HWcap){ HWcap=HWcap?HWcap*2:16; HW=realloc(HW,HWcap*sizeof(hwdb_entry_t)); }
        HW[HWn++]=cur;
    }
    fclose(f);
}
static void hwdb_load_dir(const char *dir) {
    DIR *d=opendir(dir); if(!d) return;
    char *names[256]; int n=0; struct dirent *e;
    while((e=readdir(d)) && n<256){ size_t L=strlen(e->d_name); if(L>5 && !strcmp(e->d_name+L-5,".hwdb")) names[n++]=strdup(e->d_name); }
    closedir(d);
    qsort(names,n,sizeof(char*),cmp_str);
    char path[512];
    for(int i=0;i<n;i++){ snprintf(path,sizeof path,"%s/%s",dir,names[i]); hwdb_load_file(path); free(names[i]); }
}
static void hwdb_load_all(void) {
    if (HWloaded) return;
    if (g_hwdbdir) hwdb_load_dir(g_hwdbdir);   /* --hwdbdir overrides the standard dirs (testing/staging) */
    else {
        hwdb_load_dir("/etc/udev/hwdb.d");
        hwdb_load_dir("/lib/udev/hwdb.d");
    }
    HWloaded=1;
}
static void cmd_hwdb_query(const char *modalias, int val_only) {
    hwdb_load_all();
    int found=0;
    for (int i=0;i<HWn;i++){
        if (glob_match(HW[i].match, modalias)) {
            found++;
            for (int p=0;p<HW[i].nprop;p++){
                if (val_only){ char *eq=strchr(HW[i].prop[p],'='); printf("%s\n", eq?eq+1:HW[i].prop[p]); }
                else printf("%s\n", HW[i].prop[p]);
            }
        }
    }
    if (!found) printf("(no hwdb match for %s)\n", modalias);
}

/* ===================== builtins =====================
   Clean-room reimplementations of a subset of udev's builtins. They compute
   device properties (the ID_* keys) from the uevent + sysfs, mirroring what
   systemd's net_id / path_id / blkid builtins emit. Invoked from rules via
   IMPORT{builtin}="name" (comma-separated list of names). */
static int g_test = 0;   /* declared early so builtins can print in --test mode */
static int g_apply = 0;  /* `udev apply`: process a uevent and WRITE the real DB/queue */

/* scan the devpath for a PCI device component ("0000:00:03.0" or "00:03.0") */
static int pci_ancestor(const char *dp, int *dom, int *bus, int *slot, int *fn) {
    *dom=*bus=*slot=*fn=0; int found=0;
    char tmp[384]; snprintf(tmp,sizeof tmp,"%s/",dp);
    char *save=NULL;
    for (char *tok=strtok_r(tmp,"/",&save); tok; tok=strtok_r(NULL,"/",&save)) {
        if (strchr(tok,':') && !strstr(tok,"pci")) {       /* skip "pci0000:00" host bridge */
            int d,b,s,f;
            if (sscanf(tok,"%x:%x:%x.%x",&d,&b,&s,&f)==4){ *dom=d;*bus=b;*slot=s;*fn=f;found=1; }
            else if (sscanf(tok,"%x:%x.%x",&b,&s,&f)==3){ *bus=b;*slot=s;*fn=f;found=1; }
        }
    }
    return found;
}

/* net_id: predictable network interface names.
   - ID_NET_NAME_PATH from PCI topology (enp<bus>s<slot>[f<func>]); multi-domain
     prefix as enp<bus>s<slot> is sufficient for the common single-domain case.
   - ID_NET_NAME_MAC from the device address (sysfs "address", or a MAC= env in
     --test). ONBOARD/SLOT names need firmware (BIOS/SMBIOS) data we don't read. */
static void builtin_net_id(uevent_t *ue) {
    int dom,bus,slot,fn;
    if (pci_ancestor(ue->devpath,&dom,&bus,&slot,&fn)) {
        char name[64];
        snprintf(name,sizeof name,"enp%ds%d",bus,slot);
        if (fn) { size_t l=strlen(name); snprintf(name+l,sizeof name-l,"f%d",fn); }
        ue_setenv(ue,"ID_NET_NAME_PATH",name);
        if (g_test) printf("       IMPORT(builtin net_id) ID_NET_NAME_PATH=%s\n",name);
    }
    const char *mac = ue_getenv(ue,"MAC");
    char buf[64];
    if (!mac) mac = read_sysattr(ue,"address",buf,sizeof buf);
    if (mac) {
        char norm[16]; int ni=0;
        for (const unsigned char *c=(const unsigned char*)mac; *c && ni<12; c++)
            if (isxdigit(*c)) norm[ni++]=tolower(*c);
        if (ni==12){ char nm[32]; snprintf(nm,sizeof nm,"enx%s",norm); ue_setenv(ue,"ID_NET_NAME_MAC",nm); if(g_test)printf("       IMPORT(builtin net_id) ID_NET_NAME_MAC=%s\n",nm); }
    }
}

/* path_id: persistent location-based device path (ID_PATH / ID_PATH_TAG).
   Builds a hyphen-joined topology chain: pci-<devaddr>[-usb-<func>:<bus>:<port>[:<cfg>.<if>]].
   PCI addressing is preserved verbatim (no re-formatting) so the path stays stable. */
static void builtin_path_id(uevent_t *ue) {
    char path[512]; path[0]=0;
    char tmp[384]; snprintf(tmp,sizeof tmp,"%s/",ue->devpath);
    char *save=NULL; int pci_func=-1;
    for (char *tok=strtok_r(tmp,"/",&save); tok; tok=strtok_r(NULL,"/",&save)) {
        int d,b,s,f;
        if (sscanf(tok,"%x:%x:%x.%x",&d,&b,&s,&f)==4) {
            snprintf(path,sizeof path,"pci-%s",tok);   /* keep original addressing */
            pci_func=f;
        } else if (!strncmp(tok,"usb",3) && tok[3]>='0' && tok[3]<='9') {
            int n; if (sscanf(tok,"usb%d",&n)==1) {
                size_t pl=strlen(path);
                if (pl<sizeof path-32) snprintf(path+pl,sizeof path-pl,"-usb-%d:%d",pci_func<0?0:pci_func,n);
            }
        } else if (tok[0]>='0' && tok[0]<='9' && strchr(tok,'-')) {
            char *colon=strchr(tok,':');
            if (colon) {            /* interface level N-M:C.D -> append only :C.D */
                size_t pl=strlen(path);
                if (pl<sizeof path-32) snprintf(path+pl,sizeof path-pl,":%s",colon+1);
            } else {                /* device level N-M -> append :M */
                char *dash=strchr(tok,'-'); char port[16]; int pi=0; const char *pp=dash+1;
                while (*pp && pi<15) port[pi++]=*pp++;
                port[pi]=0;
                size_t pl=strlen(path);
                if (pl<sizeof path-32) snprintf(path+pl,sizeof path-pl,":%s",port);
            }
        }
    }
    if (path[0]) {
        ue_setenv(ue,"ID_PATH",path);
        char tag[256]; int ti=0;
        for (int i=0; path[i] && ti<255; i++) tag[ti++] = (isalnum((unsigned char)path[i])||path[i]=='_')?path[i]:'_';
        tag[ti]=0;
        ue_setenv(ue,"ID_PATH_TAG",tag);
        if (g_test){ printf("       IMPORT(builtin path_id) ID_PATH=%s\n",path); printf("       IMPORT(builtin path_id) ID_PATH_TAG=%s\n",tag); }
    }
}

/* blkid: filesystem-type sniffer (clean-room, no libblkid).
   Detects common filesystems by magic bytes and, for ext2/3/4, also reads the
   UUID and label from the superblock. The device is taken from DEVNAME (an
   absolute path in --test, otherwise /dev/<name>). */
static void builtin_blkid(uevent_t *ue) {
    const char *dev = ue_getenv(ue,"DEVNAME");
    if (!dev) return;
    char path[512];
    if (dev[0]=='/') snprintf(path,sizeof path,"%s",dev);
    else snprintf(path,sizeof path,"/dev/%s",dev);
    FILE *f=fopen(path,"rb"); if(!f){ if(g_test)printf("       IMPORT(builtin blkid): cannot open %s\n",path); return; }
    unsigned char buf[0x10100]; size_t got=fread(buf,1,sizeof buf,f); fclose(f);
    if (got<2) return;
    if (got>0x439 && buf[0x438]==0x53 && buf[0x439]==0xEF) {       /* ext2/3/4 superblock (LE 0xEF53) */
        ue_setenv(ue,"ID_FS_TYPE","ext4");
        if (g_test) printf("       IMPORT(builtin blkid) ID_FS_TYPE=ext4\n");
        const unsigned char *u=buf+0x468;
        char uuid[40];
        snprintf(uuid,sizeof uuid,"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            u[0],u[1],u[2],u[3],u[4],u[5],u[6],u[7],u[8],u[9],u[10],u[11],u[12],u[13],u[14],u[15]);
        ue_setenv(ue,"ID_FS_UUID",uuid);
        if (g_test) printf("       IMPORT(builtin blkid) ID_FS_UUID=%s\n",uuid);
        char label[17]; memcpy(label,buf+0x478,16); label[16]=0;
        if (label[0]) { ue_setenv(ue,"ID_FS_LABEL",label); if(g_test)printf("       IMPORT(builtin blkid) ID_FS_LABEL=%s\n",label); }
        return;
    }
    if (got>0x56 && !memcmp(buf+0x52,"FAT32",5)) { ue_setenv(ue,"ID_FS_TYPE","vfat"); if(g_test)printf("       IMPORT(builtin blkid) ID_FS_TYPE=vfat\n"); return; }
    if (got>0x3b && !memcmp(buf+0x36,"FAT12",5)) { ue_setenv(ue,"ID_FS_TYPE","vfat"); if(g_test)printf("       IMPORT(builtin blkid) ID_FS_TYPE=vfat\n"); return; }
    if (got>0x3b && !memcmp(buf+0x36,"FAT16",5)) { ue_setenv(ue,"ID_FS_TYPE","vfat"); if(g_test)printf("       IMPORT(builtin blkid) ID_FS_TYPE=vfat\n"); return; }
    if (got>0x08 && !memcmp(buf+3,"NTFS",4))     { ue_setenv(ue,"ID_FS_TYPE","ntfs"); if(g_test)printf("       IMPORT(builtin blkid) ID_FS_TYPE=ntfs\n"); return; }
    if (got>4 && !memcmp(buf,"XFSB",4))          { ue_setenv(ue,"ID_FS_TYPE","xfs");  if(g_test)printf("       IMPORT(builtin blkid) ID_FS_TYPE=xfs\n");  return; }
    if (got>0x10048 && !memcmp(buf+0x10040,"_BHRfS_M",8)) { ue_setenv(ue,"ID_FS_TYPE","btrfs"); if(g_test)printf("       IMPORT(builtin blkid) ID_FS_TYPE=btrfs\n"); return; }
    if (got>0x2005 && (!memcmp(buf+0x1FFB,"SWAPSPACE2",10) || !memcmp(buf+0x1FFB,"SWAP-SPACE",10))) { ue_setenv(ue,"ID_FS_TYPE","swap"); if(g_test)printf("       IMPORT(builtin blkid) ID_FS_TYPE=swap\n"); return; }
    if (g_test) printf("       IMPORT(builtin blkid): no recognized filesystem on %s\n",path);
}

static void run_builtin(uevent_t *ue, const char *name) {
    if (!strcmp(name,"net_id")) builtin_net_id(ue);
    else if (!strcmp(name,"path_id")) builtin_path_id(ue);
    else if (!strcmp(name,"blkid")) builtin_blkid(ue);
}

/* ===================== actions ===================== */
static void apply_rule(rule_t *r, uevent_t *ue) {
    char mode[16]="", owner[64]="", group[64]="", linkname[160]="";
    ue->ntags = 0;
    for (int i=0;i<r->nasg;i++){
        if(!strcmp(r->a_key[i],"MODE"))  snprintf(mode,sizeof mode,"%s",r->a_val[i]);
        else if(!strcmp(r->a_key[i],"OWNER")) snprintf(owner,sizeof owner,"%s",r->a_val[i]);
        else if(!strcmp(r->a_key[i],"GROUP")) snprintf(group,sizeof group,"%s",r->a_val[i]);
        else if(!strcmp(r->a_key[i],"SYMLINK")) snprintf(linkname,sizeof linkname,"%s",r->a_val[i]);
        else if(!strcmp(r->a_key[i],"TAG")) { if(ue->ntags<16) snprintf(ue->tags[ue->ntags++],64,"%s",r->a_val[i]); }
    }
    /* PROGRAM: run and capture stdout into RESULT (visible to later rules via ENV{RESULT}) */
    if (r->program[0]) {
        char res[1024];
        if (run_capture(r->program,res,sizeof res)==0 && res[0]) {
            ue_setenv(ue,"RESULT",res);
            if (g_test) printf("       PROGRAM '%s' => RESULT=%s\n", r->program, res);
        }
    }
    /* IMPORT{file|program|hwdb}: parse KEY=VALUE lines into the uevent env */
    for (int k=0;k<r->nimp;k++){
        if (!strcmp(r->imp_kind[k],"file")) {
            FILE *f=fopen(r->imp_val[k],"r");
            if (f){ char ln[512]; while(fgets(ln,sizeof ln,f)){ size_t l=strlen(ln); while(l&&(ln[l-1]=='\n'||ln[l-1]=='\r'))ln[--l]=0; char *eq=strchr(ln,'='); if(eq&&l){*eq=0; ue_setenv(ue,ln,eq+1); if(g_test)printf("       IMPORT %s=%s\n",ln,eq+1);} } fclose(f); }
            else if (g_test) printf("       IMPORT file '%s' open failed\n", r->imp_val[k]);
        } else if (!strcmp(r->imp_kind[k],"hwdb")) {
            const char *m = ue_getenv(ue,"MODALIAS");
            if (m) {
                for (int h=0;h<HWn;h++){
                    if (glob_match(HW[h].match,m)){
                        for (int p=0;p<HW[h].nprop;p++){
                            char pk[200]; snprintf(pk,sizeof pk,"%s",HW[h].prop[p]); char *eq=strchr(pk,'=');
                            if (eq && *eq){ *eq=0; ue_setenv(ue,pk,eq+1); if(g_test)printf("       IMPORT(hwdb) %s=%s\n",pk,eq+1); }
                        }
                    }
                }
            } else if (g_test) printf("       IMPORT(hwdb): no MODALIAS in uevent\n");
        } else if (!strcmp(r->imp_kind[k],"builtin")) {
            char names[160]; snprintf(names,sizeof names,"%s",r->imp_val[k]);
            char *save=NULL;
            for (char *b=strtok_r(names,",",&save); b; b=strtok_r(NULL,",",&save)) run_builtin(ue,b);
        } else {
            char buf[1024];
            if (run_capture(r->imp_val[k],buf,sizeof buf)==0 && buf[0]){
                char *line=strtok(buf,"\n");
                while(line){ char *eq=strchr(line,'='); if(eq){*eq=0; ue_setenv(ue,line,eq+1); if(g_test)printf("       IMPORT %s=%s\n",line,eq+1);} line=strtok(NULL,"\n"); }
            }
        }
    }
    if(!ue->devname[0]) return;
    char path[512];
    /* apply mode builds a self-contained fake /dev tree under UDEV_RUNDIR so the
       result is fully inspectable without touching the real /dev (and without root);
       the live daemon always creates the real /dev node. */
    if (g_apply) snprintf(path,sizeof path,"%s/dev/%s", rundir(), ue->devname);
    else         snprintf(path,sizeof path,"/dev/%s", ue->devname);
    const char *km = mode[0]? mode : ue_getenv(ue,"MODE");
    unsigned perm = km? (unsigned)strtol(km,NULL,8) : 0600;
    if (!g_apply) {
        printf("[udev] %s action=%s node=%s mode=%o owner=%s group=%s\n",
            g_test?"TEST":"APPLY", ue->action, path, perm,
            owner[0]?owner:"(kernel)", group[0]?group:"(kernel)");
        if (linkname[0]) printf("       symlink -> /dev/%s\n", linkname);
        if (ue->ntags) { printf("       tags:"); for(int t=0;t<ue->ntags;t++) printf(" %s",ue->tags[t]); printf("\n"); }
    }
    /* RUN: execute programs on the event (test mode only prints; apply mode skips) */
    for (int k=0;k<r->nrun;k++){
        if (g_test) printf("       [would RUN] %s\n", r->run[k]);
        else if (!g_apply) run_exec(r->run[k]);
    }
    if (g_test) return;   /* --test: print only, never create nodes */
    /* create the node (apply mode: under rundir/dev; live daemon: /dev) */
    char *slash=strrchr(path,'/');
    if (slash && slash!=path){ *slash=0; mkdir(path,0755); *slash='/'; }
    if (mknod(path, S_IFCHR|perm, makedev(ue->major,ue->minor))<0) {
        if (g_apply) {
            /* not root in the fake-root test: leave a placeholder file so the node
               path exists for stat-based clients / inspection */
            FILE *pf=fopen(path,"w"); if(pf) fclose(pf);
        } else
            printf("       mknod failed: %s\n", strerror(errno));
    } else if (!g_apply) {
        uid_t u=0; gid_t g=0;
        if(owner[0]){ struct passwd *pw=getpwnam(owner); if(pw) u=pw->pw_uid; }
        if(group[0]){ struct group *gr=getgrnam(group); if(gr) g=gr->gr_gid; }
        chown(path,u,g);
    }
    if (linkname[0]) {
        char sp[512];
        if (g_apply) snprintf(sp,sizeof sp,"%s/dev/%s", rundir(), linkname);
        else         snprintf(sp,sizeof sp,"/dev/%s", linkname);
        char *ss=strrchr(sp,'/'); if(ss&&ss!=sp){*ss=0; mkdir(sp,0755); *ss='/';}
        symlink(path, sp);
    }
}

/* ===================== device DB ===================== */
static void db_write(uevent_t *ue) {
    if (g_test) return;
    if (ue->major==0 && ue->minor==0) return;
    char path[512];
    snprintf(path, sizeof path, "%s/data/c%d:%d", rundir(), ue->major, ue->minor);
    FILE *f = fopen(path,"w");
    if (!f) return;
    for (int i=0;i<ue->nenv;i++) fprintf(f, "E:%s\n", ue->env[i]);
    if (ue->ntags) {
        fprintf(f, "E:TAGS=");
        for (int t=0;t<ue->ntags;t++) fprintf(f, "%s%s", t?",":"", ue->tags[t]);
        fprintf(f, "\n");
    }
    fclose(f);
}
static void db_remove(uevent_t *ue) {
    if (g_test) return;
    if (ue->major==0 && ue->minor==0) return;
    char path[512];
    snprintf(path, sizeof path, "%s/data/c%d:%d", rundir(), ue->major, ue->minor);
    unlink(path);
}

/* ===================== netlink + monitor ===================== */
static int netlink_setup(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    if (fd<0) return -1;
    struct sockaddr_nl nl; memset(&nl,0,sizeof nl);
    nl.nl_family=AF_NETLINK; nl.nl_groups=1; /* kernel uevent multicast group */
    if (bind(fd,(struct sockaddr*)&nl,sizeof nl)<0){ close(fd); return -1; }
    return fd;
}

/* rebroadcast socket: send uevents to multicast group 4 so libudev clients
   (Y-libudev / libudev-zero) can monitor devices — same group mdevd uses (-O 4). */
static int monitor_fd = -1;
static int monitor_setup(void) {
    monitor_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    if (monitor_fd < 0) return -1;
    struct sockaddr_nl nl; memset(&nl,0,sizeof nl);
    nl.nl_family = AF_NETLINK;
    nl.nl_groups = 4;
    if (bind(monitor_fd,(struct sockaddr*)&nl,sizeof nl) < 0) { close(monitor_fd); monitor_fd=-1; return -1; }
    return 0;
}
static void monitor_send(const char *buf, ssize_t len) {
    if (monitor_fd < 0) return;
    struct sockaddr_nl dst; memset(&dst,0,sizeof dst);
    dst.nl_family = AF_NETLINK;
    dst.nl_groups = 4;
    sendto(monitor_fd, buf, (size_t)len, 0, (struct sockaddr*)&dst, sizeof dst);
}

/* ===================== queue state (seed for udev_queue_*) ===================== */
static volatile int g_pending = 0;
static volatile int g_reload = 0;
static int g_seqnum = 0;          /* monotonic udev event seqnum for udev_queue_* */
static void on_sighup(int s){ (void)s; g_reload = 1; }

/* Persist queue state so a libudev client (route Y) can read it without the
   daemon's internal memory: /run/udev/queue holds SEQNUM + QUEUE_LENGTH.
   kernel seqnum lives at /sys/kernel/uevent_seqnum (read by the lib directly). */
static void queue_write_state(void) {
    if (g_test) return;
    char path[512]; snprintf(path,sizeof path,"%s/queue",rundir());
    FILE *f=fopen(path,"w"); if(!f) return;
    fprintf(f,"SEQNUM=%d\n",g_seqnum);
    fprintf(f,"QUEUE_LENGTH=%d\n",g_pending);
    fclose(f);
}

/* ===================== admin subcommands ===================== */
/* re-trigger: walk /sys/devices and write "add" into every uevent file */
static void trigger_walk(const char *dir) {
    DIR *d = opendir(dir); if(!d) return;
    struct dirent *e;
    while ((e=readdir(d))) {
        if (!strcmp(e->d_name,".") || !strcmp(e->d_name,"..")) continue;
        char path[512]; snprintf(path,sizeof path,"%s/%s",dir,e->d_name);
        struct stat st; if (stat(path,&st)<0) continue;
        if (S_ISDIR(st.st_mode)) {
            char uev[600]; snprintf(uev,sizeof uev,"%s/uevent",path);
            if (access(uev,F_OK)==0) { FILE *f=fopen(uev,"w"); if(f){ fputs("add\n",f); fclose(f); } }
            trigger_walk(path);
        }
    }
    closedir(d);
}
static void cmd_settle(int timeout) {
    time_t start=time(NULL);
    while (g_pending>0) {
        if (time(NULL)-start >= timeout) { fprintf(stderr,"settle: timeout (%ds)\n",timeout); return; }
        usleep(50000);
    }
    printf("settled (%d pending)\n", g_pending);
}
static void cmd_info(const char *dbkey) {
    char path[512]; snprintf(path,sizeof path,"%s/data/%s",rundir(),dbkey);
    FILE *f=fopen(path,"r"); if(!f){ printf("no DB entry for %s\n",dbkey); return; }
    char line[512];
    while (fgets(line,sizeof line,f)) fputs(line,stdout);
    fclose(f);
}
static void cmd_control(const char *action) {
    if (!strcmp(action,"reload")) {
        FILE *p=fopen(UDEV_PIDFILE,"r");
        if(p){ int pid; fscanf(p,"%d",&pid); fclose(p); kill(pid,SIGHUP); printf("sent SIGHUP to %d\n",pid); }
        else printf("no daemon pidfile (%s)\n", UDEV_PIDFILE);
    } else printf("unknown control action: %s\n",action);
}

/* passive monitor: listen on the kernel uevent multicast groups and print
   each event as it arrives (mirrors `udevadm monitor`). kernel=grp1,
   udev=grp4 (our daemon's rebroadcast). default: both. */
static void cmd_monitor(int kernel, int udev) {
    int groups = (kernel?1:0) | (udev?4:0);
    if (groups == 0) groups = 1 | 4; /* default: kernel + udev replay */
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    if (fd < 0) { perror("monitor socket"); return; }
    struct sockaddr_nl nl; memset(&nl,0,sizeof nl);
    nl.nl_family = AF_NETLINK;
    nl.nl_groups = groups;
    if (bind(fd,(struct sockaddr*)&nl,sizeof nl) < 0) { perror("monitor bind"); close(fd); return; }
    char buf[8192];
    printf("[udev] monitor listening (kernel=%s udev=%s)\n",
           kernel?"yes":"no", udev?"yes":"no");
    fflush(stdout);
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof buf - 1, 0);
        if (n <= 0) continue;
        const char *p = buf, *end = buf + n;
        const char *hdr = p;
        const char *nl0 = memchr(p, '\0', end - p);
        printf("=== %s ===\n", hdr);
        if (nl0) p = nl0 + 1;
        while (p < end && *p) {
            const char *nnl = memchr(p, '\0', end - p);
            if (!nnl) break;
            printf("  %.*s\n", (int)(nnl - p), p);
            p = nnl + 1;
        }
        fflush(stdout);
    }
}

/* process one uevent through the whole ruleset: match, apply, honour GOTO/LABEL,
   then write/remove the device DB. Shared by the daemon and `--test`. Returns the
   number of matching rules. */
static int process_uevent(uevent_t *ue) {
    int is_add = strcmp(ue->action,"remove")!=0;
    if (is_add) g_pending++;
    g_seqnum++;                       /* every processed event advances the seqnum */
    int matched = 0;
    for (int i=0; i<RS.n; ) {
        rule_t *r = &RS.r[i];
        if (!rule_matches(r,ue)) { i++; continue; }
        matched++;
        apply_rule(r,ue);
        if (r->goto_l[0]) {
            int t = find_label(r->goto_l);
            if (t>=0) { i = t+1; continue; }
        }
        i++;
    }
    if (!strcmp(ue->action,"remove")) db_remove(ue); else db_write(ue);
    if (is_add && g_pending>0) g_pending--;
    queue_write_state();
    return matched;
}

/* Resolve the rules directory. An explicit --rules wins. Otherwise, if the
   default relative name ("rules") is not present in the caller's CWD, look for a
   copy next to the executable and then fall back to conventional system paths.
   A real daemon is not launched from its own source tree, so it must not depend
   on the caller's working directory to find its rules. */
static void resolve_rules_dir(const char *argv0) {
    struct stat st;
    if (stat(g_rulesdir, &st) == 0 && S_ISDIR(st.st_mode)) return; /* cwd/rules ok */
    if (strcmp(g_rulesdir,"rules") != 0) return;                  /* explicit, keep */
    char *d = NULL;
    if (argv0 && strchr(argv0,'/')) {
        d = strdup(argv0);
        char *sl = strrchr(d,'/'); if (sl) *sl = 0;
        char cand[512];
        snprintf(cand,sizeof cand,"%s/../rules",d);
        if (stat(cand,&st)==0 && S_ISDIR(st.st_mode)) { snprintf(g_rulesdir,sizeof g_rulesdir,"%s",cand); free(d); return; }
        snprintf(cand,sizeof cand,"%s/rules",d);
        if (stat(cand,&st)==0 && S_ISDIR(st.st_mode)) { snprintf(g_rulesdir,sizeof g_rulesdir,"%s",cand); free(d); return; }
        free(d);
    }
    if (stat("/etc/udev/rules.d",&st)==0 && S_ISDIR(st.st_mode))
        snprintf(g_rulesdir,sizeof g_rulesdir,"/etc/udev/rules.d");
}

/* ===================== main ===================== */
/* `udev verify`: syntax-check a rules file (or every *.rules in a directory).
   Reports line-level errors (unbalanced quotes, missing operator, unknown key)
   and returns non-zero if any are found. Mirrors `udevadm verify`. */
static int verify_file(const char *path) {
    FILE *f = fopen(path,"r");
    if (!f) { printf("[verify] cannot open %s\n", path); return 1; }
    char line[1024]; int errs=0, rules=0, ln=0;
    while (fgets(line,sizeof line,f)) {
        ln++;
        size_t L=strlen(line); while (L && (line[L-1]=='\n'||line[L-1]=='\r')) line[--L]=0;
        char *s=line; while (*s==' '||*s=='\t') s++;
        if (*s==0 || *s=='#') continue;
        int q=0; for (char *c=s; *c; c++) if (*c=='"') q++;
        if (q%2) { printf("[verify] %s:%d: unbalanced quotes\n", path, ln); errs++; }
        char *p=s, *tok;
        while ((tok = next_tok(p,&p)) != NULL) {
            char key[40],op[3],val[160];
            if (split_tok(tok,key,op,val)!=0) {
                printf("[verify] %s:%d: no operator in token '%s'\n", path, ln, tok); errs++;
            } else if (!strcmp(key,"SUBSYSTEM")||!strcmp(key,"KERNEL")||!strcmp(key,"ACTION")
                    ||!strncmp(key,"ENV{",4)||!strncmp(key,"ATTR{",5)||!strncmp(key,"IMPORT",6)
                    ||!strcmp(key,"MODE")||!strcmp(key,"OWNER")||!strcmp(key,"GROUP")
                    ||!strcmp(key,"SYMLINK")||!strcmp(key,"TAG")||!strcmp(key,"PROGRAM")
                    ||!strcmp(key,"RUN")||!strcmp(key,"LABEL")||!strcmp(key,"GOTO")) {
                /* recognised key — fine */
            } else {
                printf("[verify] %s:%d: unknown key '%s'\n", path, ln, key); errs++;
            }
        }
        rules++;
    }
    fclose(f);
    printf("[verify] %s: %d line(s), %d rule(s), %d error(s)\n", path, ln, rules, errs);
    return errs ? 1 : 0;
}

/* Build a kernel-style NUL-separated uevent buffer from a device's sysfs entry:
   header "add@<devpath>", then ACTION/DEVPATH/SUBSYSTEM plus the device's own
   KEY=VALUE lines from <syspath>/uevent. Used by `udev test` to dry-run the rules
   against a real device without touching it. Returns bytes written, 0 on error. */
static int build_uevent_from_syspath(const char *syspath, char *out, size_t outsz) {
    char uev[1024], real[1024], sl[1024], lk[1024], line[512], sub[128]="";
    if ((size_t)snprintf(uev,sizeof uev,"%s/uevent",syspath) >= sizeof uev) return 0;
    FILE *f=fopen(uev,"r"); if(!f) return 0;
    const char *devpath=syspath;
    if (realpath(syspath,real)) devpath=real;
    if (!strncmp(devpath,"/sys",4)) devpath += 4;
    if ((size_t)snprintf(sl,sizeof sl,"%s/subsystem",syspath) < sizeof sl) {
        ssize_t n=readlink(sl,lk,sizeof lk-1);
        if (n>0){ lk[n]=0; char *b=strrchr(lk,'/'); snprintf(sub,sizeof sub,"%.120s",b?b+1:lk); }
    }
    size_t w=0;
    /* every append is bounds-checked: a truncated uevent would silently test
       the wrong rule set, so treat overflow as an error instead */
#define PUT(...) do { \
        if (w >= outsz) { fclose(f); return 0; } \
        int n_ = snprintf(out+w, outsz-w, __VA_ARGS__); \
        if (n_ < 0 || (size_t)n_ >= outsz-w) { fclose(f); return 0; } \
        w += (size_t)n_ + 1; \
    } while (0)
    PUT("add@%s",devpath);
    PUT("ACTION=add");
    PUT("DEVPATH=%s",devpath);
    if (sub[0]) PUT("SUBSYSTEM=%s",sub);
    while (fgets(line,sizeof line,f)) {
        size_t L=strlen(line); while(L&&(line[L-1]=='\n'||line[L-1]=='\r')) line[--L]=0;
        if (!L) continue;
        PUT("%s",line);
    }
#undef PUT
    fclose(f);
    return (int)w;
}

int main(int argc, char **argv) {
    /* argv[0] personality: systemd ships udevd/udevadm/udev-hwdb as one ELF
       dispatched by the invoked name. Mirror that so symlinks are drop-in. */
    const char *prog = strrchr(argv[0], '/'); prog = prog ? prog + 1 : argv[0];
    const char *cmd;
    int argi;
    if (!strcmp(prog,"udevadm")) {
        if (argc>1 && argv[1][0]!='-') { cmd=argv[1]; argi=2; }
        else { fprintf(stderr,"usage: udevadm <command> [options]\n"); return 1; }
    } else if (!strcmp(prog,"udevd") || !strcmp(prog,"systemd-udevd")) {
        cmd="daemon"; argi=1;
    } else if (!strcmp(prog,"udev-hwdb") || !strcmp(prog,"systemd-hwdb")) {
        cmd="hwdb"; argi=1;
    } else {
        cmd = (argc>1 && argv[1][0]!='-') ? argv[1] : "daemon";
        argi = strcmp(cmd,"daemon")==0 ? 1 : 2;
    }
    int test=0; const char *testfile=NULL, *subsys=NULL, *dbkey=NULL, *ctlact="reload";
    int timeout=120, kernel=0, udev=0;
    const char *query=NULL; int val_only=0, do_update=0;
    for (int i = argi; i<argc; i++) {
        if(!strcmp(argv[i],"--test")){ test=1; if(i+1<argc) testfile=argv[++i]; }
        else if(!strcmp(argv[i],"--rules")){ if(i+1<argc) snprintf(g_rulesdir,sizeof g_rulesdir,"%s",argv[++i]); }
        else if(!strcmp(argv[i],"--subsystem")){ if(i+1<argc) subsys=argv[++i]; }
        else if(!strcmp(argv[i],"--timeout")){ if(i+1<argc) timeout=atoi(argv[++i]); }
        else if(!strncmp(argv[i],"--timeout=",10)){ timeout=atoi(argv[i]+10); }
        else if(!strcmp(argv[i],"--db")){ if(i+1<argc) dbkey=argv[++i]; }
        else if(!strcmp(argv[i],"--kernel")||!strcmp(argv[i],"-k")) kernel=1;
        else if(!strcmp(argv[i],"--udev")||!strcmp(argv[i],"-u")) udev=1;
        else if(!strncmp(argv[i],"--query=",8)){ query=argv[i]+8; }
        else if(!strcmp(argv[i],"--query")){ if(i+1<argc) query=argv[++i]; }
        else if(!strcmp(argv[i],"--value")) val_only=1;
        else if(!strcmp(argv[i],"--update")) do_update=1;
        else if(!strncmp(argv[i],"--hwdbdir=",10)){ g_hwdbdir=argv[i]+10; }
        else if(!strcmp(argv[i],"--action")){ /* reserved */ }
    }
    g_test = test;
    { const char *rd = getenv("UDEV_RUNDIR");
      snprintf(g_rundir, sizeof g_rundir, "%s", rd ? rd : "/run/udev"); }
    resolve_rules_dir(argv[0]);
    load_dir(g_rulesdir);
    hwdb_load_all();

    /* --test: parse a sample uevent file and run the rule engine, then exit.
       This MUST run before the daemon/trigger branches below, otherwise a bare
       `udev --test` (where argv[1] starts with '-' and cmd defaults to
       "daemon") would fall into the netlink recv() loop and hang. */
    if (test) {
        if (!testfile) { fprintf(stderr, "usage: udev --test <uevent-file>\n"); return 1; }
        FILE *tf = fopen(testfile, "rb");
        if (!tf) { fprintf(stderr, "cannot open test file: %s\n", testfile); return 1; }
        char buf[8192];
        size_t rn = fread(buf, 1, sizeof buf - 1, tf);
        fclose(tf);
        if (rn <= 0) { fprintf(stderr, "empty test file\n"); return 1; }
        /* normalize: a convenient newline-separated sample is treated the same
           as the kernel's NUL-separated uevent format */
        for (size_t i = 0; i < rn; i++) if (buf[i] == '\n') buf[i] = 0;
        buf[rn] = 0;
        uevent_t ue;
        if (ue_parse(buf, (ssize_t)rn, &ue) < 0) { fprintf(stderr, "failed to parse uevent\n"); return 1; }
        printf("[udev] test uevent: action=%s subsys=%s devname=%s devpath=%s\n",
               ue.action, ue.subsys, ue.devname, ue.devpath);
        int matched = process_uevent(&ue);
        printf("[udev] %d rule(s) matched\n", matched);
        return 0;
    }

    /* `udev apply <uevent-file>` — process a synthetic uevent and WRITE the real
       device DB + queue (not just print), so a libudev client (route Y) can read it.
       This is the daemon-side producer for an end-to-end test that needs no root or
       a live kernel netlink: feed a sample uevent, then inspect the resulting
       /run/udev/data/cMAJ:MIN with any libudev-based tool. Honors UDEV_RUNDIR. */
    if (!strcmp(cmd,"apply")) {
        if (argc < 3) { fprintf(stderr, "usage: udev apply <uevent-file>\n"); return 1; }
        const char *f = argv[2];
        FILE *af = fopen(f, "rb");
        if (!af) { fprintf(stderr, "cannot open %s\n", f); return 1; }
        char buf[8192];
        size_t rn = fread(buf, 1, sizeof buf - 1, af);
        fclose(af);
        if (rn <= 0) { fprintf(stderr, "empty uevent file\n"); return 1; }
        for (size_t i = 0; i < rn; i++) if (buf[i] == '\n') buf[i] = 0;
        buf[rn] = 0;
        uevent_t ue;
        if (ue_parse(buf, (ssize_t)rn, &ue) < 0) { fprintf(stderr, "failed to parse uevent\n"); return 1; }
        char dd[320]; snprintf(dd, sizeof dd, "%s/data", rundir());
        char dv[320]; snprintf(dv, sizeof dv, "%s/dev", rundir());
        mkdir(rundir(), 0755); mkdir(dd, 0755); mkdir(dv, 0755);
        /* continue the udev seqnum from any prior queue state, so repeated apply
           runs advance a monotonic counter as a long-running daemon would */
        { char qp[512]; snprintf(qp,sizeof qp,"%s/queue",rundir());
          FILE *qf=fopen(qp,"r");
          if(qf){ char l[256]; while(fgets(l,sizeof l,qf)){ if(!strncmp(l,"SEQNUM=",7)){ g_seqnum=(int)strtol(l+7,NULL,10); break; } } fclose(qf); } }
        g_test = 0; g_apply = 1;
        int matched = process_uevent(&ue);
        if (ue.major || ue.minor)
            printf("[udev] apply: wrote %s/data/c%d:%d (%d rule(s) matched)\n",
                   rundir(), ue.major, ue.minor, matched);
        else
            printf("[udev] apply: uevent has no MAJOR/MINOR — device DB not written "
                   "(%d rule(s) matched)\n", matched);
        printf("[udev] apply: queue state -> %s/queue (SEQNUM=%d)\n", rundir(), g_seqnum);
        return 0;
    }

    /* `udev queue` — print the daemon's queue state (SEQNUM / QUEUE_LENGTH) from
       the rundir. Drop-in equivalent to `udevadm settle`'s status read; honors UDEV_RUNDIR. */
    if (!strcmp(cmd,"queue")) {
        char p[512]; snprintf(p,sizeof p,"%s/queue",rundir());
        unsigned long long seq=0; int len=0;
        FILE *f=fopen(p,"r");
        if(f){ char l[256]; while(fgets(l,sizeof l,f)){ if(!strncmp(l,"SEQNUM=",7)) seq=strtoull(l+7,NULL,10); else if(!strncmp(l,"QUEUE_LENGTH=",13)) len=(int)strtol(l+13,NULL,10); } fclose(f); }
        printf("SEQNUM=%llu\nQUEUE_LENGTH=%d\n", seq, len);
        return 0;
    }

    /* `udev verify <rules-file-or-dir>...` — syntax-check rule files (or all
       *.rules in a dir); non-zero exit if any error. Mirrors `udevadm verify`. */
    if (!strcmp(cmd,"verify")) {
        if (argc < 3) { fprintf(stderr, "usage: udev verify <rules-file-or-dir>...\n"); return 1; }
        int total=0;
        for (int i=2;i<argc;i++) {
            struct stat st;
            if (stat(argv[i],&st)==0 && S_ISDIR(st.st_mode)) {
                DIR *dp=opendir(argv[i]); if(!dp) continue;
                struct dirent *e; char nm[600];
                while ((e=readdir(dp))) {
                    if (e->d_name[0]=='.') continue;
                    if (strstr(e->d_name,".rules")) { snprintf(nm,sizeof nm,"%s/%s",argv[i],e->d_name); total+=verify_file(nm); }
                }
                closedir(dp);
            } else total += verify_file(argv[i]);
        }
        if (total) { fprintf(stderr, "[verify] %d error(s)\n", total); return 1; }
        printf("[verify] OK\n");
        return 0;
    }

    /* `udev test <syspath|uevent-file>` — dry-run the rule engine against a
       device (reads <syspath>/uevent) or a synthetic uevent file. Prints matched
       rules + builtin results; never writes the DB or /dev. Mirrors `udevadm test`. */
    if (!strcmp(cmd,"test")) {
        const char *arg = (argc>=3)? argv[2] : NULL;
        if (!arg) { fprintf(stderr,"usage: udev test <syspath|uevent-file>\n"); return 1; }
        char buf[8192]; int rn=0;
        if (!strncmp(arg,"/sys/",5)) {
            rn = build_uevent_from_syspath(arg, buf, sizeof buf);
            if (rn<=0){ fprintf(stderr,"udev test: cannot read uevent from %s\n",arg); return 1; }
        } else {
            FILE *tf=fopen(arg,"rb");
            if(!tf){ fprintf(stderr,"udev test: cannot open %s\n",arg); return 1; }
            size_t r=fread(buf,1,sizeof buf-1,tf); fclose(tf);
            if(!r){ fprintf(stderr,"udev test: empty file %s\n",arg); return 1; }
            for(size_t i=0;i<r;i++) if(buf[i]=='\n') buf[i]=0;
            buf[r]=0; rn=(int)r;
        }
        uevent_t ue;
        if (ue_parse(buf,rn,&ue)<0){ fprintf(stderr,"udev test: failed to parse uevent\n"); return 1; }
        printf("[udev] test uevent: action=%s subsys=%s devname=%s devpath=%s\n",
               ue.action, ue.subsys, ue.devname, ue.devpath);
        g_test = 1; g_apply = 0;
        int matched = process_uevent(&ue);
        printf("[udev] test: %d rule(s) matched (dry-run, nothing written)\n", matched);
        return 0;
    }

    if (!strcmp(cmd,"daemon")) {
        signal(SIGHUP, on_sighup);
        int fd = netlink_setup();
        if (fd<0){ perror("netlink setup (need root/CAP_NET_ADMIN)"); return 1; }
        if (monitor_setup() < 0) fprintf(stderr, "warning: monitor rebroadcast unavailable\n");
        if (geteuid()==0){ FILE *pf=fopen(UDEV_PIDFILE,"w"); if(pf){ fprintf(pf,"%d",getpid()); fclose(pf); } }
        char buf[8192];
        for (;;) {
            ssize_t n = recv(fd,buf,sizeof buf-1,0);
            if (n<=0) continue;
            uevent_t ue; if (ue_parse(buf,n,&ue)<0) continue;
            process_uevent(&ue);
            monitor_send(buf, n);
            if (g_reload) { rules_reload(g_rulesdir); g_reload=0; fprintf(stderr,"rules reloaded\n"); }
        }
    } else if (!strcmp(cmd,"trigger")) {
        if (test) { printf("[trigger dry-run] would walk /sys/devices and write 'add' to uevent files (subsys=%s)\n", subsys?subsys:"*"); return 0; }
        trigger_walk("/sys/devices");
        printf("trigger done\n");
        return 0;
    } else if (!strcmp(cmd,"settle")) {
        cmd_settle(timeout);
        return 0;
    } else if (!strcmp(cmd,"info")) {
        if(!dbkey){ fprintf(stderr,"usage: udev info --db=cMAJ:MIN\n"); return 1; }
        cmd_info(dbkey);
        return 0;
    } else if (!strcmp(cmd,"control")) {
        cmd_control(ctlact);
        return 0;
    } else if (!strcmp(cmd,"monitor")) {
        cmd_monitor(kernel, udev);
        return 0;
    } else if (!strcmp(cmd,"hwdb")) {
        /* udev-hwdb / systemd-hwdb positional verbs: `update`, `query <alias>` */
        for (int i=argi; i<argc; i++) {
            if (!strcmp(argv[i],"update")) do_update=1;
            else if (!strcmp(argv[i],"query") && i+1<argc) query=argv[++i];
        }
        if (do_update) {
            hwdb_load_all();
            printf("hwdb: loaded %d entries (text query mode — no binary cache built)\n", HWn);
            return 0;
        }
        if (!query){ fprintf(stderr,"usage: udev hwdb --query=MODALIAS [--property|--value]\n"); return 1; }
        cmd_hwdb_query(query, val_only);
        return 0;
    } else {
        fprintf(stderr,"unknown command: %s\n",cmd);
        fprintf(stderr,"usage: udev [daemon|trigger|settle|info|control|monitor|hwdb|apply|queue|verify|test] [options]\n");
        return 1;
    }
    return 0;
}
