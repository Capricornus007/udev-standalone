#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/sysmacros.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <limits.h>

/* pidfile: conventional udev location. On the target systemd-free system there
   is nothing else to collide with, and keeping the standard path maximizes
   drop-in compatibility with scripts/tools that expect udev's runtime layout. */
#define UDEV_PIDFILE "/run/udev.pid"
#define UDEV_VERSION "1.0.0"

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
    int  ifindex;
    char tags[16][64];
    int  ntags;
    char symlinks[16][160];
    int  nsymlinks;
    char runs[16][160];
    int  nruns;
    char mode[16], owner[64], group[64];
    char devlinks[16][256];
    int  ndevlinks;
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
    if ((s = ue_getenv(ue,"IFINDEX"))) ue->ifindex = atoi(s);
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
static int glob_match(const char *pat, const char *str);
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
    int eq = glob_match(val,actual);
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

/* Expand udev rule values: $env{KEY}, $kernel, $devpath, $devnode, $subsystem,
   $action, $driver, %k, %n and %%. */
static void expand_value(uevent_t *ue, const char *in, char *out, size_t outsz) {
    size_t o=0;
    for (size_t i=0; in[i] && o+1<outsz; ) {
        const char *v=NULL; size_t adv=0;
        if (!strncmp(in+i,"$env{",5)) {
            const char *end=strchr(in+i+5,'}');
            if (end) {
                char key[64]; size_t kl=(size_t)(end-(in+i+5));
                if (kl>=sizeof key) kl=sizeof key-1;
                memcpy(key,in+i+5,kl); key[kl]=0;
                v=ue_getenv(ue,key); adv=(size_t)(end-in)+1-i;
            }
        } else if (!strncmp(in+i,"$kernel",7)) { v=kernel_name(ue); adv=7; }
        else if (!strncmp(in+i,"$devpath",8)) { v=ue->devpath; adv=8; }
        else if (!strncmp(in+i,"$devnode",8)) { v=ue->devname; adv=8; }
        else if (!strncmp(in+i,"$subsystem",10)) { v=ue->subsys; adv=10; }
        else if (!strncmp(in+i,"$action",7)) { v=ue->action; adv=7; }
        else if (!strncmp(in+i,"$driver",7)) { v=ue_getenv(ue,"DRIVER"); adv=7; }
        else if (in[i]=='%' && in[i+1]=='k') { v=kernel_name(ue); adv=2; }
        else if (in[i]=='%' && in[i+1]=='n') { v=ue->devname; adv=2; }
        else if (in[i]=='%' && in[i+1]=='%') { if(o+1<outsz) out[o++]='%'; i+=2; continue; }
        if (adv) {
            if (v) { size_t vl=strlen(v); if (vl>outsz-1-o) vl=outsz-1-o; memcpy(out+o,v,vl); o+=vl; }
            i+=adv; continue;
        }
        out[o++]=in[i++];
    }
    out[o]=0;
}

/* run a shell command, capture its stdout (capped) into out */
static int run_capture(uevent_t *ue, const char *cmd, char *out, size_t outsz) {
    int p[2]; if (pipe(p)<0) return -1;
    pid_t pid = fork();
    if (pid<0){ close(p[0]); close(p[1]); return -1; }
    if (pid==0){
        close(p[0]); dup2(p[1],1); close(p[1]);
        char *envp[UE_MAX_ENV+4]; int e=0;
        for (int i=0;i<ue->nenv && e<UE_MAX_ENV+2;i++) envp[e++]=ue->env[i];
        envp[e++]="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
        envp[e]=NULL;
        execle("/bin/sh","sh","-c",cmd,(char*)NULL,(char *const*)envp);
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
static void run_exec(uevent_t *ue, const char *cmd) {
    pid_t pid = fork();
    if (pid<0) return;
    if (pid==0){
        setsid();
        char *envp[UE_MAX_ENV+4]; int e=0;
        for (int i=0;i<ue->nenv && e<UE_MAX_ENV+2;i++) envp[e++]=ue->env[i];
        envp[e++]="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
        envp[e]=NULL;
        execle("/bin/sh","sh","-c",cmd,(char*)NULL,(char *const*)envp);
        _exit(127);
    }
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
        if (*pat=='?') { pat++; str++; continue; }
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
    for (int i=0;i<r->nasg;i++){
        char val[256]; expand_value(ue,r->a_val[i],val,sizeof val);
        if(!strcmp(r->a_key[i],"MODE"))  snprintf(ue->mode,sizeof ue->mode,"%.15s",val);
        else if(!strcmp(r->a_key[i],"OWNER")) snprintf(ue->owner,sizeof ue->owner,"%.63s",val);
        else if(!strcmp(r->a_key[i],"GROUP")) snprintf(ue->group,sizeof ue->group,"%.63s",val);
        else if(!strcmp(r->a_key[i],"SYMLINK")) {
            if(ue->nsymlinks<16) snprintf(ue->symlinks[ue->nsymlinks++],160,"%.159s",val);
        }
        else if(!strcmp(r->a_key[i],"TAG")) {
            int seen=0;
            for(int t=0;t<ue->ntags;t++) if(!strcmp(ue->tags[t],val)){ seen=1; break; }
            if(!seen && ue->ntags<16) snprintf(ue->tags[ue->ntags++],64,"%.63s",val);
        }
    }
    /* PROGRAM: run and capture stdout into RESULT (visible to later rules via ENV{RESULT}) */
    if (r->program[0]) {
        char cmd[512], res[1024];
        expand_value(ue,r->program,cmd,sizeof cmd);
        if (run_capture(ue,cmd,res,sizeof res)==0 && res[0]) {
            ue_setenv(ue,"RESULT",res);
            if (g_test) printf("       PROGRAM '%s' => RESULT=%s\n", cmd, res);
        }
    }
    /* IMPORT{file|program|hwdb}: parse KEY=VALUE lines into the uevent env */
    for (int k=0;k<r->nimp;k++){
        char val[512]; expand_value(ue,r->imp_val[k],val,sizeof val);
        if (!strcmp(r->imp_kind[k],"file")) {
            FILE *f=fopen(val,"r");
            if (f){ char ln[512]; while(fgets(ln,sizeof ln,f)){ size_t l=strlen(ln); while(l&&(ln[l-1]=='\n'||ln[l-1]=='\r'))ln[--l]=0; char *eq=strchr(ln,'='); if(eq&&l){*eq=0; ue_setenv(ue,ln,eq+1); if(g_test)printf("       IMPORT %s=%s\n",ln,eq+1);} } fclose(f); }
            else if (g_test) printf("       IMPORT file '%s' open failed\n", val);
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
            char names[160]; snprintf(names,sizeof names,"%.159s",val);
            char *save=NULL;
            for (char *b=strtok_r(names,",",&save); b; b=strtok_r(NULL,",",&save)) run_builtin(ue,b);
        } else {
            char buf[1024];
            if (run_capture(ue,val,buf,sizeof buf)==0 && buf[0]){
                char *line=strtok(buf,"\n");
                while(line){ char *eq=strchr(line,'='); if(eq){*eq=0; ue_setenv(ue,line,eq+1); if(g_test)printf("       IMPORT %s=%s\n",line,eq+1);} line=strtok(NULL,"\n"); }
            }
        }
    }
    for (int k=0;k<r->nrun;k++){
        char val[256]; expand_value(ue,r->run[k],val,sizeof val);
        if (ue->nruns<16) snprintf(ue->runs[ue->nruns++],160,"%.159s",val);
    }
}

/* Apply the accumulated event state once, after every matching rule has run.
   This is what makes MODE/GROUP/SYMLINK/TAG from different rules compose. */
static void apply_event(uevent_t *ue) {
    /* Remove events must NEVER create/patch nodes: devtmpfs already deleted it,
       and re-mknod-ing here would resurrect a stale /dev entry after every
       unplug (and the EEXIST fixup would chmod the fresh node of whatever
       minor got reused). Symlink cleanup lives in db_remove; RUN+ still fires. */
    if (!g_test && !strcmp(ue->action,"remove")) {
        for (int i=0;i<ue->nruns;i++) run_exec(ue,ue->runs[i]);
        return;
    }
    int has_node = ue->devname[0] && (ue->major || ue->minor);
    char path[512]="";
    if (has_node) {
        /* apply mode builds a self-contained fake /dev tree under UDEV_RUNDIR so the
           result is fully inspectable without touching the real /dev (and without root);
           the live daemon always creates the real /dev node. */
        if (g_apply) snprintf(path,sizeof path,"%s/dev/%s", rundir(), ue->devname);
        else         snprintf(path,sizeof path,"/dev/%s", ue->devname);
    }
    const char *km = ue->mode[0]? ue->mode : ue_getenv(ue,"MODE");
    unsigned perm = km? (unsigned)strtol(km,NULL,8) : 0600;
    if (g_test) {
        if (has_node) {
            printf("[udev] TEST action=%s node=%s mode=%o owner=%s group=%s\n",
                ue->action, path, perm,
                ue->owner[0]?ue->owner:"(kernel)", ue->group[0]?ue->group:"(kernel)");
            for (int i=0;i<ue->nsymlinks;i++) printf("       symlink -> /dev/%s\n", ue->symlinks[i]);
        }
        if (ue->ntags) { printf("       tags:"); for(int t=0;t<ue->ntags;t++) printf(" %s",ue->tags[t]); printf("\n"); }
        for (int i=0;i<ue->nruns;i++) printf("       [would RUN] %s\n", ue->runs[i]);
        return;
    }
    if (has_node) {
        char *slash=strrchr(path,'/');
        if (slash && slash!=path){ *slash=0; mkdir(path,0755); *slash='/'; }
        mode_t ntype = !strcmp(ue->subsys,"block") ? S_IFBLK : S_IFCHR;
        int created = (mknod(path, ntype|perm, makedev(ue->major,ue->minor))==0);
        if (!created) {
            if (g_apply) {
                /* not root in the fake-root test: leave a placeholder file so the node
                   path exists for stat-based clients / inspection */
                FILE *pf=fopen(path,"w"); if(pf) fclose(pf);
            } else if (errno==EEXIST) {
                /* devtmpfs (or an earlier coldplug pass) already made the node.
                   Fixing up an existing node is udev's core job: MODE/GROUP/OWNER
                   rules MUST still land on it, or /dev stays at kernel defaults
                   (0600 root:root) and nothing user-facing works. */
                chmod(path, perm);
                created = 1;   /* fall through to the chown below */
            } else {
                printf("       mknod failed: %s\n", strerror(errno));
            }
        }
        if (created && !g_apply) {
            uid_t u=0; gid_t g=0;
            if(ue->owner[0]){ struct passwd *pw=getpwnam(ue->owner); if(pw) u=pw->pw_uid; }
            if(ue->group[0]){ struct group *gr=getgrnam(ue->group); if(gr) g=gr->gr_gid; }
            chown(path,u,g);
        }
        for (int i=0;i<ue->nsymlinks;i++){
            char sp[512];
            if (g_apply) snprintf(sp,sizeof sp,"%s/dev/%s", rundir(), ue->symlinks[i]);
            else         snprintf(sp,sizeof sp,"/dev/%s", ue->symlinks[i]);
            /* create ALL parent dirs: links live nested (disk/by-uuid/x,
               input/by-path/x); a single mkdir left the parent missing and
               symlink() failed silently, so no stable link ever appeared. */
            for (char *q=sp+1; *q; q++) if (*q=='/') { *q=0; mkdir(sp,0755); *q='/'; }
            symlink(path, sp);
            if (ue->ndevlinks < 16)
                snprintf(ue->devlinks[ue->ndevlinks++], 256, "%s", ue->symlinks[i]);
        }
    }
    for (int i=0;i<ue->nruns;i++) if (!g_apply) run_exec(ue,ue->runs[i]);
}

/* ===================== device DB ===================== */
/* udev database key: b/c MAJOR:MINOR for device nodes, nIFINDEX for network
   interfaces, +subsystem:sysname for everything else (matches udev's layout). */
static int db_key(uevent_t *ue, char *out, size_t n) {
    if (ue->major || ue->minor) {
        snprintf(out, n, "%c%d:%d", !strcmp(ue->subsys,"block")?'b':'c', ue->major, ue->minor);
        return 1;
    }
    if (!strcmp(ue->subsys,"net") && ue->ifindex > 0) {
        snprintf(out, n, "n%d", ue->ifindex);
        return 1;
    }
    if (ue->subsys[0] && ue->devpath[0]) {
        const char *base = strrchr(ue->devpath,'/');
        base = base ? base+1 : ue->devpath;
        if (*base) { snprintf(out, n, "+%.60s:%.60s", ue->subsys, base); return 1; }
    }
    return 0;
}
static unsigned long long now_usec(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC,&ts) != 0) return 0;
    return (unsigned long long)ts.tv_sec*1000000ull + (unsigned long long)ts.tv_nsec/1000ull;
}
static void db_write(uevent_t *ue) {
    if (g_test) return;
    char key[128];
    if (!db_key(ue,key,sizeof key)) return;
    char path[512];
    snprintf(path, sizeof path, "%s/data/%s", rundir(), key);
    /* keep the original initialization timestamp across updates */
    unsigned long long init = now_usec();
    FILE *old = fopen(path,"r");
    if (old) { char l[256]; while (fgets(l,sizeof l,old)) {
        if (l[0]=='I' && l[1]==':') { init = strtoull(l+2,NULL,10); break; } } fclose(old); }
    FILE *f = fopen(path,"w");
    if (!f) return;
    for (int i=0;i<ue->ndevlinks;i++) {
        const char *dl = ue->devlinks[i];
        if (!strncmp(dl,"/dev/",5)) dl += 5;
        fprintf(f, "S:%s\n", dl);
    }
    if (init) fprintf(f, "I:%llu\n", init);
    for (int i=0;i<ue->nenv;i++) fprintf(f, "E:%s\n", ue->env[i]);
    for (int t=0;t<ue->ntags;t++) fprintf(f, "G:%s\nQ:%s\n", ue->tags[t], ue->tags[t]);
    fclose(f);
}
static void db_remove(uevent_t *ue) {
    if (g_test) return;
    char key[128];
    if (!db_key(ue,key,sizeof key)) return;
    char path[512];
    snprintf(path, sizeof path, "%s/data/%s", rundir(), key);
    /* The kernel's devtmpfs deletes the device node itself, but SYMLINK+ links
       (disk/by-uuid/..., input/by-path/...) are ours: read them back from the
       DB before dropping it, or every unplug leaves a dangling /dev symlink
       that blocks the next device that reuses the uuid/path. */
    FILE *f = fopen(path, "r");
    if (f) {
        char line[1024];
        while (fgets(line, sizeof line, f)) {
            if (strncmp(line, "S:", 2)) continue;
            char *nl = strchr(line, '\n'); if (nl) *nl = 0;
            char ln[512];
            snprintf(ln, sizeof ln, "%.500s", line + 2);
            if (!*ln) continue;
            char sp[768];   /* g_rundir(256) + "/dev/"(5) + ln(500) + NUL */
            if (g_apply) snprintf(sp, sizeof sp, "%s/dev/%.500s", rundir(), ln);
            else         snprintf(sp, sizeof sp, "/dev/%.500s", ln);
            unlink(sp);
        }
        fclose(f);
    }
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
static volatile sig_atomic_t g_stop = 0;
static int g_seqnum = 0;          /* monotonic udev event seqnum for udev_queue_* */
static void on_sighup(int s){ (void)s; g_reload = 1; }
static void on_sigterm(int s){ (void)s; g_stop = 1; }

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
static void trigger_write(const char *uev, const char *action) {
    FILE *f=fopen(uev,"w");
    if(f){ fputs(action,f); fputc('\n',f); fclose(f); }
}
static void trigger_walk(const char *dir, const char *action) {
    DIR *d = opendir(dir); if(!d) return;
    struct dirent *e;
    while ((e=readdir(d))) {
        if (!strcmp(e->d_name,".") || !strcmp(e->d_name,"..")) continue;
        char path[512]; snprintf(path,sizeof path,"%s/%s",dir,e->d_name);
        struct stat st; if (stat(path,&st)<0) continue;
        if (S_ISDIR(st.st_mode)) {
            char uev[600]; snprintf(uev,sizeof uev,"%s/uevent",path);
            if (access(uev,F_OK)==0) trigger_write(uev,action);
            trigger_walk(path,action);
        }
    }
    closedir(d);
}
/* --type=subsystems: write the action to /sys/bus/<name>/uevent */
static void trigger_subsystems(const char *action) {
    const char *base="/sys/bus";
    DIR *d=opendir(base); if(!d) return;
    struct dirent *e;
    while ((e=readdir(d))) {
        if (e->d_name[0]=='.') continue;
        char uev[600]; snprintf(uev,sizeof uev,"%s/%s/uevent",base,e->d_name);
        if (access(uev,F_OK)==0) trigger_write(uev,action);
    }
    closedir(d);
}
/* settle must work from a separate admin process, so read the daemon's persisted
   queue state rather than this process's (always-zero) in-memory counter. */
static int queue_length_from_rundir(void) {
    char p[512]; snprintf(p,sizeof p,"%s/queue",rundir());
    int len=0; FILE *f=fopen(p,"r");
    if(f){ char l[256]; while(fgets(l,sizeof l,f)){
        if(!strncmp(l,"QUEUE_LENGTH=",13)){ len=atoi(l+13); break; } } fclose(f); }
    return len;
}
static int cmd_settle(int timeout) {
    time_t start=time(NULL);
    for(;;){
        int pending=queue_length_from_rundir();
        if(pending<=0){ printf("settled\n"); return 0; }
        if(timeout>0 && time(NULL)-start>=timeout){
            fprintf(stderr,"settle: timeout (%ds, %d pending)\n",timeout,pending);
            return 1;
        }
        usleep(50000);
    }
}
/* Resolve a device argument (DB key, /dev node or /sys path) to a DB key. */
static int db_key_from_path(const char *arg, char *out, size_t n) {
    if (!arg || !arg[0]) return 0;
    if ((arg[0]=='b'||arg[0]=='c') && strchr(arg,':')) { snprintf(out,n,"%.120s",arg); return 1; }
    if (arg[0]=='n' && isdigit((unsigned char)arg[1])) { snprintf(out,n,"%.120s",arg); return 1; }
    if (arg[0]=='+' && strchr(arg,':')) { snprintf(out,n,"%.120s",arg); return 1; }
    if (!strncmp(arg,"/sys/",5)) {
        char p[1300]; snprintf(p,sizeof p,"%s/dev",arg);
        FILE *f=fopen(p,"r");
        if (f) {
            unsigned mj=0,mn=0; int ok=(fscanf(f,"%u:%u",&mj,&mn)==2); fclose(f);
            if (ok) {
                char s[1300]; snprintf(s,sizeof s,"%s/subsystem",arg);
                char lk[256]=""; ssize_t l=readlink(s,lk,sizeof lk-1);
                int blk=0; if (l>0) { lk[l]=0; if (strstr(lk,"/block")) blk=1; }
                snprintf(out,n,"%c%u:%u",blk?'b':'c',mj,mn);
                return 1;
            }
        }
        snprintf(p,sizeof p,"%s/ifindex",arg);
        f=fopen(p,"r");
        if (f) { char v[32]={0}; int ok=(fscanf(f,"%31s",v)==1); fclose(f);
            if (ok) { snprintf(out,n,"n%.30s",v); return 1; } }
        char real[1300]; char lk[512]="";
        if (realpath(arg,real)) {
            char s[1400]; snprintf(s,sizeof s,"%s/subsystem",arg);
            ssize_t l=readlink(s,lk,sizeof lk-1);
            if (l>0) { lk[l]=0; char *b=strrchr(lk,'/'); char *sn=strrchr(real,'/');
                if (b&&sn) { snprintf(out,n,"+%.60s:%.60s",b+1,sn+1); return 1; } }
        }
        return 0;
    }
    struct stat st;
    if (stat(arg,&st)==0 && (S_ISBLK(st.st_mode)||S_ISCHR(st.st_mode))) {
        snprintf(out,n,"%c%u:%u",S_ISBLK(st.st_mode)?'b':'c',major(st.st_rdev),minor(st.st_rdev));
        return 1;
    }
    return 0;
}

static void cmd_info(const char *dbkey, const char *mode, const char *arg) {
    char path[512]; snprintf(path,sizeof path,"%s/data/%s",rundir(),dbkey);
    FILE *f=fopen(path,"r"); if(!f){ fprintf(stderr,"no DB entry for %s\n",dbkey); return; }
    char line[1024], devpath[512]="", devname[256]="", links[8][512]; int nlinks=0;
    while (fgets(line,sizeof line,f)) {
        size_t L=strlen(line); while(L&&(line[L-1]=='\n'||line[L-1]=='\r')) line[--L]=0;
        if (line[0]=='E' && line[1]==':') {
            if (!strncmp(line+2,"DEVPATH=",8)) snprintf(devpath,sizeof devpath,"%.511s",line+10);
            else if (!strncmp(line+2,"DEVNAME=",8)) snprintf(devname,sizeof devname,"/dev/%.200s",line+10);
        } else if (line[0]=='S' && line[1]==':' && nlinks<8) {
            if (line[2]=='/') snprintf(links[nlinks++],512,"%.511s",line+2);
            else snprintf(links[nlinks++],512,"/dev/%.506s",line+2);
        }
    }
    fclose(f);
    if (!devpath[0] && arg && !strncmp(arg,"/sys/",5)) {
        char real[1300];
        if (realpath(arg,real)) { const char *p=real; if(!strncmp(p,"/sys",4)) p+=4;
            snprintf(devpath,sizeof devpath,"%.511s",p); }
    }
    if (!devname[0] && arg && !strncmp(arg,"/dev/",5)) snprintf(devname,sizeof devname,"%.255s",arg);
    if (mode && !strcmp(mode,"name")) { if(devname[0]) printf("%s\n",devname); return; }
    if (mode && !strcmp(mode,"path")) { if(devpath[0]) printf("%s\n",devpath); return; }
    if (mode && !strcmp(mode,"symlink")) {
        for(int i=0;i<nlinks;i++) printf("%s%s",i?" ":"",links[i]);
        printf("\n"); return;
    }
    if (mode && (!strcmp(mode,"property")||!strcmp(mode,"env"))) {
        f=fopen(path,"r");
        if(f){ while(fgets(line,sizeof line,f)){
            if(!strncmp(line,"E:",2)) fputs(line+2,stdout); } fclose(f); }
        return;
    }
    if (devpath[0]) printf("P: %s\n",devpath);
    if (devname[0]) printf("N: %s\n",devname);
    for(int i=0;i<nlinks;i++) printf("S: %s\n",links[i]);
    f=fopen(path,"r");
    if(f){ while(fgets(line,sizeof line,f)){
        if(!strncmp(line,"E:",2) && strncmp(line+2,"DEVPATH=",8) && strncmp(line+2,"DEVNAME=",8))
            fputs(line,stdout);
    } fclose(f); }
}
/* Only signal a daemon that is actually this binary. On a system that still
   carries another udev implementation, /run/udev.pid belongs to it; refusing to
   touch it keeps a migration/test session from disrupting the running system. */
static int pid_is_this_elf(int pid) {
    /* Prefer an exact identity check: the daemon is the *same ELF* we are, just
       invoked under another personality name (udevd/udevadm/udev-hwdb). */
    char target[64], self[PATH_MAX], buf[PATH_MAX];
    snprintf(target,sizeof target,"/proc/%d/exe",pid);
    ssize_t n=readlink(target,buf,sizeof buf);
    ssize_t m=readlink("/proc/self/exe",self,sizeof self);
    if(n>0 && m>0){ buf[n]=0; self[m]=0; return strcmp(self,buf)==0; }
    /* readlink fails for another user's process without privilege: fall back to
       the personality names this binary answers to. A foreign implementation
       (e.g. the host's systemd-udevd) is caught by the comm check below. */
    char cpath[64], comm[32]="";
    snprintf(cpath,sizeof cpath,"/proc/%d/comm",pid);
    FILE *c=fopen(cpath,"r");
    if(c){ if(fscanf(c,"%31s",comm)!=1) comm[0]=0; fclose(c); }
    return !strcmp(comm,"udevd") || !strcmp(comm,"udev");
}
static const char *pidfile_path(void) {
    /* Production uses the conventional /run/udev.pid; UDEV_PIDFILE overrides it so
       an unprivileged smoke test can drive control --reload/--exit end to end. */
    static char p[PATH_MAX];
    const char *e = getenv("UDEV_PIDFILE");
    snprintf(p,sizeof p,"%s", e && *e ? e : UDEV_PIDFILE);
    return p;
}
static int standalone_daemon_pid(void) {
    FILE *p=fopen(pidfile_path(),"r");
    if(!p) return 0;
    int pid=0; int ok=(fscanf(p,"%d",&pid)==1); fclose(p);
    if(!ok || pid<=0) return 0;
    if(!pid_is_this_elf(pid)) {
        char cpath[64], comm[64]="";
        snprintf(cpath,sizeof cpath,"/proc/%d/comm",pid);
        FILE *c=fopen(cpath,"r");
        if(c){ if(fscanf(c,"%63s",comm)!=1) comm[0]=0; fclose(c); }
        printf("refusing to signal pid %d (comm '%s', not this daemon)\n",pid,comm);
        return 0;
    }
    return pid;
}
static void cmd_control(const char *action) {
    if (!strcmp(action,"reload")) {
        int pid=standalone_daemon_pid();
        if(pid>0){ if(kill(pid,SIGHUP)==0) printf("sent SIGHUP to %d\n",pid); else perror("kill"); }
        else printf("no standalone daemon pidfile (%s)\n", pidfile_path());
    } else if (!strcmp(action,"exit")) {
        int pid=standalone_daemon_pid();
        if(pid>0){ if(kill(pid,SIGTERM)==0) printf("sent SIGTERM to %d\n",pid); else perror("kill"); }
        else printf("no standalone daemon pidfile (%s)\n", pidfile_path());
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
    apply_event(ue);
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

/* Load a uevent from a /sys device path or a newline-separated file.
   Returns bytes written (NUL-terminated buffer) or -1 on error. */
static int uevent_from_arg(const char *arg, char *buf, size_t bufsz) {
    if (!strncmp(arg,"/sys/",5)) {
        int rn = build_uevent_from_syspath(arg, buf, bufsz);
        return rn>0 ? rn : -1;
    }
    FILE *tf=fopen(arg,"rb"); if(!tf) return -1;
    size_t r=fread(buf,1,bufsz-1,tf); fclose(tf);
    if(!r) return -1;
    for(size_t i=0;i<r;i++) if(buf[i]=='\n') buf[i]=0;
    buf[r]=0;
    return (int)r;
}

int main(int argc, char **argv) {
    /* argv[0] personality: systemd ships udevd/udevadm/udev-hwdb as one ELF
       dispatched by the invoked name. Mirror that so symlinks are drop-in. */
    const char *prog = strrchr(argv[0], '/'); prog = prog ? prog + 1 : argv[0];
    if (argc>1 && (!strcmp(argv[1],"--version") || !strcmp(argv[1],"-V"))) {
        printf("udev %s\n", UDEV_VERSION);
        return 0;
    }
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
    const char *query=NULL, *infoarg=NULL; int val_only=0, do_update=0;
    const char *tract="add"; int trsub=0;
    for (int i = argi; i<argc; i++) {
        if(!strcmp(argv[i],"--test")){ test=1; if(i+1<argc) testfile=argv[++i]; }
        else if(!strcmp(argv[i],"--rules")){ if(i+1<argc) snprintf(g_rulesdir,sizeof g_rulesdir,"%s",argv[++i]); }
        else if(!strcmp(argv[i],"--subsystem")){ if(i+1<argc) subsys=argv[++i]; }
        else if(!strcmp(argv[i],"--timeout")){ if(i+1<argc) timeout=atoi(argv[++i]); }
        else if(!strncmp(argv[i],"--timeout=",10)){ timeout=atoi(argv[i]+10); }
        else if(!strcmp(argv[i],"--db")){ if(i+1<argc) dbkey=argv[++i]; }
        else if(!strncmp(argv[i],"--db=",5)){ dbkey=argv[i]+5; }
        else if(!strcmp(argv[i],"-q") && i+1<argc){ query=argv[++i]; }
        else if(!strcmp(argv[i],"--exit")){ ctlact="exit"; }
        else if(!strcmp(argv[i],"--reload")){ ctlact="reload"; }
        else if(!strncmp(argv[i],"--action=",9)){ tract=argv[i]+9; }
        else if(!strcmp(argv[i],"--action") && i+1<argc){ tract=argv[++i]; }
        else if(!strncmp(argv[i],"--type=",7)){ trsub=!strcmp(argv[i]+7,"subsystems"); }
        else if(!strcmp(argv[i],"--type") && i+1<argc){ trsub=!strcmp(argv[++i],"subsystems"); }
        else if(!strcmp(cmd,"info") && argv[i][0]!='-'){ infoarg=argv[i]; }
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
    if (test && !strcmp(cmd,"daemon")) {
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
        char key[128];
        if (db_key(&ue,key,sizeof key))
            printf("[udev] apply: wrote %s/data/%s (%d rule(s) matched)\n",
                   rundir(), key, matched);
        else
            printf("[udev] apply: no device-DB key for this uevent (%d rule(s) matched)\n",
                   matched);
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
        char buf[8192];
        int rn=uevent_from_arg(arg, buf, sizeof buf);
        if (rn<0){ fprintf(stderr,"udev test: cannot read uevent from %s\n",arg); return 1; }
        uevent_t ue;
        if (ue_parse(buf,rn,&ue)<0){ fprintf(stderr,"udev test: failed to parse uevent\n"); return 1; }
        printf("[udev] test uevent: action=%s subsys=%s devname=%s devpath=%s\n",
               ue.action, ue.subsys, ue.devname, ue.devpath);
        g_test = 1; g_apply = 0;
        int matched = process_uevent(&ue);
        printf("[udev] test: %d rule(s) matched (dry-run, nothing written)\n", matched);
        return 0;
    }

    /* `udev test-builtin <builtin> <syspath|uevent-file>` — run one builtin
       against a device and print the environment it produces; nothing is
       written. Mirrors `udevadm test-builtin`. */
    if (!strcmp(cmd,"test-builtin")) {
        if (argc<4) { fprintf(stderr,"usage: udev test-builtin <builtin> <syspath|uevent-file>\n"); return 1; }
        const char *bn=argv[2], *arg=argv[3];
        if (strcmp(bn,"net_id") && strcmp(bn,"path_id") && strcmp(bn,"blkid")) {
            fprintf(stderr,"udev test-builtin: unknown builtin '%s' (supported: net_id, path_id, blkid)\n",bn);
            return 1;
        }
        char buf[8192];
        int rn=uevent_from_arg(arg, buf, sizeof buf);
        if (rn<0){ fprintf(stderr,"udev test-builtin: cannot read uevent from %s\n",arg); return 1; }
        uevent_t ue;
        if (ue_parse(buf,rn,&ue)<0){ fprintf(stderr,"udev test-builtin: failed to parse uevent\n"); return 1; }
        printf("[udev] test-builtin %s: action=%s subsys=%s devname=%s devpath=%s\n",
               bn, ue.action, ue.subsys, ue.devname, ue.devpath);
        g_test = 1; g_apply = 0;
        run_builtin(&ue, bn);
        printf("[udev] test-builtin: done (dry-run, nothing written)\n");
        return 0;
    }

    if (!strcmp(cmd,"daemon")) {
        signal(SIGHUP, on_sighup);
        struct sigaction sa; memset(&sa,0,sizeof sa);
        sa.sa_handler=on_sigterm;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGTERM,&sa,NULL);
        sigaction(SIGINT,&sa,NULL);
        int fd = netlink_setup();
        if (fd<0){ perror("netlink setup (need root/CAP_NET_ADMIN)"); return 1; }
        if (monitor_setup() < 0) fprintf(stderr, "warning: monitor rebroadcast unavailable\n");
        if (geteuid()==0 || getenv("UDEV_PIDFILE")){ FILE *pf=fopen(pidfile_path(),"w"); if(pf){ fprintf(pf,"%d",getpid()); fclose(pf); } }
        char buf[8192];
        while (!g_stop) {
            ssize_t n = recv(fd,buf,sizeof buf-1,0);
            if (n<=0) continue;
            uevent_t ue; if (ue_parse(buf,n,&ue)<0) continue;
            process_uevent(&ue);
            monitor_send(buf, n);
            if (g_reload) { rules_reload(g_rulesdir); g_reload=0; fprintf(stderr,"rules reloaded\n"); }
        }
        unlink(pidfile_path());
    } else if (!strcmp(cmd,"trigger")) {
        if (test) { printf("[trigger dry-run] would write '%s' to %s uevent files (subsys=%s)\n",
                          tract, trsub?"/sys/bus/*":"/sys/devices", subsys?subsys:"*"); return 0; }
        if (trsub) trigger_subsystems(tract); else trigger_walk("/sys/devices", tract);
        printf("trigger done\n");
        return 0;
    } else if (!strcmp(cmd,"settle")) {
        return cmd_settle(timeout);
    } else if (!strcmp(cmd,"info")) {
        char key[128];
        if (dbkey) snprintf(key,sizeof key,"%s",dbkey);
        else if (infoarg && db_key_from_path(infoarg,key,sizeof key)) { /* resolved */ }
        else { fprintf(stderr,"usage: udev info <devpath|--db=KEY> [-q property|name|symlink|path]\n"); return 1; }
        cmd_info(key, query, infoarg);
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
        fprintf(stderr,"usage: udev [daemon|trigger|settle|info|control|monitor|hwdb|apply|queue|verify|test|test-builtin] [options]\n");
        return 1;
    }
    return 0;
}
