#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>

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
} rule_t;

typedef struct { rule_t *r; int n, cap; } ruleset_t;
static ruleset_t RS;
static const char *g_rulesdir = "rules";

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
    char path[512];
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
        char *tok = strtok(s," \t,");
        while (tok) {
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
                    if (cur.nasg<RL_MAX_ASG){
                        snprintf(cur.a_key[cur.nasg],40,"%s",key);
                        snprintf(cur.a_op[cur.nasg],3,"%s",op);
                        snprintf(cur.a_val[cur.nasg],160,"%s",val);
                        cur.nasg++;
                    }
                }
            }
            tok = strtok(NULL," \t,");
        }
        if (cur.nmatch || cur.nasg) rules_add(&cur);
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

/* ===================== actions ===================== */
static int g_test=0;
static void apply_rule(rule_t *r, uevent_t *ue) {
    char mode[16]="", owner[64]="", group[64]="", linkname[160]="";
    ue->ntags = 0;
    for (int i=0;i<r->nasg;i++){
        if(!strcmp(r->a_key[i],"MODE"))  snprintf(mode,sizeof mode,"%s",r->a_val[i]);
        else if(!strcmp(r->a_key[i],"OWNER")) snprintf(owner,sizeof owner,"%s",r->a_val[i]);
        else if(!strcmp(r->a_key[i],"GROUP")) snprintf(group,sizeof group,"%s",r->a_val[i]);
        else if(!strcmp(r->a_key[i],"SYMLINK")) snprintf(linkname,sizeof linkname,"%s",r->a_val[i]);
        else if(!strcmp(r->a_key[i],"TAG")) { if(ue->ntags<16) snprintf(ue->tags[ue->ntags++],64,"%s",r->a_val[i]); }
        /* RUN/PROGRAM/IMPORT/GOTO -> milestone TODO */
    }
    if(!ue->devname[0]) return;
    char path[512]; snprintf(path,sizeof path,"/dev/%s",ue->devname);
    const char *km = mode[0]? mode : ue_getenv(ue,"MODE");
    unsigned perm = km? (unsigned)strtol(km,NULL,8) : 0600;
    printf("[udev] %s action=%s node=%s mode=%o owner=%s group=%s\n",
        g_test?"TEST":"APPLY", ue->action, path, perm,
        owner[0]?owner:"(kernel)", group[0]?group:"(kernel)");
    if (linkname[0]) printf("       symlink -> /dev/%s\n", linkname);
    if (ue->ntags) { printf("       tags:"); for(int t=0;t<ue->ntags;t++) printf(" %s",ue->tags[t]); printf("\n"); }
    if (g_test) return;
    char *slash=strrchr(path,'/');
    if (slash && slash!=path){ *slash=0; mkdir(path,0755); *slash='/'; }
    if (mknod(path, S_IFCHR|perm, makedev(ue->major,ue->minor))<0)
        printf("       mknod failed: %s\n", strerror(errno));
    else {
        uid_t u=0; gid_t g=0;
        if(owner[0]){ struct passwd *pw=getpwnam(owner); if(pw) u=pw->pw_uid; }
        if(group[0]){ struct group *gr=getgrnam(group); if(gr) g=gr->gr_gid; }
        chown(path,u,g);
    }
    if (linkname[0]) {
        char sp[512]; snprintf(sp,sizeof sp,"/dev/%s",linkname);
        char *ss=strrchr(sp,'/'); if(ss&&ss!=sp){*ss=0; mkdir(sp,0755); *ss='/';}
        symlink(path, sp);
    }
}

/* ===================== device DB ===================== */
static void db_write(uevent_t *ue) {
    if (g_test) return;
    if (ue->major==0 && ue->minor==0) return;
    char path[256];
    snprintf(path, sizeof path, "/run/udev/data/c%d:%d", ue->major, ue->minor);
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
    char path[256];
    snprintf(path, sizeof path, "/run/udev/data/c%d:%d", ue->major, ue->minor);
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
static void on_sighup(int s){ (void)s; g_reload = 1; }

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
    char path[256]; snprintf(path,sizeof path,"/run/udev/data/%s",dbkey);
    FILE *f=fopen(path,"r"); if(!f){ printf("no DB entry for %s\n",dbkey); return; }
    char line[512];
    while (fgets(line,sizeof line,f)) fputs(line,stdout);
    fclose(f);
}
static void cmd_control(const char *action) {
    if (!strcmp(action,"reload")) {
        FILE *p=fopen("/run/udev.pid","r");
        if(p){ int pid; fscanf(p,"%d",&pid); fclose(p); kill(pid,SIGHUP); printf("sent SIGHUP to %d\n",pid); }
        else printf("no daemon pidfile (/run/udev.pid)\n");
    } else printf("unknown control action: %s\n",action);
}

/* ===================== main ===================== */
int main(int argc, char **argv) {
    const char *cmd = (argc>1 && argv[1][0]!='-') ? argv[1] : "daemon";
    int test=0; const char *testfile=NULL, *subsys=NULL, *dbkey=NULL, *ctlact="reload";
    int timeout=120;
    for (int i = (strcmp(cmd,"daemon")==0)?1:2; i<argc; i++) {
        if(!strcmp(argv[i],"--test")){ test=1; if(i+1<argc) testfile=argv[++i]; }
        else if(!strcmp(argv[i],"--rules")){ if(i+1<argc) g_rulesdir=argv[++i]; }
        else if(!strcmp(argv[i],"--subsystem")){ if(i+1<argc) subsys=argv[++i]; }
        else if(!strcmp(argv[i],"--timeout")){ if(i+1<argc) timeout=atoi(argv[++i]); }
        else if(!strcmp(argv[i],"--db")){ if(i+1<argc) dbkey=argv[++i]; }
        else if(!strcmp(argv[i],"--action")){ /* reserved */ }
    }
    g_test = test;
    load_dir(g_rulesdir);

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
        int matched = 0;
        for (int i = 0; i < RS.n; i++)
            if (rule_matches(&RS.r[i], &ue)) { apply_rule(&RS.r[i], &ue); matched++; }
        printf("[udev] %d rule(s) matched\n", matched);
        return 0;
    }

    if (!strcmp(cmd,"daemon")) {
        signal(SIGHUP, on_sighup);
        int fd = netlink_setup();
        if (fd<0){ perror("netlink setup (need root/CAP_NET_ADMIN)"); return 1; }
        if (monitor_setup() < 0) fprintf(stderr, "warning: monitor rebroadcast unavailable\n");
        if (geteuid()==0){ FILE *pf=fopen("/run/udev.pid","w"); if(pf){ fprintf(pf,"%d",getpid()); fclose(pf); } }
        char buf[8192];
        for (;;) {
            ssize_t n = recv(fd,buf,sizeof buf-1,0);
            if (n<=0) continue;
            uevent_t ue; if (ue_parse(buf,n,&ue)<0) continue;
            int is_add = strcmp(ue.action,"remove")!=0;
            if (is_add) g_pending++;
            for (int i=0;i<RS.n;i++) if (rule_matches(&RS.r[i],&ue)) apply_rule(&RS.r[i],&ue);
            monitor_send(buf, n);
            if (!strcmp(ue.action,"remove")) db_remove(&ue); else db_write(&ue);
            if (is_add && g_pending>0) g_pending--;
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
    } else {
        fprintf(stderr,"unknown command: %s\n",cmd);
        fprintf(stderr,"usage: udev [daemon|trigger|settle|info|control] [options]\n");
        return 1;
    }
    return 0;
}
