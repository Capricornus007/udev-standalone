#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <pwd.h>
#include <grp.h>

/* ===================== uevent ===================== */
#define UE_MAX_ENV 96
#define UE_ENV_LEN 160
typedef struct {
    char action[32];
    char devpath[320];
    char subsys[64];
    char devname[128];
    int  major, minor;
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
        actual=NULL; /* milestone: ATTR lookup not yet implemented */
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
    char mode[16]="", owner[64]="", group[64]="";
    for (int i=0;i<r->nasg;i++){
        if(!strcmp(r->a_key[i],"MODE"))  snprintf(mode,sizeof mode,"%s",r->a_val[i]);
        else if(!strcmp(r->a_key[i],"OWNER")) snprintf(owner,sizeof owner,"%s",r->a_val[i]);
        else if(!strcmp(r->a_key[i],"GROUP")) snprintf(group,sizeof group,"%s",r->a_val[i]);
        /* SYMLINK/RUN/PROGRAM/IMPORT/GOTO -> milestone TODO */
    }
    if(!ue->devname[0]) return;
    char path[512]; snprintf(path,sizeof path,"/dev/%s",ue->devname);
    const char *km = mode[0]? mode : ue_getenv(ue,"MODE");
    unsigned perm = km? (unsigned)strtol(km,NULL,8) : 0600;
    printf("[udevd] %s action=%s node=%s mode=%o owner=%s group=%s\n",
        g_test?"TEST":"APPLY", ue->action, path, perm,
        owner[0]?owner:"(kernel)", group[0]?group:"(kernel)");
    if (g_test) return;
    char *slash=strrchr(path,'/');
    if (slash && slash!=path){ *slash=0; mkdir(path,0755); *slash='/'; }
    if (mknod(path, S_IFCHR|perm, makedev(ue->major,ue->minor))<0)
        printf("        mknod failed: %s\n", strerror(errno));
    else {
        uid_t u=0; gid_t g=0;
        if(owner[0]){ struct passwd *pw=getpwnam(owner); if(pw) u=pw->pw_uid; }
        if(group[0]){ struct group *gr=getgrnam(group); if(gr) g=gr->gr_gid; }
        chown(path,u,g);
    }
}

/* ===================== netlink ===================== */
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

/* persistent device database, udev-compatible layout under /run/udev/data/ */
static void db_write(uevent_t *ue) {
    if (g_test) return;
    if (ue->major==0 && ue->minor==0) return;
    char path[256];
    snprintf(path, sizeof path, "/run/udev/data/c%d:%d", ue->major, ue->minor);
    FILE *f = fopen(path,"w");
    if (!f) return;
    for (int i=0;i<ue->nenv;i++) fprintf(f, "E:%s\n", ue->env[i]);
    fclose(f);
}
static void db_remove(uevent_t *ue) {
    if (g_test) return;
    if (ue->major==0 && ue->minor==0) return;
    char path[256];
    snprintf(path, sizeof path, "/run/udev/data/c%d:%d", ue->major, ue->minor);
    unlink(path);
}

/* ===================== main ===================== */
int main(int argc, char **argv) {
    int test=0; const char *testfile=NULL;
    for (int i=1;i<argc;i++){
        if(!strcmp(argv[i],"--test")){ test=1; if(i+1<argc) testfile=argv[++i]; }
    }
    g_test = test;
    load_file("rules/example.rules"); /* milestone: load full dir later */

    if (test) {
        FILE *f = testfile? fopen(testfile,"r") : stdin;
        if (!f){ perror("test file"); return 1; }
        char buf[8192]; size_t total=0; int c;
        /* convert newlines to NULs so the file uses the kernel uevent layout */
        while ((c=fgetc(f))!=EOF && total<sizeof buf-1) { if(c=='\n') c='\0'; buf[total++]=(char)c; }
        fclose(f);
        uevent_t ue; ue_parse(buf,total,&ue);
        printf("action=%s devpath=%s subsys=%s devname=%s major=%d minor=%d\n",
               ue.action,ue.devpath,ue.subsys,ue.devname,ue.major,ue.minor);
        int matched=0;
        for (int i=0;i<RS.n;i++) if (rule_matches(&RS.r[i],&ue)) {
            matched++; printf("  matched rule #%d\n",i); apply_rule(&RS.r[i],&ue);
        }
        if(!matched) printf("  (no rule matched)\n");
        return 0;
    }

    int fd = netlink_setup();
    if (fd<0){ perror("netlink setup (need root/CAP_NET_ADMIN)"); return 1; }
    if (monitor_setup() < 0) fprintf(stderr, "warning: monitor rebroadcast unavailable\n");
    char buf[8192];
    for (;;) {
        ssize_t n = recv(fd,buf,sizeof buf-1,0);
        if (n<=0) continue;
        uevent_t ue; if (ue_parse(buf,n,&ue)<0) continue;
        for (int i=0;i<RS.n;i++) if (rule_matches(&RS.r[i],&ue)) apply_rule(&RS.r[i],&ue);
        monitor_send(buf, n);
        if (!strcmp(ue.action,"remove")) db_remove(&ue); else db_write(&ue);
    }
}
