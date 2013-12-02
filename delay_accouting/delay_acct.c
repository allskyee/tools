#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>

#include <linux/genetlink.h>
#include <linux/taskstats.h>
#include <linux/cgroupstats.h>

FILE* f;
#define PRINTF(fmt, arg...)     fprintf(f, fmt, ##arg)
#define ERROR(fmt, arg...)      fprintf(stderr, "[ERROR] " fmt, ##arg)

int pid_max = 0;
int get_pid_max()
{
    int fd, pid_max;
    char buf[64] = {0};

    //get pid_max
    if ((fd = open("/proc/sys/kernel/pid_max", O_RDONLY)) < 0) {
        ERROR("cannot read pid_max\n");
        return -1;
    }
    if (read(fd, &buf[0], sizeof(buf)) < 0) {
        ERROR("cannot read pid_max file\n");
        return -1;
    }
    pid_max = strtoul(buf, NULL, 10);
    if (pid_max == 0) {
        ERROR("cannot convert string [%s]\n", buf);
        return -1;
    }
    close(fd);

    return pid_max;
}

volatile int sig_int = 0;
void sig_int_cb(int signum)
{
    fprintf(stderr, "sigint\n");
    sig_int++;
}


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
// netlink auxilary functions
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

int rcvbufsz = 0; //use default

/* Create a raw netlink socket and bind */
int nl_sd;
static int create_nl_socket(int protocol)
{
    int fd;
    struct sockaddr_nl local;

    fd = socket(AF_NETLINK, SOCK_RAW, protocol);
    if (fd < 0)
        return -1;

    if (rcvbufsz)
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                &rcvbufsz, sizeof(rcvbufsz)) < 0) {
            ERROR("Unable to set socket rcv buf size to %d\n", rcvbufsz);
            goto error;
        }

    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;

    if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0)
        goto error;

    return fd;
error:
    close(fd);
    return -1;
}

#define MAX_MSG_SIZE    1024
/* Maximum number of cpus expected to be specified in a cpumask */
#define MAX_CPUS    32

struct msgtemplate {
    struct nlmsghdr n;
    struct genlmsghdr g;
    char buf[MAX_MSG_SIZE];
};

/* Generic macros for dealing with netlink sockets. Might be duplicated
 * elsewhere. It is recommended that commercial grade applications use
 * libnl or libnetlink and use the interfaces provided by the library */
#define GENLMSG_DATA(glh)   ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh)    (NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na)        ((void *)((char*)(na) + NLA_HDRLEN))
#define NLA_PAYLOAD(len)    (len - NLA_HDRLEN)

static int __send_cmd(int sd, __u16 nlmsg_type, __u32 nlmsg_pid,
         __u8 genl_cmd, __u16 nla_type,
         void *nla_data, int nla_len)
{
    struct nlattr *na;
    struct sockaddr_nl nladdr;
    int r, buflen;
    char *buf;

    struct msgtemplate msg;

    msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    msg.n.nlmsg_type = nlmsg_type;
    msg.n.nlmsg_flags = NLM_F_REQUEST;
    msg.n.nlmsg_seq = 0;
    msg.n.nlmsg_pid = nlmsg_pid;
    msg.g.cmd = genl_cmd;
    msg.g.version = 0x1;
    na = (struct nlattr *) GENLMSG_DATA(&msg);
    na->nla_type = nla_type;
    na->nla_len = nla_len + 1 + NLA_HDRLEN;
    memcpy(NLA_DATA(na), nla_data, nla_len);
    msg.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

    buf = (char *) &msg;
    buflen = msg.n.nlmsg_len ;
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    while ((r = sendto(sd, buf, buflen, 0, (struct sockaddr *) &nladdr,
               sizeof(nladdr))) < buflen) {
        if (r > 0) {
            buf += r;
            buflen -= r;
        } else if (errno != EAGAIN)
            return -1;
    }
    return 0;
}

/* Probe the controller in genetlink to find the family id
 * for the TASKSTATS family */
int my_pid;
int fam_id;
static int __get_family_id(int sd)
{
    struct {
        struct nlmsghdr n;
        struct genlmsghdr g;
        char buf[256];
    } ans;

    int id = 0, rc;
    struct nlattr *na;
    int rep_len;
    static char name[100];

    strcpy(name, TASKSTATS_GENL_NAME);
    rc = __send_cmd(sd, GENL_ID_CTRL, getpid(), CTRL_CMD_GETFAMILY,
            CTRL_ATTR_FAMILY_NAME, (void *)name,
            strlen(TASKSTATS_GENL_NAME)+1);
    if (rc < 0)
        return 0;   /* sendto() failure? */

    rep_len = recv(sd, &ans, sizeof(ans), 0);
    if (ans.n.nlmsg_type == NLMSG_ERROR ||
        (rep_len < 0) || !NLMSG_OK((&ans.n), rep_len))
        return 0;

    na = (struct nlattr *) GENLMSG_DATA(&ans);
    na = (struct nlattr *) ((char *) na + NLA_ALIGN(na->nla_len));
    if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
        id = *(__u16 *) NLA_DATA(na);
    }
    return id;
}

static int send_cmd(__u8 genl_cmd, __u16 nla_type, void *nla_data, int nla_len)
{
    return __send_cmd(nl_sd, fam_id, my_pid, genl_cmd, nla_type, nla_data, nla_len);
}


#define average_ms(t, c) (t / 1000000ULL / (c ? c : 1))

void print_delayacct(struct taskstats* t)
{
    PRINTF("\n\nCPU   %15s%15s%15s%15s%15s\n"
           "      %15llu%15llu%15llu%15llu%15.3fms\n"
           "IO    %15s%15s%15s\n"
           "      %15llu%15llu%15llums\n"
           "SWAP  %15s%15s%15s\n"
           "      %15llu%15llu%15llums\n"
           "RECLAIM  %12s%15s%15s\n"
           "      %15llu%15llu%15llums\n",
           "count", "real total", "virtual total",
           "delay total", "delay average",
            //CPU
           (unsigned long long)t->cpu_count,
           (unsigned long long)t->cpu_run_real_total,
           (unsigned long long)t->cpu_run_virtual_total,
           (unsigned long long)t->cpu_delay_total,
           average_ms((double)t->cpu_delay_total, t->cpu_count),
           "count", "delay total", "delay average",
           (unsigned long long)t->blkio_count,
           (unsigned long long)t->blkio_delay_total,
           average_ms(t->blkio_delay_total, t->blkio_count),
           "count", "delay total", "delay average",
           (unsigned long long)t->swapin_count,
           (unsigned long long)t->swapin_delay_total,
           average_ms(t->swapin_delay_total, t->swapin_count),
           "count", "delay total", "delay average",
           (unsigned long long)t->freepages_count,
           (unsigned long long)t->freepages_delay_total,
           average_ms(t->freepages_delay_total, t->freepages_count));
}

static void print_ioacct(struct taskstats *t)
{
    PRINTF("%s: read=%llu %llu, write=%llu %llu, cancelled_write=%llu\n",
        t->ac_comm,
        (unsigned long long)t->read_bytes,
        (unsigned long long)t->read_char,
        (unsigned long long)t->write_bytes,
        (unsigned long long)t->write_char,
        (unsigned long long)t->cancelled_write_bytes);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
// proc info
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

struct proc_info {
    struct taskstats t;
    struct taskstats* tg_t;
    int tgid;
    int pid;
    int updated:1;
};

struct proc_info* alloc_proc_info()
{
    struct proc_info* info = malloc(sizeof(*info));
    if (!info)
        return NULL;
    memset(info, 0, sizeof(*info));
    return info;
}

void free_proc_info(struct proc_info* info)
{
    free(info);
}

void print_taskstats(struct taskstats* t)
{
    __u64 cpu_delay = t->cpu_delay_total;
    __u64 cpu_run = t->cpu_run_real_total;
    __u64 utime = t->ac_utime;
    __u64 stime = t->ac_stime;

    //if (!(cpu_delay | cpu_run | utime | stime))
    //    return;

    if (t->ac_pid) //pid 0 is meaningless
        PRINTF("%s,%d,%d,%d,%lld\n", t->ac_comm, t->ac_pid, t->ac_ppid, 
            t->ac_btime, t->ac_etime);
    PRINTF(" cpu %llu, user %llu, system %llu\n",  
        (unsigned long long)t->cpu_run_real_total / 1000, 
        (unsigned long long)t->ac_utime, 
        (unsigned long long)t->ac_stime);
    PRINTF(" read_ch %llu, read_sys %llu, write_ch %llu, write_sys %llu\n", 
        (unsigned long long)t->read_char, 
        (unsigned long long)t->read_syscalls, 
        (unsigned long long)t->write_char, 
        (unsigned long long)t->write_syscalls);
    PRINTF(" read_byte %lld, write_bytes %lld, write_cancel %lld\n", 
        t->read_bytes, t->write_bytes, t->cancelled_write_bytes);
    PRINTF(" cpuwait %lld, blkio %lld, swapin %lld, freepages %lld, nvcsw %lld, nivcsw %lld\n", 
        t->cpu_delay_total, t->blkio_delay_total, t->swapin_delay_total, t->freepages_delay_total,
        t->nvcsw, t->nivcsw);

    /*
     * cpu_run_real_total(ns) : cpu "wall-clock" running time 
     * ac_utime (us) : user cpu time
     * ac_stime (us) : system cpu time
     *
     * read_char, bytes write, read_syscalls, write_syscalls
     * read_bytes, write_bytes, cancelled_write_bytes
     * 
     * cpu_delay_total (ns) : Delay waiting for cpu, while runnable
     * blkio_delay_total : Delay waiting for synchronous block I/O to complete
     *                     does not account for delays in I/O submission
     * swapin_delay_total : Delay waiting for page fault I/O
     * freepages_delay_total : delay waiting for memory reclaim
     * nvcsw : voluntary_ctxt_switches
     * nivcsw : nonvoluntary_ctxt_switches 
     */
}

void diff_taskstats(struct taskstats* res, struct taskstats* t1, struct taskstats* t2)
{
#define T_DIFF(name)    res->name = (t1->name - t2->name)
#define T_ASSIGN(name)  res->name = t1->name
    T_DIFF(cpu_delay_total);
    T_DIFF(cpu_run_real_total);
    T_DIFF(ac_utime);
    T_DIFF(ac_stime);
    T_DIFF(read_char);
    T_DIFF(write_char);
    T_DIFF(read_syscalls);
    T_DIFF(write_syscalls);
    T_DIFF(read_bytes);
    T_DIFF(write_bytes);
    T_DIFF(cancelled_write_bytes);
    T_DIFF(cpu_delay_total);
    T_DIFF(blkio_delay_total);
    T_DIFF(swapin_delay_total);
    T_DIFF(freepages_delay_total);
    T_DIFF(nvcsw);
    T_ASSIGN(ac_pid);
    T_ASSIGN(ac_ppid);
    T_ASSIGN(ac_btime);
    res->ac_etime = t1->ac_etime;
    memcpy(&res->ac_comm, &t1->ac_comm, sizeof(t1->ac_comm));
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
// main loop
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

int recv_taskstats(int recv_flags, struct proc_info** infos)
{
    int rep_len, len, aggr_len, len2;
    struct msgtemplate msg;
    struct nlattr* na;
    __u32 tgid = 0, pid = 0;

//recv :
    if ((rep_len = recv(nl_sd, &msg, sizeof(msg), recv_flags)) < 0) { //MSG_DONTWAIT
        //if (errno == EAGAIN) {
        //    usleep(10000);
        //    goto recv;
        //}
        //if (!(recv_flags | MSG_DONTWAIT) && rep_len == -1) {
        //}

        if ((recv_flags & MSG_DONTWAIT) && errno == EAGAIN)
            return -EAGAIN;

        ERROR("receive error %d %d\n", rep_len, errno);
        return rep_len;
    }

    //check if packet is error
    if (msg.n.nlmsg_type == NLMSG_ERROR ||
        !NLMSG_OK((&msg.n), rep_len)) {
        struct nlmsgerr* err = NLMSG_DATA(&msg);
        ERROR("fatal reply error, errno %d\n", err->error);
        return -1;
    }

    rep_len = GENLMSG_PAYLOAD(&msg.n);
    na = (struct nlattr*)GENLMSG_DATA(&msg);
    len = 0;
    
    while (len < rep_len) {
        len += NLA_ALIGN(na->nla_len);

        switch (na->nla_type) {
        case TASKSTATS_TYPE_AGGR_TGID:
            // fall through
        case TASKSTATS_TYPE_AGGR_PID:
            aggr_len = NLA_PAYLOAD(na->nla_len);
            len2 = 0;
            na = (struct nlattr*)NLA_DATA(na);

            while (len2 < aggr_len) {
                switch (na->nla_type) {
                case TASKSTATS_TYPE_PID:
                    pid = *(int*)NLA_DATA(na);
                    tgid = 0;
                    break;
                case TASKSTATS_TYPE_TGID:
                    tgid = *(int*)NLA_DATA(na);
                    pid = 0;
                    break;
                case TASKSTATS_TYPE_STATS:
                    if (tgid) {
                        break;
                    }

                    if (!infos[pid] && !(infos[pid] = alloc_proc_info())) {
                        ERROR("unable to allocate memory\n");
                        return -ENOMEM;
                    }
                    memcpy(&infos[pid]->t, (struct taskstats*)NLA_DATA(na), 
                        sizeof(struct taskstats));
                    infos[pid]->updated = 1;

                    //print_delayacct(NLA_DATA(na));
                    //print_ioacct(NLA_DATA(na));
                    break;
                default :
                    ERROR("unknown nested nla_type %d\n", na->nla_type);
                    break;
                }
                len2 += NLA_ALIGN(na->nla_len);
                na = (struct nlattr*)((char*)na + len2);
            } //end of while for TASKSTATS_TYPE_AGGR_PID packet analysis
            break;

        case CGROUPSTATS_TYPE_CGROUP_STATS:
            PRINTF("cgroup\n"); break;
        default :
            PRINTF("default %d\n", msg.n.nlmsg_type);
        case TASKSTATS_TYPE_NULL:
            break;
        } //end of switch clause

        na = (struct nlattr*)(GENLMSG_DATA(&msg) + len);
    } //end of while loop for recv'ed packet analysis

    return 0;
}

int fill_infos(struct proc_info** infos)
{
    DIR* dirp, *ddirp;
    struct dirent* dptr, *ddptr;
    __u32 pid, tid;
    int ret = -1;
    static char path[32];

    if ((dirp = opendir("/proc")) == NULL) {
        ERROR("unable to open proc \n");
        return -1;
    }

    while (dptr = readdir(dirp)) {
        char* endp;

        pid = strtoul(dptr->d_name, &endp, 10);
        if (*endp != '\0')
            continue;

        snprintf(path, sizeof(path), "/proc/%s/task/", dptr->d_name);
        if ((ddirp = opendir(path)) == NULL) {
            ERROR("Unable to open task dir\n");
            goto close;
        }

        while (ddptr = readdir(ddirp)) {
            if (strcmp(ddptr->d_name, ".") == 0 ||
                strcmp(ddptr->d_name, "..") == 0)
                continue;
            tid = strtoul(ddptr->d_name, &endp, 10);
            if (*endp != '\0') {
                ERROR("huh? %s\n", ddptr->d_name);
                goto close;
            }

            if (!(infos[tid] = alloc_proc_info())) {
                ERROR("Unable to alloc memory\n");
                goto close;
            }
            infos[tid]->tgid = pid;
            infos[tid]->pid = tid;
        }
    }
    ret = 0;

close : 
    closedir(dirp);
    dirp = NULL;
    if (ret) 
        return ret;

    for (tid = 0; tid < pid_max; tid++) {
        if (!infos[tid])
            continue;
        if (infos[tid]->updated)
            continue;

        if (tid && (ret = send_cmd(TASKSTATS_CMD_GET, TASKSTATS_CMD_ATTR_PID, \
            &tid, sizeof(__u32))) < 0) {
            ERROR("unable to send cmd to tid [%d]\n", tid);
            goto out;
        }

    retry : 
        if ((ret = recv_taskstats(0, infos)) < 0) {  //MSG_DONTWAIT
            goto out;
        }

        if (!infos[tid]->updated)
            goto retry;
    }

out : 
    return ret;
}

struct proc_info* infos1[32768] = {0};
struct proc_info* infos2[32768] = {0};

int main(int argc, char* argv[])
{
    int c, ret = -1;
    char* log_file = NULL;
    char* cpu_mask = NULL;
    int rc, mode = 0, tid;

    while ((c = getopt(argc, argv, "c:l:m:")) != -1) {
        switch(c) {
        case 'l' :
            log_file = strdup(optarg);
            break;
        case 'c' :
            cpu_mask = strdup(optarg);
            break;
        case 'm' :
            if (strcmp(optarg, "1") == 0)
                mode = 1;
            else if (strcmp(optarg, "2") == 0)
                mode = 2;
            else if (strcmp(optarg, "3") == 0)
                mode = 3;
            break;
        default :
            fprintf(stderr, "unknown option %c\n", c);
            exit(-1);
        }
    }

    /*
     * checking an dealing with input parameters
     */
    if (log_file) {
        if (!(f = fopen(log_file, "w"))) {
            fprintf(stderr, "cannot open file\n");
            goto out;
        }
    }
    else {
        f = stdout;
    }

    if (!mode) {
        ERROR("must specify mode\n");
        goto out;
    }

    if (!cpu_mask) {
        ERROR("need to specify CPU type\n");
        goto out;
    }

    /*
     * setting up system stuff
     */
    if ((pid_max = get_pid_max()) < 0) {
        ERROR("unable to get pid_max\n");
        goto out;
    }

    PRINTF("pid_max is %d\n", pid_max);
    
    signal(SIGINT, sig_int_cb);
    if ((nl_sd = create_nl_socket(NETLINK_GENERIC)) < 0) {
        ERROR("error creating Netlink socket\n");
        goto out;
    }

    /*
     * register taskstats notifier
     */
    fam_id = __get_family_id(nl_sd);
    if (!fam_id) {
        ERROR("Error getting family id, errno %d\n", errno);
        goto out;
    }

    my_pid = getpid();
    if ((rc = send_cmd(TASKSTATS_CMD_GET,
        TASKSTATS_CMD_ATTR_REGISTER_CPUMASK, cpu_mask, strlen(cpu_mask))) < 0) {
        ERROR("error sending register cpumask\n");
        goto out;
    }

    /*
     * now for the main loop
     * modes of operations 
     * i) get all process stats and print
     * ii) wait until receive signal (be polling for dead process in meantime)
     *     then get all process stats
     * iii) get all process stats, then wait for signal and print diff
     */
    if (mode == 1) {
        fill_infos(infos1);
        for (tid = 0; tid < pid_max; tid++) {
            if (!infos1[tid])
                continue;
            print_taskstats(&infos1[tid]->t);
        }
    }
    else if (mode == 2) {
        PRINTF("waiting for signal\n");
        while (!sig_int)
            sleep(1);
        fill_infos(infos1);
        for (tid = 0; tid < pid_max; tid++) {
            if (!infos1[tid])
                continue;
            print_taskstats(&infos1[tid]->t);
        }
    }
    else if (mode == 3) {
        struct timeval start_since_epoch;
        struct timespec start, end;
        static struct taskstats ts_tot = {0};

        if (fill_infos(infos1) < 0) {
            ERROR("error before start\n");
            goto out;
        }

        if (clock_gettime(CLOCK_MONOTONIC, &start) < 0) {
            ERROR("unable to get start time\n");
            goto out;
        }

        if (gettimeofday(&start_since_epoch, NULL)) { 
            ERROR("unable to get start time since epoch\n");
            goto out;
        }

        PRINTF("waiting for signal\n");
        while (!sig_int) {
            ret = recv_taskstats(MSG_DONTWAIT, infos2);

            if (ret == 0 || ret == -EAGAIN) {
                usleep(10000);
                continue;
            }

            ERROR("unable to recv taskstats, %d\n", ret);
            goto out;
        }

        if (fill_infos(infos2) < 0) {
            ERROR("error at end\n");
            goto out;
        }
        if (clock_gettime(CLOCK_MONOTONIC, &end) < 0) {
            ERROR("unable to get end time\n");
            goto out;
        }

        PRINTF("--- task dump start ---\n");

        for (tid = 0; tid < pid_max; tid++) {
            struct proc_info* p1 = infos1[tid];
            struct proc_info* p2 = infos2[tid];

            if (!(p1 || p2))
                continue;
            else if (p1 && p2) {
                static struct taskstats ts;
                diff_taskstats(&ts, &p2->t, &p1->t);
                print_taskstats(&ts);
            }
            else if (p2) {
                print_taskstats(&p2->t);
            }
        }
        PRINTF("--- task dump end ---\n");

        PRINTF("Start since epoch (s) %d\n", start_since_epoch.tv_sec);
        PRINTF("Elapsed time (ns) %llu\n",
            ((long long)end.tv_sec - start.tv_sec) * 1000000000LL +
            end.tv_nsec - start.tv_nsec);
    }

out : 
    if (f != stdout)
        fclose(f);

    return ret;
}
