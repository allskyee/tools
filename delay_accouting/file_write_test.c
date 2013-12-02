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

#define PRINTF(fmt, arg...)     fprintf(stdout, fmt, ##arg)
#define ERROR(fmt, arg...)      fprintf(stderr, "[ERROR] " fmt, ##arg)

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

int __send_cmd(int sd, __u16 nlmsg_type, __u32 nlmsg_pid,
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
int __get_family_id(int sd)
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

int init_delay_acct(void) 
{
    if ((nl_sd = create_nl_socket(NETLINK_GENERIC)) < 0) {
        ERROR("error creating Netlink socket\n");
        return -1;
    }

    fam_id = __get_family_id(nl_sd);
    if (!fam_id) {
        ERROR("Error getting family id, errno %d\n", errno);
        return -1;
    }

    my_pid = getpid();

    return 0;
}

int send_cmd(__u8 genl_cmd, __u16 nla_type, void *nla_data, int nla_len)
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

void print_ioacct(struct taskstats *t)
{
    PRINTF("%s: read=%llu %llu, write=%llu %llu, cancelled_write=%llu\n",
        t->ac_comm,
        (unsigned long long)t->read_bytes,
        (unsigned long long)t->read_char,
        (unsigned long long)t->write_bytes,
        (unsigned long long)t->write_char,
        (unsigned long long)t->cancelled_write_bytes);
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
    T_DIFF(blkio_delay_total);
    T_DIFF(swapin_delay_total);
    T_DIFF(freepages_delay_total);
    T_DIFF(nvcsw);
    T_DIFF(nivcsw);
    T_ASSIGN(ac_pid);
    T_ASSIGN(ac_ppid);
    T_ASSIGN(ac_btime);
    //res->ac_etime = t1->ac_etime;
    T_DIFF(ac_etime);
    memcpy(&res->ac_comm, &t1->ac_comm, sizeof(t1->ac_comm));
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
        printf("%s,%d,%d,%d,%lld\n", t->ac_comm, t->ac_pid, t->ac_ppid, 
            t->ac_btime, t->ac_etime);
    printf(" cpu %llu, user %llu, system %llu\n",  
        (unsigned long long)t->cpu_run_real_total / 1000, 
        (unsigned long long)t->ac_utime, 
        (unsigned long long)t->ac_stime);
    printf(" read_ch %llu, read_sys %llu, write_ch %llu, write_sys %llu\n", 
        (unsigned long long)t->read_char, 
        (unsigned long long)t->read_syscalls, 
        (unsigned long long)t->write_char, 
        (unsigned long long)t->write_syscalls);
    printf(" read_byte %lld, write_bytes %lld, write_cancel %lld\n", 
        t->read_bytes, t->write_bytes, t->cancelled_write_bytes);
    printf(" cpuwait %lld, blkio %lld, swapin %lld, freepages %lld, nvcsw %lld, nivcsw %lld\n", 
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

void print_taskstats2(struct taskstats* t)
{
    printf("%s,%d,%d,%d,%lld\n", t->ac_comm, t->ac_pid, t->ac_ppid, 
            t->ac_btime, t->ac_etime);
    printf(" cpu %llu\n", (unsigned long long)t->cpu_run_real_total / 1000);
    printf(" user %llu\n", (unsigned long long)t->ac_utime);
    printf(" system %llu\n", (unsigned long long)t->ac_stime);

    printf(" read_ch %llu\n", (unsigned long long)t->read_char);
    printf(" read_sys %llu\n", (unsigned long long)t->read_syscalls);
    printf(" write_ch %llu\n", (unsigned long long)t->write_char);
    printf(" write_sys %llu\n", (unsigned long long)t->write_syscalls);
        
    printf(" read_byte %lld\n", t->read_bytes);
    printf(" write_bytes %lld\n", t->write_bytes);
    printf(" write_cancel %lld\n", t->cancelled_write_bytes);
    
    printf(" cpuwait %lld\n", t->cpu_delay_total);
    printf(" blkio %lld\n", t->blkio_delay_total);
    printf(" swapin %lld\n", t->swapin_delay_total);
    printf(" freepages %lld\n", t->freepages_delay_total);
    printf(" nvcsw %lld\n", t->nvcsw);
    printf(" nivcsw %lld\n", t->nivcsw);
}

int get_delay_acct(__u32 tid, struct taskstats* t)
{
    int ret;   
    int rep_len, len, aggr_len, len2;
    struct msgtemplate msg;
    struct nlattr* na;
    __u32 tgid = 0, pid = 0;

    if ((ret = send_cmd(TASKSTATS_CMD_GET, TASKSTATS_CMD_ATTR_PID, \
            &tid, sizeof(__u32))) < 0) {
        ERROR("unable to send cmd to tid [%d] ret [%d]\n", tid, ret);
        return ret;
    }

    if ((rep_len = recv(nl_sd, &msg, sizeof(msg), 0)) < 0) { //MSG_DONTWAIT
        ERROR("receive error %d %d\n", rep_len, errno);
        return rep_len;
    }

    //check if packet is error
    if (msg.n.nlmsg_type == NLMSG_ERROR ||
        !NLMSG_OK((&msg.n), rep_len)) {
        struct nlmsgerr* err = NLMSG_DATA(&msg);
        ERROR("fatal reply error, errno %d\n", err->error);
        return -(err->error);
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
                    if (pid != tid) {
                        ERROR("huh? recv pid %d\n", pid);
                        return -1;
                    }
                    break;
                case TASKSTATS_TYPE_TGID:
                    ERROR("huh? why tgid?\n");
                    return -1;
                case TASKSTATS_TYPE_STATS:
                    memcpy(t, (struct taskstats*)NLA_DATA(na), 
                        sizeof(struct taskstats));
                    break;
                default :
                    ERROR("unknown nested nla_type %d\n", na->nla_type);
                    return -1;
                }
                len2 += NLA_ALIGN(na->nla_len);
                na = (struct nlattr*)((char*)na + len2);
            } //end of while for TASKSTATS_TYPE_AGGR_PID packet analysis
            break;

        case CGROUPSTATS_TYPE_CGROUP_STATS:
            PRINTF("cgroup\n"); 
            return -1;
        default :
            PRINTF("default %d\n", msg.n.nlmsg_type);
            return -1;
        case TASKSTATS_TYPE_NULL:
            PRINTF("type null \n", msg.n.nlmsg_type);
            return -1;
        } //end of switch clause

        na = (struct nlattr*)(GENLMSG_DATA(&msg) + len);
    } //end of while loop for recv'ed packet analysis

    return 0;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
// main function
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

int main(int argc, char* argv[])
{
    if (argc < 4) { 
        fprintf(stderr, "usage : ./file_write [name] [recl] [count]\n");
        return -1;
    }

    /* 
     * init delay accouting stuff
     */
    if (init_delay_acct()) {
        return -1;
    }

    /* 
     * perform test
     */

    const char* name = argv[1];
    int recl = atoi(argv[2]);
    int rec_size = recl << 10;
    int count = atoi(argv[3]);

    struct taskstats t_open, t_write_start, t_write_end;

    printf("file write [%s] %d %d\n", name, recl, count);

    char* p = malloc(rec_size);
    memset(p, 0, rec_size);

    if (get_delay_acct(my_pid, &t_open)) {
        ERROR("unable to get delay acct for me at start\n");
        return -1;
    }

    int fd = open(name, O_WRONLY | O_CREAT, 
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    if (fd < 0) {
        fprintf(stderr, "unable to open file for write %d\n", errno);
        return -1;
    }

    struct timespec start, end;

    if (get_delay_acct(my_pid, &t_write_start)) {
        ERROR("unable to get delay acct for me at start\n");
        return -1;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &start) < 0) {
        fprintf(stderr, "unable to get start time\n");
        return -1;
    }

    while (count--) {
        if (write(fd, p, rec_size) != rec_size) {
            fprintf(stderr, "unable to write\n");
            return -1;
        }
    }

    if (clock_gettime(CLOCK_MONOTONIC, &end) < 0) {
        fprintf(stderr, "unable to get start time\n");
        return -1;
    }

    if (get_delay_acct(my_pid, &t_write_end)) {
        ERROR("unable to get delay acct for me at end\n");
        return -1;
    }

    diff_taskstats(&t_open, &t_write_start, &t_open);
    diff_taskstats(&t_write_start, &t_write_end, &t_write_start);

    print_taskstats2(&t_open);

    printf("Elapsed time (ns) %llu\n",
        ((long long)end.tv_sec - start.tv_sec) * 1000000000LL +
        end.tv_nsec - start.tv_nsec);

    print_taskstats2(&t_write_start);

    close(fd);

    return 0;
}
