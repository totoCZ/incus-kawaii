/*
 * clat-init: static C replacement for clat-inject/run.sh.
 *
 * Runs as an LXC start hook (chain after net-wait), and brings up CLAT
 * inside the container without depending on a shell or iproute2:
 *
 *   1. Read eth0's non-tentative global SLAAC address (GUA) from
 *      /proc/net/if_inet6.
 *   2. Derive a CLAT IPv6 address as the EUI-64 sibling of the GUA by
 *      flipping the U/L bit on byte 8.  Unique per container as long as
 *      the upstream SLAAC address is unique.
 *   3. Render /clat-inject/tundra.conf.tmpl into /tmp/tundra.conf with
 *      __IPV6__ replaced by the formatted CLAT v6 address.
 *   4. Spawn /clat-inject/tundra detached (setsid + stdio /dev/null) so
 *      the lxc-monitor pipe closes when this hook returns.
 *   5. Wait up to 4 s for the kernel-side tundra TUN interface to appear.
 *   6. Write the sysctls needed for CLAT return traffic:
 *        net.ipv6.conf.eth0.accept_ra = 2  (keep RAs with forwarding on)
 *        net.ipv6.conf.all.forwarding = 1  (forward eth0 ↔ tundra)
 *        net.ipv6.conf.eth0.proxy_ndp = 1
 *   7. Via raw netlink (no iproute2 needed) on the tundra ifindex:
 *        - add 192.0.0.2/32
 *        - set MTU 1480, link UP
 *        - add default v4 route (src 192.0.0.2)
 *        - add CLAT_V6/128 host route
 *      And on eth0:
 *        - add proxy-NDP entry for CLAT_V6
 *
 * Build:
 *   gcc -static -Os -Wall -Wextra -o clat-init clat-init.c && strip clat-init
 *
 * Hook wiring (in container raw.lxc):
 *   lxc.hook.start = /net-inject/net-wait
 *   lxc.hook.start = /clat-inject/clat-init
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define ETH0          "eth0"
#define TUNDRA_IF     "tundra"
#define TUNDRA_BIN    "/clat-inject/tundra"
#define TEMPLATE_PATH "/clat-inject/tundra.conf.tmpl"
#define CONF_PATH     "/tmp/tundra.conf"
#define CLAT_V4       "192.0.0.2"
#define CLAT_V4_MTU   1480

static void die(const char *fmt, ...) __attribute__((noreturn, format(printf,1,2)));
static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("clat-init: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

static void info(const char *fmt, ...) __attribute__((format(printf,1,2)));
static void info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("clat-init: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

/* ---------- SLAAC GUA discovery ---------- */

static int read_eth0_gua_once(unsigned char out[16])
{
    FILE *f = fopen("/proc/net/if_inet6", "r");
    if (!f) return -1;
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char addr_hex[33], ifname[32];
        unsigned int idx, plen, scope, flags;
        if (sscanf(line, "%32s %x %x %x %x %31s",
                   addr_hex, &idx, &plen, &scope, &flags, ifname) < 6)
            continue;
        if (strcmp(ifname, ETH0) != 0) continue;
        if (scope != 0) continue;
        if (flags & IFA_F_TENTATIVE) continue;
        /* skip ULA — we want the GUA */
        char c0 = addr_hex[0], c1 = addr_hex[1];
        if ((c0 == 'f' || c0 == 'F') &&
            (c1 == 'c' || c1 == 'C' || c1 == 'd' || c1 == 'D'))
            continue;
        for (int i = 0; i < 16; i++) {
            char b[3] = { addr_hex[i*2], addr_hex[i*2+1], 0 };
            out[i] = (unsigned char)strtoul(b, NULL, 16);
        }
        found = 1;
        break;
    }
    fclose(f);
    return found ? 0 : -1;
}

/* Poll for a non-tentative GUA on eth0. net-wait gates on the ULA
 * address — DAD on the GUA may still be running for another fraction
 * of a second after that, so retry briefly here. */
static int get_eth0_gua(unsigned char out[16])
{
    for (int i = 0; i < 50; i++) {  /* up to 10s, 200 ms steps */
        if (read_eth0_gua_once(out) == 0)
            return 0;
        struct timespec ts = { 0, 200L * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    return -1;
}

static void compute_clat_v6(const unsigned char gua[16], unsigned char out[16])
{
    memcpy(out, gua, 16);
    out[8] ^= 0x02;  /* flip U/L bit on the interface ID's first byte */
}

/* ---------- tundra config + spawn ---------- */

static void write_tundra_conf(const unsigned char clat_v6[16])
{
    char v6str[INET6_ADDRSTRLEN];
    if (!inet_ntop(AF_INET6, clat_v6, v6str, sizeof(v6str)))
        die("inet_ntop failed");
    FILE *in = fopen(TEMPLATE_PATH, "r");
    if (!in) die("open %s: %s", TEMPLATE_PATH, strerror(errno));
    FILE *out = fopen(CONF_PATH, "w");
    if (!out) die("open %s: %s", CONF_PATH, strerror(errno));
    char line[512];
    const char *needle = "__IPV6__";
    size_t nlen = strlen(needle);
    while (fgets(line, sizeof(line), in)) {
        char *p = strstr(line, needle);
        if (p) {
            *p = 0;
            fputs(line, out);
            fputs(v6str, out);
            fputs(p + nlen, out);
        } else {
            fputs(line, out);
        }
    }
    fclose(in);
    if (fclose(out) != 0)
        die("write %s: %s", CONF_PATH, strerror(errno));
}

static void spawn_tundra(void)
{
    pid_t pid = fork();
    if (pid < 0) die("fork: %s", strerror(errno));
    if (pid == 0) {
        setsid();
        int dn = open("/dev/null", O_RDWR);
        if (dn >= 0) {
            dup2(dn, 0); dup2(dn, 1); dup2(dn, 2);
            if (dn > 2) close(dn);
        }
        char *argv[] = {
            (char *)TUNDRA_BIN, "--config-file", (char *)CONF_PATH,
            "translate", NULL
        };
        execv(TUNDRA_BIN, argv);
        _exit(127);
    }
}

static unsigned int wait_for_tundra_iface(void)
{
    for (int i = 0; i < 40; i++) {
        unsigned int idx = if_nametoindex(TUNDRA_IF);
        if (idx) return idx;
        struct timespec ts = { 0, 100L * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    die("tundra interface did not appear within 4s");
}

/* ---------- sysctls ---------- */

static void write_sysctl(const char *path, const char *value)
{
    FILE *f = fopen(path, "w");
    if (!f) die("open %s: %s", path, strerror(errno));
    if (fputs(value, f) == EOF || fclose(f) != 0)
        die("write %s: %s", path, strerror(errno));
}

/* ---------- netlink ---------- */

static unsigned int nl_seq;

static int nl_open(void)
{
    int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (s < 0) die("netlink socket: %s", strerror(errno));
    return s;
}

static void nl_add_attr(struct nlmsghdr *nh, size_t cap,
                        unsigned short type, const void *data, size_t dlen)
{
    size_t off = NLMSG_ALIGN(nh->nlmsg_len);
    if (off + RTA_LENGTH(dlen) > cap)
        die("netlink attr overflow (type=%u)", type);
    struct rtattr *rta = (struct rtattr *)((char *)nh + off);
    rta->rta_type = type;
    rta->rta_len  = RTA_LENGTH(dlen);
    memcpy(RTA_DATA(rta), data, dlen);
    nh->nlmsg_len = off + RTA_ALIGN(rta->rta_len);
}

static void nl_send_recv(int s, struct nlmsghdr *nh, const char *what)
{
    nh->nlmsg_flags |= NLM_F_ACK;
    nh->nlmsg_seq   = ++nl_seq;
    struct sockaddr_nl k = { .nl_family = AF_NETLINK };
    if (sendto(s, nh, nh->nlmsg_len, 0,
               (struct sockaddr *)&k, sizeof(k)) < 0)
        die("netlink send %s: %s", what, strerror(errno));
    char buf[4096];
    ssize_t n = recv(s, buf, sizeof(buf), 0);
    if (n < 0) die("netlink recv %s: %s", what, strerror(errno));
    struct nlmsghdr *r = (struct nlmsghdr *)buf;
    if (r->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(r);
        if (e->error)
            die("netlink %s: %s", what, strerror(-e->error));
    }
}

/* ip addr add 192.0.0.2/32 dev tundra */
static void add_addr_v4(int s, unsigned int ifindex)
{
    struct {
        struct nlmsghdr  nh;
        struct ifaddrmsg ifa;
        char             buf[64];
    } req = {0};
    req.nh.nlmsg_len   = NLMSG_LENGTH(sizeof(req.ifa));
    req.nh.nlmsg_type  = RTM_NEWADDR;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    req.ifa.ifa_family    = AF_INET;
    req.ifa.ifa_prefixlen = 32;
    req.ifa.ifa_scope     = 0;            /* universe */
    req.ifa.ifa_index     = ifindex;
    struct in_addr a;
    inet_pton(AF_INET, CLAT_V4, &a);
    nl_add_attr(&req.nh, sizeof(req), IFA_LOCAL,   &a, sizeof(a));
    nl_add_attr(&req.nh, sizeof(req), IFA_ADDRESS, &a, sizeof(a));
    nl_send_recv(s, &req.nh, "addr add v4");
}

/* ip link set tundra mtu 1480 up */
static void link_up_mtu(int s, unsigned int ifindex, unsigned int mtu)
{
    struct {
        struct nlmsghdr  nh;
        struct ifinfomsg ifi;
        char             buf[64];
    } req = {0};
    req.nh.nlmsg_len   = NLMSG_LENGTH(sizeof(req.ifi));
    req.nh.nlmsg_type  = RTM_NEWLINK;
    req.nh.nlmsg_flags = NLM_F_REQUEST;
    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index  = ifindex;
    req.ifi.ifi_change = IFF_UP;
    req.ifi.ifi_flags  = IFF_UP;
    nl_add_attr(&req.nh, sizeof(req), IFLA_MTU, &mtu, sizeof(mtu));
    nl_send_recv(s, &req.nh, "link set up+mtu");
}

/* ip route add default dev tundra src 192.0.0.2 */
static void route_default_v4(int s, unsigned int ifindex)
{
    struct {
        struct nlmsghdr nh;
        struct rtmsg    rt;
        char            buf[128];
    } req = {0};
    req.nh.nlmsg_len    = NLMSG_LENGTH(sizeof(req.rt));
    req.nh.nlmsg_type   = RTM_NEWROUTE;
    req.nh.nlmsg_flags  = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    req.rt.rtm_family   = AF_INET;
    req.rt.rtm_dst_len  = 0;
    req.rt.rtm_table    = RT_TABLE_MAIN;
    req.rt.rtm_protocol = RTPROT_BOOT;
    req.rt.rtm_scope    = RT_SCOPE_LINK;
    req.rt.rtm_type     = RTN_UNICAST;
    nl_add_attr(&req.nh, sizeof(req), RTA_OIF, &ifindex, sizeof(ifindex));
    struct in_addr src;
    inet_pton(AF_INET, CLAT_V4, &src);
    nl_add_attr(&req.nh, sizeof(req), RTA_PREFSRC, &src, sizeof(src));
    nl_send_recv(s, &req.nh, "route default v4");
}

/* ip -6 route add <addr>/128 dev tundra */
static void route_host_v6(int s, unsigned int ifindex,
                          const unsigned char addr[16])
{
    struct {
        struct nlmsghdr nh;
        struct rtmsg    rt;
        char            buf[128];
    } req = {0};
    req.nh.nlmsg_len    = NLMSG_LENGTH(sizeof(req.rt));
    req.nh.nlmsg_type   = RTM_NEWROUTE;
    req.nh.nlmsg_flags  = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    req.rt.rtm_family   = AF_INET6;
    req.rt.rtm_dst_len  = 128;
    req.rt.rtm_table    = RT_TABLE_MAIN;
    req.rt.rtm_protocol = RTPROT_BOOT;
    req.rt.rtm_scope    = RT_SCOPE_UNIVERSE;
    req.rt.rtm_type     = RTN_UNICAST;
    nl_add_attr(&req.nh, sizeof(req), RTA_DST, addr, 16);
    nl_add_attr(&req.nh, sizeof(req), RTA_OIF, &ifindex, sizeof(ifindex));
    nl_send_recv(s, &req.nh, "route host v6");
}

/* ip -6 neigh add proxy <addr> dev eth0 */
static void proxy_ndp(int s, unsigned int ifindex,
                      const unsigned char addr[16])
{
    struct {
        struct nlmsghdr nh;
        struct ndmsg    nd;
        char            buf[64];
    } req = {0};
    req.nh.nlmsg_len    = NLMSG_LENGTH(sizeof(req.nd));
    req.nh.nlmsg_type   = RTM_NEWNEIGH;
    req.nh.nlmsg_flags  = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
    req.nd.ndm_family   = AF_INET6;
    req.nd.ndm_ifindex  = ifindex;
    req.nd.ndm_state    = NUD_PERMANENT;
    req.nd.ndm_flags    = NTF_PROXY;
    nl_add_attr(&req.nh, sizeof(req), NDA_DST, addr, 16);
    nl_send_recv(s, &req.nh, "neigh proxy");
}

/* ---------- main ---------- */

int main(void)
{
    unsigned char gua[16], clat_v6[16];
    if (get_eth0_gua(gua) < 0)
        die("no non-tentative GUA on %s (was net-wait skipped?)", ETH0);

    compute_clat_v6(gua, clat_v6);
    char gua_str[INET6_ADDRSTRLEN], clat_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, gua, gua_str, sizeof(gua_str));
    inet_ntop(AF_INET6, clat_v6, clat_str, sizeof(clat_str));
    info("eth0 GUA %s, CLAT v6 %s", gua_str, clat_str);

    write_tundra_conf(clat_v6);
    spawn_tundra();

    unsigned int tun_ifx = wait_for_tundra_iface();
    unsigned int eth_ifx = if_nametoindex(ETH0);
    if (!eth_ifx) die("no %s interface", ETH0);

    /* Sysctls before routes so the kernel will actually accept forwarding
     * of CLAT_V6 packets we're about to route via tundra. */
    write_sysctl("/proc/sys/net/ipv6/conf/eth0/accept_ra", "2");
    write_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1");
    write_sysctl("/proc/sys/net/ipv6/conf/eth0/proxy_ndp", "1");

    int s = nl_open();
    add_addr_v4(s, tun_ifx);
    link_up_mtu(s, tun_ifx, CLAT_V4_MTU);
    route_default_v4(s, tun_ifx);
    route_host_v6(s, tun_ifx, clat_v6);
    proxy_ndp(s, eth_ifx, clat_v6);
    close(s);

    info("CLAT up");
    return 0;
}
