/* np_proxy: add an IPv6 proxy NDP entry on a given interface, via netlink.
 * Equivalent to: ip -6 neigh add proxy <addr> dev <iface>
 * Built static so it runs in any container (no glibc / no iproute2 needed).
 *
 * Usage: np_proxy <ipv6-addr> <ifname>
 */
#include <arpa/inet.h>
#include <errno.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <ipv6-addr> <ifname>\n", argv[0]);
        return 2;
    }
    struct in6_addr addr;
    if (inet_pton(AF_INET6, argv[1], &addr) != 1) {
        fprintf(stderr, "bad ipv6: %s\n", argv[1]);
        return 2;
    }
    unsigned int ifindex = if_nametoindex(argv[2]);
    if (!ifindex) {
        fprintf(stderr, "no such iface: %s\n", argv[2]);
        return 2;
    }

    int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (s < 0) { perror("socket"); return 1; }

    struct {
        struct nlmsghdr  nh;
        struct ndmsg     nd;
        char             buf[64];
    } req = {0};

    req.nh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.nh.nlmsg_type  = RTM_NEWNEIGH;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    req.nh.nlmsg_seq   = 1;

    req.nd.ndm_family  = AF_INET6;
    req.nd.ndm_ifindex = ifindex;
    req.nd.ndm_state   = NUD_PERMANENT;
    req.nd.ndm_flags   = NTF_PROXY;

    /* NDA_DST attribute */
    struct rtattr *rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.nh.nlmsg_len));
    rta->rta_type = NDA_DST;
    rta->rta_len  = RTA_LENGTH(sizeof(addr));
    memcpy(RTA_DATA(rta), &addr, sizeof(addr));
    req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

    struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
    if (sendto(s, &req, req.nh.nlmsg_len, 0,
               (struct sockaddr *)&kernel, sizeof(kernel)) < 0) {
        perror("sendto"); return 1;
    }

    char rbuf[4096];
    ssize_t n = recv(s, rbuf, sizeof(rbuf), 0);
    if (n < 0) { perror("recv"); return 1; }
    struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;
    if (rh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(rh);
        if (e->error) {
            fprintf(stderr, "netlink: %s\n", strerror(-e->error));
            return 1;
        }
    }
    return 0;
}
