/*
 * net-wait: static init-wait for Incus OCI containers.
 *
 * Waits until BOTH conditions are true (or timeout):
 *   1. IPv6 default route with RTF_GATEWAY exists in /proc/net/ipv6_route
 *   2. At least one 'nameserver' line present in /etc/resolv.conf
 *
 * Designed to run as an LXC start-hook (lxc.hook.start) installed via
 * the default Incus profile:
 *
 *     raw.lxc: lxc.hook.start = /net-inject/net-wait
 *
 * LXC executes the hook inside the container's mount and PID namespace
 * synchronously before lxc.execute.cmd (the OCI entrypoint) is forked,
 * so the OCI process is guaranteed to see a working default route and
 * resolv.conf when it starts.
 *
 * Detection of hook mode: LXC sets LXC_HOOK_TYPE in the hook's
 * environment.  When present, we wait then exit 0 (LXC then starts
 * lxc.execute.cmd as PID 1, unmodified).
 *
 * Build:
 *   gcc -static -Os -o net-wait net-wait.c && strip net-wait
 *
 * Static C with no shell/libc surface beyond what -static provides;
 * safe to use against distroless/scratch images that lack /bin/sh.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TIMEOUT_SEC  60
#define POLL_US      200000   /* 200 ms */
#define LOG_INTERVAL 5        /* seconds between "still waiting" lines */

/*
 * Log to both stderr and a tmpfs file inside the container.
 * The hook's stderr is captured by lxc-monitor but never surfaced
 * to a stable file; /tmp/net-wait.log gives us a post-mortem trace.
 * /tmp exists and is writable in essentially every OCI image
 * (it's a tmpfs mount, not a rootfs path).
 */
static FILE *log_fp;

static void log_init(void)
{
    log_fp = fopen("/tmp/net-wait.log", "a");
}

#define LOG(fmt, ...) do { \
    fprintf(stderr, "net-wait: " fmt "\n", ##__VA_ARGS__); \
    if (log_fp) { \
        fprintf(log_fp, "net-wait: " fmt "\n", ##__VA_ARGS__); \
        fflush(log_fp); \
    } \
} while (0)

/* ------------------------------------------------------------------ */

/*
 * /proc/net/ipv6_route columns (all hex, no header line):
 *   dest(32) pfx(2) src(32) spfx(2) nexthop(32) metric refcnt use flags iface
 *
 * A usable default route has dest == 0…0, pfx == 00, and
 * flags & RTF_GATEWAY (0x2).  Loopback unreachable routes have
 * RTF_REJECT (0x200) instead and must be skipped.
 */
#define RTF_GATEWAY 0x2u
#define RTF_REJECT  0x200u

static int has_ipv6_default_route(void)
{
    FILE *f = fopen("/proc/net/ipv6_route", "r");
    if (!f)
        return 0;

    char line[384];
    while (fgets(line, (int)sizeof(line), f)) {
        char dest[33], pfx[3], src[33], spfx[3], gw[33];
        unsigned int metric, refcnt, use, flags;

        int n = sscanf(line,
            "%32s %2s %32s %2s %32s %x %x %x %x",
            dest, pfx, src, spfx, gw,
            &metric, &refcnt, &use, &flags);
        if (n < 9)
            continue;

        if (strcmp(dest, "00000000000000000000000000000000") == 0 &&
            strcmp(pfx,  "00") == 0 &&
            (flags & RTF_GATEWAY) &&
            !(flags & RTF_REJECT)) {
            fclose(f);
            return 1;
        }
    }

    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */

/*
 * /proc/net/if_inet6 columns:
 *   addr(32) ifindex(2) plen(2) scope(2) flags(2) ifname
 *
 * On this network, every resolver is either on the ULA subnet
 * (fc00::/7) or reachable via the default route. Waiting for a
 * non-tentative ULA address on a real interface gives us both:
 *
 *   - the on-link route for the ULA /64 is installed (so a
 *     ULA-prefix resolver is reachable), AND
 *   - the default route from the same RA is already in place
 *     (so any non-ULA resolver is also reachable).
 *
 * Without the tentative check (IFA_F_TENTATIVE = 0x40) the address
 * is visible in /proc but still doing DAD, and outgoing connects
 * fail until it goes non-tentative.
 */
#define IFA_F_TENTATIVE 0x40u

static int has_ula_address(void)
{
    FILE *f = fopen("/proc/net/if_inet6", "r");
    if (!f)
        return 0;

    char line[256];
    while (fgets(line, (int)sizeof(line), f)) {
        char addr[33], ifname[32];
        unsigned int ifindex, plen, scope, flags;
        int n = sscanf(line, "%32s %x %x %x %x %31s",
            addr, &ifindex, &plen, &scope, &flags, ifname);
        if (n < 6)
            continue;
        if (strcmp(ifname, "lo") == 0)
            continue;
        if (flags & IFA_F_TENTATIVE)
            continue;
        /* ULA = fc00::/7 → first byte's top 7 bits are 1111110x,
         * i.e. the hex string starts with "fc" or "fd". */
        if ((addr[0] == 'f' || addr[0] == 'F') &&
            (addr[1] == 'c' || addr[1] == 'C' ||
             addr[1] == 'd' || addr[1] == 'D')) {
            fclose(f);
            return 1;
        }
    }

    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */

/*
 * A nameserver line in /etc/resolv.conf means DHCPv6/SLAAC-RD has
 * completed and written the container's resolver configuration.
 * We don't probe the nameserver itself — if it's in the file it's
 * been assigned by the DHCP client and is on-link or reachable
 * through the default route we've already verified above.
 */
static int has_nameserver(void)
{
    FILE *f = fopen("/etc/resolv.conf", "r");
    if (!f)
        return 0;

    char line[256];
    while (fgets(line, (int)sizeof(line), f)) {
        /* "nameserver<SP|TAB>" */
        if (strncmp(line, "nameserver", 10) == 0 &&
            (line[10] == ' ' || line[10] == '\t')) {
            fclose(f);
            return 1;
        }
    }

    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */

static long elapsed_sec(const struct timespec *start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long)(now.tv_sec - start->tv_sec);
}

int main(int argc, char **argv)
{
    log_init();

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int have_route = 0, have_dns = 0, have_addr = 0;
    long last_log  = -LOG_INTERVAL;   /* trigger immediate first log */

    for (;;) {
        have_route = has_ipv6_default_route();
        have_dns   = has_nameserver();
        have_addr  = has_ula_address();

        if (have_route && have_dns && have_addr)
            break;

        long secs = elapsed_sec(&start);

        if (secs - last_log >= LOG_INTERVAL) {
            LOG("waiting… elapsed=%lds route=%d dns=%d addr=%d",
                secs, have_route, have_dns, have_addr);
            last_log = secs;
        }

        if (secs >= TIMEOUT_SEC) {
            LOG("timeout after %lds; proceeding anyway (route=%d dns=%d addr=%d)",
                secs, have_route, have_dns, have_addr);
            break;
        }

        usleep(POLL_US);
    }

    LOG("ready (route=%d dns=%d addr=%d elapsed=%lds)",
        have_route, have_dns, have_addr, elapsed_sec(&start));

    if (getenv("LXC_HOOK_TYPE"))
        return 0;

    if (argc > 1) {
        execv(argv[1], argv + 1);
        LOG("execv(%s) failed: %s", argv[1], strerror(errno));
        return 127;
    }

    return 0;
}
