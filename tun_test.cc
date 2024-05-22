
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <functional>
#include <getopt.h>
#include <linux/if_tun.h>
#include <malloc.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#define TUN_NAME "tun0"

const char* tun_addr;
const char* tun_route;
const char* targetIP; // = "172.31.224.1";
const int targetPort = 8080;

#define dbg(fmt, ...) printf("[%s] " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define dbg_errno(fmt, ...) printf("[%s] " fmt ": %s\n", __FUNCTION__, ##__VA_ARGS__, strerror(errno))

int open_tun(const char* name)
{
    int fd, ret;
    struct ifreq ifr = {};

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        dbg_errno("open(/dev/net/tun) failed");
        return -1;
    }

    sprintf(ifr.ifr_name, name);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    ret = ioctl(fd, TUNSETIFF, (void*)&ifr);
    if (ret < 0) {
        dbg_errno("ioctl(%s,TUNSETIFF) failed", name);
        close(fd);
        return -1;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    sprintf(ifr.ifr_name, name);

    ret = ioctl(fd, TUNSETLINK, (void*)ARPHRD_PPP);
    if (ret < 0) {
        dbg_errno("ioctl(%s,TUNSETLINK) failed", name);
        close(fd);
        return -1;
    }

    dbg("open tun(%s) success", name);
    return fd;
}

int config_tun(const char* name, int mtu, int txqlen)
{
    int fd, ret;
    struct ifreq ifr = {};
    struct sockaddr_in* sin;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        dbg_errno("socket() failed");
        return -1;
    }

    sprintf(ifr.ifr_name, name);

    ret = ioctl(fd, SIOCGIFFLAGS, (void*)&ifr);
    if (ret < 0) {
        dbg_errno("ioctl(%s,SIOCGIFFLAGS) failed", name);
        close(fd);
        return -1;
    }

    ifr.ifr_flags |= IFF_UP;
    ret = ioctl(fd, SIOCSIFFLAGS, (void*)&ifr);
    if (ret < 0) {
        dbg_errno("ioctl(%s,SIOCSIFFLAGS) failed", name);
        close(fd);
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    sprintf(ifr.ifr_name, name);

    sin = (struct sockaddr_in*)&ifr.ifr_addr;
    sin->sin_family = AF_INET;

    ret = ioctl(fd, SIOCSIFADDR, &ifr);
    if (ret < 0) {
        dbg_errno("ioctl(%s,SIOCSIFADDR) failed", name);
        close(fd);
        return -1;
    }

    dbg("up tun(%s) success", name);

    if (mtu > 0) {
        memset(&ifr, 0, sizeof(ifr));
        sprintf(ifr.ifr_name, name);
        ifr.ifr_mtu = mtu;

        ret = ioctl(fd, SIOCSIFMTU, &ifr);
        if (ret < 0) {
            dbg_errno("ioctl(%s,SIOCSIFMTU) failed", name);
            close(fd);
            return -1;
        }

        dbg("set tun(%s) mtu to %d", name, mtu);
    }

    if (txqlen > 0) {
        memset(&ifr, 0, sizeof(ifr));
        sprintf(ifr.ifr_name, name);
        ifr.ifr_qlen = txqlen;

        ret = ioctl(fd, SIOCSIFTXQLEN, (void*)&ifr);
        if (ret < 0) {
            dbg_errno("ioctl(%s,SIOCSIFTXQLEN) failed", name);
            close(fd);
            return -1;
        }

        dbg("set tun(%s) txqlen to %d", name, txqlen);
    }

    close(fd);
    return 0;
}

int config_tun_addr_and_route()
{
    char cmd[256] = "";
    snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s", tun_addr, TUN_NAME);
    dbg("system: %s", cmd);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "ip route add %s dev %s", tun_route, TUN_NAME);
    dbg("system: %s", cmd);
    system(cmd);
    return 0;
}

int raw_socket_init()
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock == -1) {
        dbg_errno("Failed to create socket");
        return -1;
    }

    // 设置套接字选项，允许 IP 数据包构造
    int enable = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) == -1) {
        dbg_errno("Failed to set socket options");
        close(sock);
        return -1;
    }

    dbg("create raw socket ok");
    return sock;
}

int write_to_raw_socket(int fd, uint8_t* ippkt, int ippktlen)
{
    struct sockaddr_in targetAddr;
    memset(&targetAddr, 0, sizeof(targetAddr));
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_addr.s_addr = inet_addr(targetIP);

    ssize_t bytesSent = sendto(fd, ippkt, ippktlen, 0,
        (struct sockaddr*)&targetAddr, sizeof(targetAddr));
    if (bytesSent == -1) {
        dbg_errno("Failed to send packet");
        return -1;
    }

    dbg("send pkt to %s ok", targetIP);

    return 0;
}

void usage()
{
    printf("./tun_test -a [tun_addr] -r [tun_route] -d [dest_ip]\n");
    exit(0);
}

int main(int argc, char** argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "a:r:d:")) != -1) {
        switch (opt) {
        case 'a':
            tun_addr = strdupa(optarg);
            break;
        case 'r':
            tun_route = strdupa(optarg);
            break;
        case 'd':
            targetIP = strdupa(optarg);
            break;
        default:
            usage();
        }
    }

    if (!tun_addr || !tun_route || !targetIP) {
        usage();
    }

    int fd = open_tun(TUN_NAME);
    if (fd < 0) {
        exit(0);
    }

    if (config_tun(TUN_NAME, 1400, 1000) < 0) {
        exit(0);
    }

    config_tun_addr_and_route();

    int rawfd = raw_socket_init();
    if (rawfd < 0) {
        exit(0);
    }

    while (1) {
        uint8_t ippkt[2048];
        int ippktlen;

        do {
            ippktlen = read(fd, ippkt, sizeof(ippkt));
        } while (ippktlen < 0 && errno == EINTR);

        if (ippktlen < 0) {
            if (errno != EAGAIN) {
                dbg_errno("read ippkt from tun failed");
            }
            break;
        }

        dbg("read pkt from %s, length:%d", TUN_NAME, ippktlen);

        write_to_raw_socket(rawfd, ippkt, ippktlen);
    }

    pause();
    return 0;
}