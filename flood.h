#ifndef FLOOD_H
#define FLOOD_H

#include <netinet/tcp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>

#define DEFAULT_IP     "127.0.0.1"
#define DEFAULT_PORT   80
#define DATAGRAM_SIZE  4096
#define DEFAULT_WINDOW 5840
#define TTL_VALUE      255

struct pseudo_header {
    uint32_t      src_addr;
    uint32_t      dst_addr;
    uint8_t       placeholder;
    uint8_t       protocol;
    uint16_t      tcp_length;
    struct tcphdr tcp;
};

typedef struct {
    volatile sig_atomic_t running;
    volatile sig_atomic_t packet_count;
} FloodState;

typedef struct {
    char     dst_ip[16];
    uint16_t dst_port;
    int      flag_syn;
    int      flag_rst;
    int      time_limit;
} FloodConfig;

typedef struct {
    int                  sock;
    char                 datagram[DATAGRAM_SIZE];
    struct pseudo_header psh;
    FloodConfig         *cfg;
    FloodState          *state;
} FloodContext;

uint16_t       rand_port(void);
void           rand_ip(char *buf, size_t len);
int            valid_ip(const char *ip);
unsigned short checksum(const unsigned short *ptr, int nbytes);

int  flood_parse_args(int argc, char *argv[], FloodConfig *cfg);
int  flood_init(FloodContext *ctx, FloodConfig *cfg, FloodState *state);
void flood_run(FloodContext *ctx);
void flood_cleanup(FloodContext *ctx);

#endif