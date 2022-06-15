#ifndef STATISTICS_H
#define STATISTICS_H
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

struct socks5_stats {
    uint64_t bytes_transfered;
    uint64_t historic_connections;
    uint16_t current_connections;
    int usr_amount;
};

void stats_init(struct socks5_stats * socks5_stats);
void inc_current_connection(void);
void dec_current_connection(void);
void inc_historic_connections(void);
void add_bytes_sent(uint64_t bytes);
void inc_usr_amount(void);
#endif