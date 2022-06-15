#include "statistics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct socks5_stats socks5_stats;
static void inc_historic_connections(void);

void stats_init(struct socks5_stats * socks5_stats){
    memset(socks5_stats, 0,sizeof(*socks5_stats));
}

void inc_current_connections(void){
    if(socks5_stats.current_connections<UINT16_MAX){
        socks5_stats.current_connections++;
        inc_historic_connections();
    }
}

void dec_current_connections(void){
    if(socks5_stats.current_connections > 0){
        socks5_stats.current_connections--;
    }
}

static void inc_historic_connections(void){
    if(socks5_stats.historic_connections < UINT64_MAX ){
        socks5_stats.historic_connections++;
    }
}

void add_bytes_transferred(uint64_t bytes){
    if(bytes + socks5_stats.bytes_transfered < UINT64_MAX){
        socks5_stats.bytes_transfered+=bytes;
    }
    // TODO: Error
}

void inc_usr_amount(void){
    socks5_stats.usr_amount++;
}
