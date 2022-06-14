#include "statistics.h"
#include <stdio.h>
#include <stdlib.h>


socks5Stats stats;
void stats_init(void){
    memset(&stats, 0,sizeof(stats));
}
void inc_current_connection(void){

    if(stats.current_connections<UINT64_MAX){
        stats.current_connections++;
        inc_historic_connections();
    }

}
void dec_current_connection(void){
    if(stats.current_connections >0){
        stats.current_connections--;
    }
}
void inc_historic_connections(void){
    if(stats.historic_connections < UINT64_MAX ){
        stats.historic_connections++;
    }
}

void add_bytes_sent(uint64_t bytes){
    if(bytes + stats.bytes_transfered < UINT64_MAX){
        stats.bytes_transfered+=bytes;
    }
}

void inc_usr_amount(void){
    stats.usr_amount++; //TODO: VALIDACION?
}
