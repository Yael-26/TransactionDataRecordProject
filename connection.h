#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "transaction.h"

typedef struct 
{
    int id_connection;
    long video_connection_size;
    struct timeval start_time;
    double time_last_packet;
    transaction* transactions;
    int count_transactions; //the count of close transactions
    /*5 tuple*/
    uint16_t client_port;
    uint16_t server_port;
    uint32_t client_ip;
    uint32_t server_ip;
    int ip_protocol;
}connection;