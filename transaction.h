#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


typedef struct transaction
{
    int transaction_id;
    int size_transaction;
    double time_start_transaction;
    double time_last_inbound_packet;
    int num_inbound_packets_in_range;
    int num_outbound_packets_in_range;
    int max_packet_size_inbound;
    int min_packet_size_inbound;
    double min_diff_time_inbound;
    double max_diff_time_inbound;
    double sum_square_inbound_packet_time_diff;
    double RTT;
}transaction;
