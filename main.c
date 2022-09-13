//BSD
#include "pcap.h"
#include "pthread.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <json-c/json.h>
#include "values_struct.h"
#include "hashtable.h"
#include "connection.h"
#include "packet_structs.h"



#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)

/* global varible */
FILE *fpt;
FILE *statistic;
FILE *json_file;
ht *hash_table;
struct values *values;
connection* all_connection;
int flag_first_inbound_packet;
double packet_time;
static int identity_connection = 0;
static int number_connection = 1;
int server_to_client = 0;  //Flag to indicate whether the packet is server to client or client to server. server to client? 1 : 0
int num_of_request = 0;
int num_of_packet = 0;
int five_tuple = 0;
int num_of_transaction = 0;
int num_of_connection_over_size = 0;

void print_csv_file(int connection_index)
{
	num_of_transaction+=all_connection[connection_index].count_transactions;
	//printf("++++++++++++++++++++++++++++++++++++++print😊😊😊😊😊😊++++++++++++++++++++++++++++++++++++++++++++++++\n");
	num_of_connection_over_size++;
	for(int i=0; i < all_connection[connection_index].count_transactions; i++){
		char serverIp[18], clientIp[18];
		// struct in_addr temp;
		// inet_pton()
		strcpy(serverIp, inet_ntoa(*(struct in_addr *)&all_connection[connection_index].server_ip));
		strcpy(clientIp, inet_ntoa(*(struct in_addr *)&all_connection[connection_index].client_ip));

		// char buff[50];
		// struct tm *time_info;
		// time_info = localtime(&all_connection[connection_index].transactions[i].time_start_transaction);
		// strftime(buff,sizeof(buff), "%H:%M:%S",time_info);
		// printf("%d, %u, %u, %d, %d, %d, %d, %dl, %d, %d, %d, %d\n", all_connection[connection_index].id_connection, all_connection[connection_index].client_ip, all_connection[connection_index].server_ip, all_connection[connection_index].ip_protocol, all_connection[connection_index].client_port, all_connection[connection_index].server_port,all_connection[connection_index].transactions[i].transaction_id, all_connection[connection_index].transactions[i].time_start_transaction, all_connection[connection_index].transactions[i].num_inbound_packets_in_range, all_connection[connection_index].transactions[i].num_outbound_packets_in_range, all_connection[connection_index].transactions[i].max_packet_size_inbound, all_connection[connection_index].transactions[i].min_packet_size_inbound);
		fprintf(fpt,"%d, %s, %s, %d, %d, %d, %d, %lf, %d, %d, %d, %d, %lf, %lf, %lf, %lf\n",
		all_connection[connection_index].id_connection,
		clientIp,
		serverIp,
		all_connection[connection_index].ip_protocol,
		all_connection[connection_index].client_port,
		all_connection[connection_index].server_port,
		all_connection[connection_index].transactions[i].transaction_id,
		all_connection[connection_index].transactions[i].time_start_transaction,
		all_connection[connection_index].transactions[i].num_inbound_packets_in_range,
		all_connection[connection_index].transactions[i].num_outbound_packets_in_range,
		all_connection[connection_index].transactions[i].max_packet_size_inbound,
		all_connection[connection_index].transactions[i].min_packet_size_inbound,
		all_connection[connection_index].transactions[i].max_diff_time_inbound,
		all_connection[connection_index].transactions[i].min_diff_time_inbound,
		all_connection[connection_index].transactions[i].sum_square_inbound_packet_time_diff,
		all_connection[connection_index].transactions[i].RTT
		);
	}
}


double diff(struct timeval start, struct timeval end)
{
    // double deff= double(end->tv_sec - start->tv_sec) + double(end->tv_usec - start->tv_usec) * 1e-6;
    // return deff;
    long usec = end.tv_usec - start.tv_usec;
    long sec = end.tv_sec - start.tv_sec;
    return 1.0 * sec + 1e-6 * usec;
}
void init_transaction(int connection_index, int transaction_index)
{
	// char str[100];
    // sprintf(str, "%d%d",sizeof(str), all_connection[connection_index].count_transactions, all_connection[connection_index].id_connection);
	// int id = strtol(str, NULL, 10);
    all_connection[connection_index].transactions[transaction_index].transaction_id = all_connection[connection_index].count_transactions;
    all_connection[connection_index].transactions[transaction_index].size_transaction = 0;
    all_connection[connection_index].transactions[transaction_index].time_start_transaction = packet_time;
    all_connection[connection_index].transactions[transaction_index].num_inbound_packets_in_range = 0;
    all_connection[connection_index].transactions[transaction_index].num_outbound_packets_in_range = 0;
    all_connection[connection_index].transactions[transaction_index].max_packet_size_inbound = 0;
    all_connection[connection_index].transactions[transaction_index].min_packet_size_inbound = values->inbound_packets_in_range_max;
	all_connection[connection_index].transactions[transaction_index].max_diff_time_inbound = 0;
	all_connection[connection_index].transactions[transaction_index].min_diff_time_inbound = values->video_connection_timeout;
	all_connection[connection_index].transactions[transaction_index].time_last_inbound_packet = 0;
	//printf("finish init transaction in all_connection[%d]. transaction in  place %d id %d\n", connection_index, transaction_index, id);
}

void init_connection(int connection_index, int ip_protocol, uint32_t server_ip, uint32_t client_ip,int server_port, int client_port)
{
    all_connection[connection_index].id_connection = identity_connection++;
    all_connection[connection_index].video_connection_size = 0;
    all_connection[connection_index].count_transactions = 0;//close transactions
    all_connection[connection_index].transactions = (transaction*)malloc(values->max_number_of_transaction_per_video*sizeof(transaction));
    all_connection[connection_index].client_port = client_port;
    all_connection[connection_index].server_port = server_port;
    all_connection[connection_index].ip_protocol = ip_protocol;
    all_connection[connection_index].server_ip = server_ip;
    all_connection[connection_index].client_ip = client_ip;
	all_connection[connection_index].time_last_packet = packet_time;
	//printf("finish init connection in all_connection[%d]. id %d\n", connection_index, all_connection[connection_index].id_connection);
    init_transaction(connection_index, all_connection[connection_index].count_transactions);
}

void add_new_transaction_to_connection(int connection_index)
{
	if(all_connection[connection_index].transactions[all_connection[connection_index].count_transactions].num_inbound_packets_in_range == 0){
		all_connection[connection_index].transactions[all_connection[connection_index].count_transactions].min_packet_size_inbound = 0;
		all_connection[connection_index].transactions[all_connection[connection_index].count_transactions].min_diff_time_inbound = 0;
		all_connection[connection_index].transactions[all_connection[connection_index].count_transactions].sum_square_inbound_packet_time_diff = 0;
		all_connection[connection_index].transactions[all_connection[connection_index].count_transactions].RTT = 0;
	}
	all_connection[connection_index].video_connection_size += all_connection[connection_index].transactions[all_connection[connection_index].count_transactions].size_transaction;//save the size of last transaction
    all_connection[connection_index].count_transactions++;//edit the count of transaction - that in the transactions_collection
    init_transaction(connection_index, all_connection[connection_index].count_transactions);
}

void update_connection(int connection_index)
{
	all_connection[connection_index].id_connection = identity_connection++;
	all_connection[connection_index].time_last_packet = packet_time;
	all_connection[connection_index].count_transactions = 0;
    init_transaction(connection_index , all_connection[connection_index].count_transactions);
}

void create_connection(char* key, int connection_index, int ip_protocol, uint32_t server_ip, uint32_t client_ip, int server_port, int client_port)
{
	ht_set(hash_table, key, (void *)(connection_index));
	//printf("in create connection finish insert to key %s value %d\n", key, (int)ht_get(hash_table , key));
	init_connection(connection_index, ip_protocol, server_ip, client_ip, server_port, client_port);
}

void get_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
	/* ethernet type */
	unsigned short eth_type;
	struct sniff_ethernet *ethernet;
	ethernet = (struct sniff_ethernet*)(packet);
	eth_type = ntohs(ethernet->ether_type);
	//printf("eth_type %u\n 😊😊😊\n", eth_type);

	/* 5 tuple */
	const struct sniff_ip *ip = (struct sniff_ip *)(packet + SIZE_ETHERNET); // ip layer
    int size_ip = IP_HL(ip) * 4;
    const struct sniff_udp *udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip); // udp layer
	uint32_t src_ip;
    uint32_t dst_ip;
    src_ip = ip->ip_src.s_addr;
    dst_ip = ip->ip_dst.s_addr;
    int ip_protocol = (int)ip->ip_p;
	uint16_t src_port = ntohs(udp->udp_srcport);
    uint16_t dst_port = ntohs(udp->udp_destport);


	/*1 check if the packet is Ipv4 & udp & (src_port = 443 | dst_port =443)*/
	if(eth_type != ETHERTYPE_IP || ip_protocol != values->udp  || (src_port != values->youtube_port && dst_port != values->youtube_port))
		return;

	num_of_packet++;
	int size_packet = ntohs(udp->udp_len);	/*size packet*/
	//printf("-------------------------------------------------------------------------------------------------------\n");
	packet_time = header->ts.tv_sec + header->ts.tv_usec / 1000000.00000000;

	// printf("num_of_packet %d\n", num_of_packet);
	// printf("ip_protocol %d\n", ip_protocol);
	// printf("src_ip %u\n", src_ip);
	// printf("dst_ip %u\n", dst_ip);
	// printf("src_port %d\n", src_port);
	// printf("dst_port %d\n", dst_port);
	// printf("size_packet %u\n", size_packet);
	// printf("time packet  %lf\n", packet_time);

	char *key = (char *)malloc(1024 * sizeof(char));
	if (src_port == 443){//Checking the source port
		server_to_client = 1; //If it is equal to 443, the package is server to client
		sprintf(key, "%u%u%hu", src_ip, dst_ip, dst_port);
	}
	else{
		server_to_client = 0; //If it is equal to 443, the package is server to client
		sprintf(key, "%u%u%hu", dst_ip, src_ip, src_port);
	}
	// printf("key %s\n", key);
	int current_index = (int)ht_get(hash_table, key);// check exist in the hash table*/
	//printf("key %s is value %d\n",key,  current_index);
	// sleep(1);
	if(current_index == -1)/* The connection does not exist*/
	{
		if(number_connection == values->max_number_of_connections)
		{
			printf("ERROR! There is no entrys for another connection");
			return;
		}
		five_tuple++;
		if(server_to_client==0 && size_packet > values->request_packet_threshold)
		{
			num_of_request++;
			current_index = number_connection++;
			create_connection(key, current_index, ip_protocol, dst_ip, src_ip, dst_port, src_port);
		}
	}
	else /*The connection exists*/
	{
		/*A check that the timeout has not passed since the previous package passed*/
		if(packet_time - all_connection[current_index].time_last_packet > values->video_connection_timeout){/*The timeout has passed*/
			/*check if the connection contains more than “minimum_video_connection_size” bytes in all his transactions*/
			if(all_connection[current_index].video_connection_size > values->minimum_video_connection_size){// The size of all transactions is not enough
				//printf("befor printing because time passed and > values->minimum_video_connection_size\n");
				print_csv_file(current_index);//save all feild of connection
			}
			update_connection(current_index);//if The size of all transactions is not enough && if is enough
		}
		else  /* the timeout has not passed */
		{
			all_connection[current_index].time_last_packet = packet_time;
			if(server_to_client == 0)//from client to server
			{
				//printf("server to client\n");
				if(size_packet < values->request_packet_threshold)
					all_connection[current_index].transactions[all_connection[current_index].count_transactions].num_outbound_packets_in_range++;
				else{
					num_of_request++;
					//printf("is request\n");
					if(all_connection[current_index].count_transactions == values->max_number_of_transaction_per_video && all_connection[current_index].video_connection_size >= values->minimum_video_connection_size)//If the maximum number of transactions for the connection has been reached, save the connection and open a new one for this request.
					{
						//printf("befor printing because max_number_of_transaction_per_video\n");
						print_csv_file(current_index);
						update_connection(current_index);
					}
					else
					{
						add_new_transaction_to_connection(current_index); //In any case, save the currently open transaction.
						//printf("add transaction to connection %d because request\n", current_index);
					}
				}
			}
			else//from the server to the client
			{
				if(size_packet >= values->inbound_packets_in_range_min && size_packet < values->inbound_packets_in_range_max)//This is a video data packet
				{
					all_connection[current_index].transactions[all_connection[current_index].count_transactions].num_inbound_packets_in_range++;
					/* add packet to current transaction */
					all_connection[current_index].transactions[all_connection[current_index].count_transactions].size_transaction += size_packet;

					double diff_time_inbound = packet_time - all_connection[current_index].transactions[all_connection[current_index].count_transactions].time_last_inbound_packet;

					if(diff_time_inbound > all_connection[current_index].transactions[all_connection[current_index].count_transactions].max_diff_time_inbound)
						all_connection[current_index].transactions[all_connection[current_index].count_transactions].max_diff_time_inbound = packet_time - all_connection[current_index].transactions[all_connection[current_index].count_transactions].time_last_inbound_packet;
					
					if(diff_time_inbound < all_connection[current_index].transactions[all_connection[current_index].count_transactions].min_diff_time_inbound)
						all_connection[current_index].transactions[all_connection[current_index].count_transactions].min_diff_time_inbound = packet_time - all_connection[current_index].transactions[all_connection[current_index].count_transactions].time_last_inbound_packet;

					all_connection[current_index].transactions[all_connection[current_index].count_transactions].sum_square_inbound_packet_time_diff += diff_time_inbound * diff_time_inbound;

					if(all_connection[current_index].transactions[all_connection[current_index].count_transactions].time_last_inbound_packet == 0)

						all_connection[current_index].transactions[all_connection[current_index].count_transactions].RTT = diff_time_inbound;

					all_connection[current_index].transactions[all_connection[current_index].count_transactions].time_last_inbound_packet = packet_time;

					if(size_packet > all_connection[current_index].transactions[all_connection[current_index].count_transactions].max_packet_size_inbound)
						all_connection[current_index].transactions[all_connection[current_index].count_transactions].max_packet_size_inbound = size_packet;
					
					if(size_packet < all_connection[current_index].transactions[all_connection[current_index].count_transactions].min_packet_size_inbound)
						all_connection[current_index].transactions[all_connection[current_index].count_transactions].min_packet_size_inbound = size_packet;
				}
			}
		}
	}
	free(key);
}

void init_json_file(json_object *object)
{
	values = (struct values*)malloc(sizeof(struct values));
	values->youtube_port = (json_object_get_int(json_object_object_get(object, "youtube_port")));
	values->udp = (json_object_get_int(json_object_object_get(object, "udp")));
	values->request_packet_threshold= (json_object_get_int(json_object_object_get(object, "request_packet_threshold")));
	values->video_connection_timeout = (json_object_get_int(json_object_object_get(object, "video_connection_timeout")));
	values->minimum_video_connection_size = (json_object_get_int(json_object_object_get(object, "minimum_video_connection_size")));
	values->max_number_of_connections= (json_object_get_int(json_object_object_get(object, "max_number_of_connections")));
	values->inbound_packets_in_range_min= (json_object_get_int(json_object_object_get(object, "inbound_packets_in_range_min")));
	values->inbound_packets_in_range_max= (json_object_get_int(json_object_object_get(object, "inbound_packets_in_range_max")));
	values->outbound_packets_in_range_min= (json_object_get_int(json_object_object_get(object, "outbound_packets_in_range_min")));
	values->outbound_packets_in_range_max= (json_object_get_int(json_object_object_get(object, "outbound_packets_in_range_max")));
	values->max_diff_time_inbound_threshold= (json_object_get_int(json_object_object_get(object, "max_diff_time_inbound_threshold")));
	values->min_diff_time_inbound_threshold= (json_object_get_int(json_object_object_get(object, "min_diff_time_inbound_threshold")));
	values->max_number_of_transaction_per_video= (json_object_get_int(json_object_object_get(object, "max_number_of_transaction_per_video")));
}

int main(int argc, char **argv)
{
	json_object *object = json_object_from_file("values.json");
	init_json_file(object);
	statistic = fopen("statistics.csv", "w+");
	fpt = fopen("output.csv", "w+");
	fprintf(fpt,"Conn_id, Client_IP, Server_IP, IP_protocl, UDP_client_port, UDP_server_port, Transaction_id, Start_time, num_in_packets, num_out_packets, max_packet_size_in, min_packet_size_in, max_diff_time, min_diff_time, SumSquareInboundPacketTimeDiff, RTT\n");
	char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
	pcap_t *handle = pcap_open_offline("capture_file.pcap", errbuf);  /* packet capture handle */
	all_connection=(connection*)malloc(values->max_number_of_connections*sizeof(connection));
    hash_table = ht_create();
	pcap_loop(handle, 0, get_packet, NULL);
	for (int i = 0; i < number_connection; i++)
	{
		if(all_connection[i].video_connection_size > values->minimum_video_connection_size){
			print_csv_file(i);
		}
		// free(all_connection[i].transactions);
	}
    printf("number_connection %d\n", number_connection);
    printf("five_tuple %d\n", five_tuple);
	printf("num_of_connection_over_size %d\n", num_of_connection_over_size);
	printf("num_of_request %d\n", num_of_request);
	printf("num_of_packet %d\n", num_of_packet);
	printf("num_of_transaction %d\n", num_of_transaction);
	
	/* print to statistic file */
	fprintf(statistic,"The amount of videos have been watched: %d", num_of_connection_over_size);

    ht_destroy(hash_table);
    free(all_connection);
    fclose(fpt);
	fclose(statistic);
	free(object);
}