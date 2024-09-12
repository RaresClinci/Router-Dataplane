#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#define IPv4_type 0x0800
#define ARP_type 0x0806
#define ICMP_type 1
#define ARP_INIT_SIZE 16
#define ARP_MAX_SIZE 4096

// routing table data
struct route_table_entry *rtable;
int rtable_len;

// arp table data
struct arp_table_entry *arp_table;
int arp_table_len;
int arp_max; // maximum capacity before realloc

// packet queue
struct queue* packet_queue;

// struct for waiting packets
struct waiting_packet{
	uint32_t next;
	int len;
	char* buf;
};

// mac for broadcast
uint8_t mac_broadcast[6];

// trie struct
struct trie{
	struct route_table_entry* entry;
	struct trie* next[2];
};

// routing trie
struct trie* routing_trie;

// empty trie func
struct trie* empty_trie() {
	struct trie* Trie = (struct trie*)malloc(sizeof(struct trie));
	Trie->entry = NULL;
	Trie->next[0] = NULL;
	Trie->next[1] = NULL;

	return Trie;
}

// add to trie func
void add_to_trie(struct trie* route, struct route_table_entry *rt) {
	uint32_t pos = 1;
	while((pos & rt->mask) != 0) {
		// extracting the current bit
		int bit = (rt->prefix & pos);
		if(bit != 0) {
			bit = 1;
		}

		// creating that field if it's empty
		if(route->next[bit] == NULL) {
			route->next[bit] = empty_trie();
		}

		// going down the trie
		route = route->next[bit];
		pos = (pos << 1);
	}
	// we reached all the relevant bits
	route->entry = rt;
}

// build trie form routing table
void build_route_trie() {
	routing_trie = empty_trie();
	for (int i = 0; i < rtable_len; i++) {
		add_to_trie(routing_trie, &(rtable[i])); 
	}
}

// search in route trie
struct route_table_entry* true_search_in_trie(struct trie* rtrie, uint32_t ip) {
	uint32_t pos = 1;
	struct route_table_entry* best = rtrie->entry;
	while (rtrie != NULL) {
        // extracting current bit
        int bit = (ip & pos);
		if(bit != 0){
			bit = 1;
		}

        // updating best
        if (rtrie->entry != NULL) {
            best = rtrie->entry;
        }

        // move deeper
    	rtrie = rtrie->next[bit];
        pos = (pos << 1);
    }
	return best;
}

// caller for search function
struct route_table_entry* search_in_trie(uint32_t ip) {
	return true_search_in_trie(routing_trie, ip);
}

// function for converting address to int
uint32_t parse_address(char *address) {
	char* p = strtok(address, " .");
	uint32_t conv = 0;
	int i = 0;

	while (p != NULL) {
		*(((unsigned char *)&conv)  + i % 4) = (unsigned char)atoi(p);
		i++;
		p = strtok(NULL, " .");
	}

	return conv;
}

// original rtable search function
struct route_table_entry *get_best_route(uint32_t ip_dest) {
	struct route_table_entry *best = NULL;

	for (int i = 0; i < rtable_len; i++) {
		if ((ip_dest & rtable[i].mask) == rtable[i].prefix) {
			if(best == NULL)
				best = &rtable[i];
			else if(ntohl(best->mask) < ntohl(rtable[i].mask)) {
				best = &rtable[i];
			}
		}
	}
	return best;
}

// arp table search function
struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
	for (int i = 0; i < arp_table_len; i++) {
		if(arp_table[i].ip == given_ip) {
			return &(arp_table[i]);
		}
	}
	return NULL;
}


// icmp packet function
void sendICMP(int interface, struct ether_header *eth, struct iphdr *ip, char* buff, int type) {
	// allocating the memory
	int packet_len = sizeof(struct ether_header) + sizeof(struct iphdr)
					+ sizeof(struct icmphdr) + 64;
	char* packet = malloc(packet_len);

	// sectioning the package into headers and payload
	struct ether_header* eth_header = (struct ether_header*)packet;
	struct iphdr* ip_header = (struct iphdr*)(packet + sizeof(struct ether_header));
	struct icmphdr* icmp_header = (struct icmphdr*)(packet + sizeof(struct ether_header)
						+ sizeof(struct iphdr));
	char* payload = packet + sizeof(struct ether_header) + sizeof(struct iphdr)
					+ sizeof(struct icmphdr);

	// building the ethernet header
	memcpy(eth_header->ether_dhost, eth->ether_shost, sizeof(struct ether_header));
	memcpy(eth_header->ether_shost, eth->ether_dhost, sizeof(struct ether_header));
	eth_header->ether_type = htons(IPv4_type);

	// building the ip header
	ip_header->tos = 0;
	ip_header->frag_off = 0;
	ip_header->version = 4;
	ip_header->ihl = 5;
	ip_header->id = 1;
	ip_header->protocol = ICMP_type;
	
	ip_header->ttl = 64;

	ip_header->saddr = parse_address(get_interface_ip(interface));
	ip_header->daddr = ip->saddr;

	ip_header->check = 0;
	ip_header->check = ntohs(checksum((uint16_t *)ip_header, sizeof(ip_header)));

	// building the icmp header
	memset(icmp_header, 0, sizeof(struct icmphdr));
	icmp_header->type = type;
	icmp_header->checksum = ntohs(checksum((uint16_t*)icmp_header, sizeof(icmp_header)));

	// copying the 64 bits
	buff = buff + sizeof(struct ether_header) + sizeof(struct iphdr);
	memcpy(payload, buff, 64);

	// sending the packet
	send_to_link(interface, packet, packet_len);

	free(packet);
}

// checking if our router is the destination
int is_for_router(struct arp_header *arphdr) {
	int i;
	for(i = 0; i < ROUTER_NUM_INTERFACES; i++) {
		if(arphdr->tpa == parse_address(get_interface_ip(i))) 
			return 1;
	}

	return 0;
}

// function for sending arp request
void send_ARP_request(uint32_t ip) {
	int len = sizeof(struct ether_header) + sizeof(struct arp_header);
	char *buf = malloc(len);

	// configuring the ethernet header
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	memcpy(eth_hdr->ether_dhost, mac_broadcast, sizeof(struct ether_header));
	eth_hdr->ether_type = htons(ARP_type);

	// configuring the arp header
	struct arp_header *arp_hdr = (struct arp_header*)(buf + sizeof(struct ether_header));

	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(IPv4_type);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1);
	arp_hdr->tpa = ip;

	struct route_table_entry* best_hop = search_in_trie(ip);

	get_interface_mac(best_hop->interface, eth_hdr->ether_shost);
	arp_hdr->spa = parse_address(get_interface_ip(best_hop->interface));
	get_interface_mac(best_hop->interface, arp_hdr->sha);
	send_to_link(best_hop->interface, buf, len);

	free(buf);
}

void handle_ARP_request(struct ether_header *ethr,struct arp_header* arphdr, char* buf, int len, int interface) {
	if(is_for_router(arphdr)) {
		printf("Is for me\n");
		// converting to reply
		arphdr->op = htons(2);

		// switching the source and target ip addresses
		uint32_t aux;
		aux = arphdr->spa;
		arphdr->spa = arphdr->tpa;
		arphdr->tpa = aux;

		// switching the target mac
		memcpy(arphdr->tha, arphdr->sha, sizeof(arphdr->tha));

		// getting system mac
		uint8_t mac[6];
		get_interface_mac(interface, mac);
		memcpy(arphdr->sha, mac, sizeof(mac));

		// changing ether header
		memcpy(ethr->ether_dhost, ethr->ether_shost, sizeof(mac));
		memcpy(ethr->ether_shost, mac, sizeof(mac));

		send_to_link(interface, buf, len);
	} else {
		struct route_table_entry* best_hop = search_in_trie(arphdr->tpa);

		send_to_link(best_hop->interface, buf, len);
	}
}

// handling the arp reply
void handle_ARP_reply(struct arp_header* arphdr, char *buf, int len, int interface) {
	if(is_for_router(arphdr)) {
		// reply is for me, processing it
		// did we send multiple arp requests and got multiple replies?
		struct arp_table_entry* mac = get_arp_entry(arphdr->spa);

		if(mac == NULL) {
			if(arp_max <= arp_table_len) {
				// maximum capacity reached => reallocing
				arp_max += 10;
				arp_table = (struct arp_table_entry*)realloc(arp_table, sizeof(struct arp_table_entry) * arp_max);
			}

			// adding the new mac address
			memcpy(arp_table[arp_table_len].mac, arphdr->sha, sizeof(arphdr->sha));
			arp_table[arp_table_len].ip = arphdr->spa;
			arp_table_len++;
		}

		// sending the pending packets
		struct queue* aux = queue_create();

		while(!queue_empty(packet_queue)) {
			struct waiting_packet* packet = (struct waiting_packet*)queue_deq(packet_queue);

			// getting the eth and ip headers
			struct ether_header *eth_hdr = (struct ether_header *) packet->buf;

			// did we get the packet's mac?
			if(arphdr->spa == packet->next) {
				// sending the packet
				memcpy(eth_hdr->ether_dhost, arphdr->sha, sizeof(eth_hdr->ether_dhost));

				get_interface_mac(interface, eth_hdr->ether_shost);

				send_to_link(interface, packet->buf, packet->len);
			} else {
				// requeuing
				queue_enq(aux, packet);
			}
		}
		packet_queue = aux;
	} else {
		// reply isn't for me, sending it forward
		struct route_table_entry* best_hop = search_in_trie(arphdr->tpa);

		send_to_link(best_hop->interface, buf, len);
	}
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// getting broadcast mac
	memset(mac_broadcast, 0xFF, sizeof(mac_broadcast));

	// parsing routing table
	rtable = malloc(sizeof(struct route_table_entry) * 80000);
	DIE(rtable == NULL, "memory");

	rtable_len = read_rtable(argv[1], rtable);

	// turning the table into a trie
	build_route_trie();

	// initializing arp table
	arp_table = malloc(sizeof(struct arp_table_entry) * ARP_INIT_SIZE);
	DIE(arp_table == NULL, "memory");

	arp_table_len = 0;
	arp_max = ARP_INIT_SIZE;

	// initializing queue
	packet_queue = queue_create();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		// getting the interface mac address
		uint8_t mac_system[6];
		get_interface_mac(interface, mac_system);
		
		// verifying if the packet has the correct destination
		if(memcmp(mac_system, eth_hdr->ether_dhost, sizeof(mac_system)) != 0 && memcmp(mac_broadcast, eth_hdr->ether_dhost, sizeof(mac_system) != 0)
				&& eth_hdr->ether_type != htons(ARP_type)) {
			printf("Wrong destination packet thrown\n");
			continue;
		}

		// verifying packet type
		if(eth_hdr->ether_type == htons(IPv4_type)) {
			// the packet is IPv4, extracting the header
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			// checking if the router is the destination
			if(ip_hdr->daddr == parse_address(get_interface_ip(interface))) {
				// send Echo Reply
				struct icmphdr* icmp_hdr = (struct icmphdr*)(buf + sizeof(struct ether_header)
					+ sizeof(struct iphdr));
				if(icmp_hdr->type == 8) {
					sendICMP(interface, eth_hdr, ip_hdr, buf, 0);
				}
				
				continue;
			}

			// checking the checksum
			uint16_t old_check = ip_hdr->check;
			ip_hdr->check = 0;

			if(old_check != htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)))) {
				printf("Corrupted checksum packet thrown\n");
				memset(buf, 0, sizeof(buf));
				continue;
			}

			// checking the ttl
			if(ip_hdr->ttl <= 1) {
				printf("Low TTL packet thrown\n");
				// sending back icmp message
				sendICMP(interface, eth_hdr, ip_hdr, buf, 11);
				continue;
			}

			// decrementing ttl and actualizing checksum
			uint16_t old_ttl;
			old_ttl = ip_hdr->ttl;

			ip_hdr->ttl--;
			ip_hdr->check = ~(~old_check +  ~((uint16_t)old_ttl) + (uint16_t)ip_hdr->ttl) - 1;

			// finding next router
			struct route_table_entry* best_hop = search_in_trie(ip_hdr->daddr);
			if(best_hop == NULL) {
				printf("No next hop packet thrown\n");
				sendICMP(interface, eth_hdr, ip_hdr, buf, 3);
				continue;
			}

			// updating ethernet info
			struct arp_table_entry* next_arp_entry = get_arp_entry(best_hop->next_hop);

			if (next_arp_entry == NULL) {
				// sending ARP request and queueing the packet
				send_ARP_request(best_hop->next_hop);

				struct waiting_packet p;

				p.buf = malloc(sizeof(buf));
				memcpy(p.buf, buf, sizeof(buf));
				p.len = len;
				p.next = best_hop->next_hop;
				queue_enq(packet_queue, &p);

				continue;
			}

			memcpy(eth_hdr->ether_dhost, next_arp_entry->mac, sizeof(eth_hdr->ether_dhost));

			get_interface_mac(interface, eth_hdr->ether_shost);

			// sending packet
			printf("Packet sent to %d!\n", best_hop->interface);
			send_to_link(best_hop->interface, buf, len);

		} else if(eth_hdr->ether_type == htons(ARP_type)) {
			// the packet is ARP => extracting the header
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

			if(ntohs(arp_hdr->op) == 1) {
				// request
				printf("Got request\n");
				handle_ARP_request(eth_hdr, arp_hdr, buf, len, interface);
			} else if (ntohs(arp_hdr->op) == 2) {
				// reply
				handle_ARP_reply(arp_hdr, buf, len, interface);
			}
		} else {
			// the packet is not a supported type
			printf("Wrong type packet thrown\n");
			continue;
		}
	}
}

