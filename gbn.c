#include "gbn.h"

state_t s;

volatile sig_atomic_t timeout_occurred = 0;

void print_sockaddr(const struct sockaddr *addr) {
    if (addr->sa_family == AF_INET) {  /* Check if the address is IPv4 */
        const struct sockaddr_in *addr_in = (const struct sockaddr_in *)addr;
        
        /* Convert the IP address to a string */
        char ip_str[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, sizeof(ip_str)) == NULL) {
            perror("inet_ntop failed");
            return;
        }

        /* Convert the port number from network byte order to host byte order */
        unsigned int port = ntohs(addr_in->sin_port);

        printf("IPv4 Address: %s, Port: %u\n", ip_str, port);
    } else {
        printf("Address family is not AF_INET, currently unsupported for printing\n");
    }
}

void print_gbnhdr(const gbnhdr *packet) {
    printf("Packet Type: %u\n", packet->type);
    printf("Sequence Number: %u\n", packet->seqnum);
    printf("Checksum: 0x%04x\n", packet->checksum);

    printf("Data (first 10 bytes): ");
		int i = 0;
		while (i < 10 && i < DATALEN) {
			printf("%02x ", packet->data[i]);
			++i;
		}
    printf("\n");
}

void timeout_handler(int signum) {
	printf("we timedout cuh\n");
	timeout_occurred = 1;
}

uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

/* Check Finite state specification from the textbook */
ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	printf("entered\n");
	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

	gbnhdr *data_packet = (gbnhdr*)malloc(sizeof(gbnhdr));
	gbnhdr *ack_packet = (gbnhdr*)malloc(sizeof(gbnhdr));
	ack_packet->type = DATAACK;
	memset(ack_packet->data, '\0', sizeof(ack_packet->data));

	if (len == 0) {
		return 0;
	}

	size_t packets_sent = 0;
	size_t total_packets = (len + DATALEN - 1) / DATALEN; /* round up */
	size_t wraparound = (len % DATALEN == 0) ? DATALEN : len % DATALEN;

	printf("current status %d \n", s.current_status);

	while (packets_sent < total_packets && s.current_status == ESTABLISHED) {
		size_t endpoint = packets_sent + s.window_size > total_packets ? 
				total_packets : packets_sent + s.window_size;
		int first_packet_sent = 0;

		while (packets_sent < endpoint) {
			
			data_packet->type = DATA;

			data_packet->seqnum = s.seqnum;
			printf("data_packet_seqnum is %d \n", data_packet->seqnum);
			s.seqnum += (uint8_t)1;

			memset(data_packet->data, '\0', sizeof(data_packet->data)); 
			size_t packet_length = (packets_sent + 1) == total_packets ? wraparound : DATALEN;
			memcpy(data_packet->data, (uint8_t *) buf + packets_sent * DATALEN, packet_length);

			data_packet->checksum = 0;
			uint16_t checksum_number = checksum((uint16_t*)data_packet,
				(sizeof(data_packet->type) + sizeof(data_packet->seqnum) + sizeof(data_packet->data) / sizeof(uint16_t)));
			
			data_packet->checksum = checksum_number;

			packets_sent += 1;

			printf("trying to send packet%d\n", packets_sent);
			printf("packet of length %d\n", packet_length);
			print_sockaddr(s.address);

			printf("printing data packet\n");
			print_gbnhdr(data_packet);
			
			printf("sockfd %d", s.sockfd);
			printf("Socklen: %u\n", (unsigned int)*s.socklen);

			int retval = maybe_sendto(sockfd, data_packet, sizeof(*data_packet), 0, s.address, *s.socklen);

			if (retval == -1) {
				printf("Error sending data packet\n");
				free(data_packet); 
				return -1;
			} 

			if (first_packet_sent == 0) {
				alarm(TIMEOUT);
				first_packet_sent = 1;
			}
		}

		while (recvfrom(sockfd, ack_packet, sizeof(*ack_packet), 0, s.address, s.socklen) != -1) {
			uint16_t ack_packet_checksum = ack_packet->checksum;
			ack_packet->checksum = 0;
			uint16_t computed_checksum = checksum((uint16_t*)ack_packet, 
				(sizeof(ack_packet->type) + sizeof(ack_packet->seqnum) + sizeof(ack_packet->data) / sizeof(uint16_t)));

			if (ack_packet_checksum == computed_checksum) {
				printf("og ma\n");
			}
		}
	}

	return(-1);
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){
	/* TODO: Your code here. */
	gbnhdr *data_packet = malloc(sizeof(*data_packet));
	data_packet->type = DATA;
	/*ata_packet->seqnum = 0;*/
  	/*memset(data_packet->data, '\0', sizeof(data_packet->data));*/

  	/* Initial ACK packet */
  	gbnhdr *ack_packet = malloc(sizeof(*ack_packet));
  	memset(ack_packet->data, '\0', sizeof(ack_packet->data));

	print_sockaddr(s.address);
	printf("socklen: %u\n", (unsigned int)*s.socklen);

	while (s.current_status == ESTABLISHED) {
    	if (maybe_recvfrom(sockfd, data_packet, sizeof(*data_packet), flags, s.address, s.socklen) != -1) {
			print_gbnhdr(data_packet);
			uint16_t data_packet_checksum = data_packet->checksum;
			data_packet->checksum = 0;

			uint16_t computed_checksum = checksum((uint16_t*)data_packet,
				(sizeof(data_packet->type) + sizeof(data_packet->seqnum) + sizeof(data_packet->data) / sizeof(uint16_t)));

			if (computed_checksum == data_packet_checksum) {
				printf("S Sequence Number: %u\n", s.seqnum);
				printf("D Sequence Number: %u\n", data_packet->seqnum);

				if (s.seqnum + 1 == data_packet->seqnum) {
					printf("RECEIVED CORRECT\n");
					
					/*s.seqnum = data_packet->seqnum + (uint8_t)1;
					printf("seqnum is now %d\n", s.seqnum);*/

					ack_packet->seqnum = s.seqnum + 1;
					ack_packet->checksum = 0;  
					ack_packet->checksum = checksum((uint16_t*)ack_packet, 
							(sizeof(ack_packet->type) + sizeof(ack_packet->seqnum) + sizeof(ack_packet->data) / sizeof(uint16_t)));

					if (maybe_sendto(sockfd, ack_packet, sizeof(*ack_packet), 0, s.address, *s.socklen) != -1) {
							printf("Sent ack for data packet\n");
					} else {
							printf("Unable to send ack for data packet\n");
					}
					/* put in buffer */
					s.seqnum += 1;
				} else {
					printf("DID NOT RECEIVE CORRECT (sequence number mismatch)\n");
					ack_packet->seqnum = s.seqnum;
					ack_packet->checksum = 0;
					ack_packet->checksum = checksum((uint16_t*)ack_packet, 
							(sizeof(ack_packet->type) + sizeof(ack_packet->seqnum) + sizeof(ack_packet->data) / sizeof(uint16_t)));

					if (maybe_sendto(sockfd, ack_packet, sizeof(*ack_packet), 0, s.address, s.socklen) != -1) {
							printf("Resent ack for previous data packet\n");
					} else {
							printf("Unable to resend ack for previous data packet\n");
					}
				}
			} else {
					printf("Checksum mismatch\n");
			}
    	}
	}
	return(-1);
}

int gbn_close(int sockfd){

	/* TODO: Your code here. */

	/* FIN packet must be sent by the party that wants to close the connection
	 The other party will respond with a FIN-ACK packet */

	return(-1);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* TODO: Your code here. */

	/* SYN packet must be sent to the server to initiate the connection
	 The server will respond with a SYN-ACK packet if it accepts or a RST packet if it rejects */
	
	/* Initialize a packet with the gbnhdr with type SYN */
	printf("server address before saving in gbn_connect\n");
	print_sockaddr(server);
	printf("sockfd %d", sockfd);
	printf("Socklen: %u\n", (unsigned int)socklen);

	gbnhdr *syn_packet = (gbnhdr*)malloc(sizeof(gbnhdr));
	syn_packet->type = SYN;
	syn_packet->seqnum = s.seqnum;
	/* clear data payload as we are not sending data */
	memset(syn_packet->data, '\0', sizeof(syn_packet->data));
	/* calculate the checksum */
	syn_packet->checksum = 0;
	uint16_t checksum_number = checksum((uint16_t*)syn_packet, 
			(sizeof(syn_packet->type) + sizeof(syn_packet->seqnum) + sizeof(syn_packet->data) / sizeof(uint16_t)));
	syn_packet->checksum = checksum_number;

	s.current_status = SYN_SENT;
	int current_attempts = 0;

	gbnhdr *syn_ack_packet = (gbnhdr*)malloc(sizeof(gbnhdr));
	memset(syn_ack_packet->data, '\0', sizeof(syn_ack_packet->data));
	
	while (s.current_status == SYN_SENT && current_attempts < 3) {
		/* Send SYN packet */
		if (maybe_sendto(sockfd, syn_packet, sizeof(*syn_packet), 0, server, socklen) == -1) {
			printf("Error sending SYN packet\n");
			free(syn_packet);
			free(syn_ack_packet);
			return -1;
		}
		printf("Sent SYN packet attempt %d\n", current_attempts);

		alarm(TIMEOUT);
		current_attempts++;

		struct sockaddr temp;
		socklen_t temp_size = sizeof(temp);

		int recv_result = maybe_recvfrom(sockfd, (char *) syn_ack_packet, sizeof(*syn_ack_packet), 0, &temp, &temp_size);

		if (recv_result != -1) {
			uint16_t saved_checksum = syn_ack_packet->checksum;
			syn_ack_packet->checksum = 0;
			uint16_t synack_checksum_number = checksum((uint16_t*)syn_ack_packet, 
				((sizeof(syn_ack_packet->type) + sizeof(syn_ack_packet->seqnum) + sizeof(syn_ack_packet->data) / sizeof(uint16_t))));

			if (syn_ack_packet->type == SYNACK && synack_checksum_number == saved_checksum) {
				if (syn_ack_packet->seqnum == s.seqnum) { 
						printf("SYNACK Packet Received\n");
						s.seqnum += (uint8_t)1;
						printf("incremented seqnum to %d\n", s.seqnum);
						s.address = (struct sockaddr *) server;
						s.socklen = malloc(sizeof(socklen_t));
						*s.socklen = socklen;
						printf("THIS IS WHERE IT MATTERS: %u\n", (unsigned int)*s.socklen);

						s.current_status = ESTABLISHED;

						printf("reciever server after saving in gbn_connect\n");
						print_sockaddr(s.address);

				}
			} else if (syn_ack_packet->type == RST && synack_checksum_number == syn_ack_packet->checksum) {
				printf("Recieved an RST packet\n");
				s.current_status = CLOSED;
			}

		} else {
			if (errno == EINTR && timeout_occurred == 1) {
				timeout_occurred = 0;
				printf("Timeout occurred\n");
			} else {
				printf("Error receiving SYN-ACK packet\n");
			}
			printf("Retrying...\n");
		}
	}

	/* Free the memory allocated for the packets */
	free(syn_packet);
	free(syn_ack_packet);

	if (current_attempts == 3) {
		printf("Reached the maximum number of attempts many attempts\n");
		s.current_status = CLOSED;
	} else if (s.current_status == CLOSED) {
		printf("Connection failed\n");
		return -1;
	} else if (s.current_status == ESTABLISHED) {
		printf("Connection established\n");
		return 0;
	}

	return(-1);
}

int gbn_listen(int sockfd, int backlog){
	s.current_status = LISTENING;
	printf("Socket is listening on port %d\n", sockfd);
	return 0;
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){

	int bind_val = bind(sockfd, server, socklen);
	if (bind_val == -1) {
		printf("Error binding socket\n");
		return -1;
	}

	return bind_val;
}

int gbn_socket(int domain, int type, int protocol){
		
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));

	printf("Initializing the GBN protocol...\n");

	s = *(state_t*)malloc(sizeof(state_t));
	/* s.seqnum = rand() % 256; random initial sequence number */
	
	int sockfd = socket(domain, type, protocol);
	if (sockfd == -1) {
		printf("Error creating socket\n");
		return -1;
	}
	printf("Created socket with fd: %d\n", sockfd);
	s.sockfd = sockfd;
	s.window_size = 1;
	s.current_status = CLOSED;
	s.seqnum = 0;

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = timeout_handler;
	sigaction(SIGALRM, &sa, NULL);

	return sockfd;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){
	printf("Ready to accept connection on port %d\n", sockfd);
	gbnhdr *syn_packet = (gbnhdr*)malloc(sizeof(gbnhdr));
	memset(syn_packet->data, '\0', sizeof(syn_packet->data));

	gbnhdr *syn_ack_packet = (gbnhdr*)malloc(sizeof(gbnhdr));
	syn_ack_packet->type = SYNACK;
	memset(syn_ack_packet->data, '\0', sizeof(syn_ack_packet->data));

	struct sockaddr sender_addr;
	socklen_t sender_len = sizeof(sender_addr);

	/* TODO: Your code here. */
	while (s.current_status != ESTABLISHED) {
		if (s.current_status == LISTENING) {

			int recv_result = maybe_recvfrom(sockfd, (char *) syn_packet, sizeof(*syn_packet), 0, client, socklen);
			if (recv_result != -1) {
				uint16_t saved_checksum = syn_packet->checksum;
				syn_packet->checksum = 0;
				uint16_t syn_checksum_number = checksum((uint16_t*)syn_packet, 
					((sizeof(syn_packet->type) + sizeof(syn_packet->seqnum) + sizeof(syn_packet->data) / sizeof(uint16_t))));
		
				if (syn_packet->type == SYN && syn_checksum_number == saved_checksum) {
					printf("Recieved SYN\n");
					/* s.seqnum = syn_packet->seqnum; */
					s.current_status = SYN_RCVD;
				} else {
					printf("Packet Incorrect\n");
				}
			}
		} else if (s.current_status == SYN_RCVD) {
			/* Send SYN-ACK packet */
			syn_ack_packet->seqnum = s.seqnum;
			uint16_t checksum_number = checksum((uint16_t*)syn_ack_packet, 
					(sizeof(syn_ack_packet->type) + sizeof(syn_ack_packet->seqnum) + sizeof(syn_ack_packet->data) / sizeof(uint16_t)));
			syn_ack_packet->checksum = checksum_number;

			if (maybe_sendto(sockfd, syn_ack_packet, sizeof(*syn_ack_packet), 0, client, *socklen) == -1) {
				printf("Error sending SYN-ACK packet\n");
				free(syn_packet);
				free(syn_ack_packet);
				return -1;
			} else {
			/* Wait for data packet*/
				printf("Connection Estabalished\n");
				print_sockaddr(client);
				s.address = (struct sockaddr *) client;
				s.socklen = malloc(sizeof(socklen_t));
				*s.socklen = *socklen;
				s.current_status = ESTABLISHED;
			}
		}
	}

	free(syn_packet);
	free(syn_ack_packet);
	return s.current_status == ESTABLISHED ? sockfd : -1;
}

/* I changed sockaddr to const here be careful */
ssize_t maybe_recvfrom(int s, char *buf, size_t len, int flags, const struct sockaddr *from, socklen_t *fromlen){
	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX){


		/*----- Receiving the packet -----*/
		int retval = recvfrom(s, buf, len, flags, from, fromlen);
		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX){
			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buf[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buf[index] = c;
		}

		return retval;
	}
	/*----- Packet lost -----*/
	return(len);  /* Simulate a success */
}

ssize_t maybe_sendto(int  s, const void *buf, size_t len, int flags, \
                     const struct sockaddr *to, socklen_t tolen){

    char *buffer = malloc(len);
    memcpy(buffer, buf, len);
    
    
    /*----- Packet not lost -----*/
    if (rand() > LOSS_PROB*RAND_MAX){
        /*----- Packet corrupted -----*/
        if (rand() < CORR_PROB*RAND_MAX){
            
            /*----- Selecting a random byte inside the packet -----*/
            int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

            /*----- Inverting a bit -----*/
            char c = buffer[index];
            if (c & 0x01)
                c &= 0xFE;
            else
                c |= 0x01;
            buffer[index] = c;
        }

        /*----- Sending the packet -----*/
        int retval = sendto(s, buffer, len, flags, to, tolen);
        free(buffer);
		return retval;
    }
    /*----- Packet lost -----*/
    else
        return(len);  /* Simulate a success */
}
