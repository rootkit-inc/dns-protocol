// #define RDATA_T_IPV4 0x56
// #define RDATA_T_IPV6 0x88

#define RR_TYPE_A 1 			// IPv4
#define RR_TYPE_NS 2 			// NameServer
#define RR_TYPE_CNAME 5 		// domain name
#define RR_TYPE_NULL 10 		// NULL
#define RR_TYPE_AAAA 28			// IPv6

#ifndef _INCLUDES_H
#define _INCLUDES_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>


#define ERRNO_NON_FATAL(msg, ...) ({			\
	fprintf(stderr, msg, __VA_ARGS__);			\
	strerror(errno);							\
})

#pragma pack(1)
typedef struct {			// Sz Of Question_t - long
	char *QName;			//
	uint16_t QType;			// might just count with 2*16bit, 
	uint16_t QClass;		// not even bother with sizeof
} Question_t;


typedef struct {
	char *addr;
	int size;
	int type;
} rdata_t;

#pragma pack(1)
typedef struct {
	uint16_t Name;			// just copy paste this, until of RData, when do hit
	uint16_t Type;			// RData at [0] just read what it got, and go on
	uint16_t Class;			// NullByte 0x00 wonder?
	uint32_t TTL;			//
	uint16_t RDLen;
	rdata_t	RData;			// Address 
} ResRec_t;

typedef struct {			// +++ This struct out to be memset to 0
	#pragma pack(2)			//	because of Qnum, RRnum... has to be 0 if it's used 0 times
	struct {				//	for COPY_DNS_SECTION
		uint16_t id;
		uint16_t flagz_ncodez;
		/* QR (1 bits) - query response 0 - question 1 - response
		 * Opcode (4 bits)  - created by creator of query, Unchanged
		 * - 0 - Standard Query		|		2 - Server status request
		 * - 4 - Notify - request for me to request a zone transfer request by a Authorative server due to zone transfer
		 * - 5 - Update RRs to be updated deleted added
		 * AA (1 bit) - 1 - server is authorative 0 - no
		 * TC (1 bit) - truncated, UDP max 512b, if truncated portion is part of the Additional section, don't establish a TCP conn
		 * RD (1 bit) - Recursion Wanted - change to 0 if server is not doing recursion - client may set to 1, set to 0
		 * RA (1 bit) - Recursion Available -1 yes - 0 no
		 * Z  (3 bits) - 000 - reserved - always
		 * RCode (4 bits) - response code, set to 0 in queries changed by server
		 */
		uint16_t q_count;		// number of Questions in Question secton - only 1 question section
		uint16_t a_count;		// number of RRs in Answer section
		uint16_t auth_count;	// number of Auth stuff
		uint16_t add_count;		// number of additional RRs in Additional section
	} hdr;
	Question_t	*Q;			// Question
	ResRec_t	*RRsec;		// Answer - Resource Record
	ResRec_t	*NS;		// NameServer
	ResRec_t	*AR;		// Additional Record

	struct {
		int Qnum;
		int RRnum;
		int NSnum;
		int ARnum;
	} meta;
} dns_message_t;

typedef struct {			// Has ALREADY been stuck into 2 bytes
	uint8_t QR;				// @ -DNS_Msg::Forge_Flagz
	uint8_t Opcode;
	uint8_t AA;
	uint8_t TC;
	uint8_t RD;
	uint8_t RA;
	uint8_t Z;
	uint8_t RCode;
} dns_flagz_t;
#endif
