#include <assert.h>
#include <arpa/inet.h>
#include "../includes/includes.h"
#include "../includes/dns.h"
// #include "../includes/hexdump.h"


dns_message_t *DNS_Msg::CreateHeader(uint16_t id, uint16_t flagz, uint16_t q, uint16_t a, uint16_t auth, uint16_t add) {
	dns_message_t *msg = (dns_message_t*)malloc(sizeof(dns_message_t));
	memset(msg, 0, sizeof(dns_message_t));
	msg->hdr = {
		.id 			= htons(id),
		.flagz_ncodez	= htons(flagz),
		.q_count 		= htons(q),
		.a_count 		= htons(a),
		.auth_count 	= htons(auth),
		.add_count 		= htons(add),
	};

	return msg;
}

uint16_t DNS_Msg::Forge_Flagz(dns_flagz_t flags) {
	if (!(flags.QR <= 1 && flags.Opcode <= 15 && flags.AA <= 1 && flags.TC <= 1 &&
		  flags.RD <= 1 && flags.RA <= 1 && flags.Z <= 7 && flags.RCode <= 15))
	{
		fprintf(stderr, "Wrong flag sizes @dns_forge_Flagz");

		return 0;
	}

	uint16_t output = uint16_t(0);

	output |= flags.QR << 15;		// 1 bit
	output |= flags.Opcode << 11;	// 4 bits
	output |= flags.AA << 10;		// 1 bit
	output |= flags.TC << 9;		// 1 bit
	output |= flags.RD << 8;		// 1 ...
	output |= flags.RA << 7;		// 1 ...
	output |= flags.Z << 4;			// 3 bits
	output |= flags.RCode << 0;		// 4 bits - [0] bit counts

	return output;
}

uint16_t DNS_Msg::new_flagz(uint8_t qr, uint8_t op, uint8_t aa, uint8_t tc, uint8_t rd, uint8_t ra, uint8_t z, uint8_t rcode)
{
	return this->Forge_Flagz(dns_flagz_t{.QR=qr, .Opcode=op, .AA=aa, .TC=tc, .RD=rd, .RA=ra, .Z=z, .RCode=rcode});	
}

void DNS_Msg::stick_flagz(dns_message_t *msg, uint16_t flagz) {
	msg->hdr.flagz_ncodez = flagz;
}

size_t near_nullbyte(char *addr, size_t limit) {
	int i;
	for (i = 0; i <= limit && addr[i] != 0x0; i++) {}
	return (i <= limit) ? i : -1;
}

size_t times_char(char *str, char delim, size_t max) {
	size_t ret = 0;

	for (int i = 0; i < max; i++, ret++)
		if (str[i] == delim)
			ret++;

	return ret;
}

size_t until_char(char *str, char delim, size_t max) {
	for (int i = 0; i < max; i++) {
		if (str[i] == delim || str[i] == '\x00')
			return i;
	}
	return 0;
}

char *dns_split_dot(char *str, int max) {			// FREE ME
	assert(max < 512);		// Max UDP packet size
	int size = (int)times_char(str, '.', (size_t)max);
	char *output = (char*)malloc(size*sizeof(unsigned char));
	int j = 0;
	int not_taken = 1;
	
	max = (int)near_nullbyte(str, max);
	assert(max != -1);

	for (int i = 0; i < max; i++, j++) {
		if (i == 0 && not_taken == 1) {
			output[j] = (char)until_char(&str[i], '.', max);
			not_taken = 0; i--;
			continue;
		}
		if (str[i] == '.') {
			output[j] = (char)until_char(&str[i+1], '.', max);
			continue;
		}
		output[j] = str[i];
	}
	
	return output;
}

ResRec_t *DNS_Msg::CreateResRec(uint16_t name, uint16_t type, uint16_t cls, uint32_t ttl, uint16_t rdlen, rdata_t data)
{
	ResRec_t *rr = (ResRec_t*)malloc(sizeof(ResRec_t));
	memset(rr, 0, sizeof(ResRec_t));
	*rr = {
		.Name	= htons(name),		// shall be a pointer
		.Type	= htons(type),
		.Class 	= htons(cls),
		.TTL	= htonl(ttl),
		.RDLen	= htons(rdlen),
		.RData	= data,
	};
	
	return rr;
}


Question_t *DNS_Msg::CreateQuestion(char *name, uint16_t type, uint16_t cls, int split_dot)
{
	Question_t *q = (Question_t*)malloc(sizeof(Question_t));
	memset(q, 0, sizeof(Question_t));

	*q = {
		.QName = (split_dot == 0) ? name : dns_split_dot(name, 253),		// format to split at '.' and repalce with until next '.'
		.QType = htons(type),
		.QClass = htons(cls),
	};

	return q;
}

rdata_t DNS_Msg::new_rdata(const char * dat, int type) {
	unsigned char addr_v4[sizeof(struct in_addr)];
	unsigned char addr_v6[sizeof(struct in6_addr)];

	rdata_t x;

	memset(&x, 0, sizeof(rdata_t));
	switch(type) {
	case AF_INET:
		x.addr = (char *)malloc(sizeof(uint32_t));
		memset(x.addr, 0, sizeof(uint32_t));
		assert(inet_pton(AF_INET, dat, addr_v4) == 1);
		memcpy(x.addr, addr_v4, sizeof(uint32_t));
		// printf("[][][]222[]DAT AT DET   %lx\n", *addr_v4);
		x.size = sizeof(uint32_t);
		x.type = type;
		break;
	case AF_INET6:
		x.addr = (char *)malloc(16*sizeof(uint8_t));
		memset(x.addr, 0, 16*sizeof(uint8_t));
		assert(inet_pton(AF_INET6, dat, addr_v6) == 1);
		memcpy(x.addr, addr_v6, 16);
		// hexdump((char*)x.addr, 16);
		x.size = 16;
		x.type = AF_INET6;
		break;
	}

	return x;
}

// AddNS / AddAR / AddRRec / AddQ
//


void DNS_Msg::Qsec_push(dns_message_t *m, char *name, uint16_t type, uint16_t cls, int split_dot) {
	if (m->Q == nullptr) {
		m->Q = (Question_t*)malloc(20*sizeof(Question_t));
	} else {
		if (m->meta.Qnum >= 20 && m->meta.Qnum %10 == 0)
			m->Q = (Question_t*)realloc(m->Q, m->meta.Qnum+10 * sizeof(Question_t));
	}

	Question_t *question = this->CreateQuestion(name, type, cls, split_dot);
	memcpy((void*)(((uintptr_t)m->Q)+(uintptr_t)(m->meta.Qnum*sizeof(Question_t))), question, sizeof(Question_t));
	free(question);

	m->meta.Qnum++;
}

// The same as the above, but I am not going to fool around with Generics, just Yet
void DNS_Msg::ResRec_push(ResRec_t **rr, int num, ResRec_t *st) {
	if (*rr == nullptr) {
		*rr = (ResRec_t*)malloc(20*sizeof(ResRec_t));
	} else {
		if (num >= 20 && num %10 == 0)
			*rr = (ResRec_t*)realloc(*rr, num+10 * sizeof(ResRec_t));
	}

	memcpy((void*)((uintptr_t)*rr+(uintptr_t)((num)*sizeof(ResRec_t))), st, sizeof(ResRec_t));
}

							// memcpy(buffer+offset, dns_msg->Q[l].QName, len);		\


#define COPY_DNS_QSECTIONS(Q, buffer, offset, n) ({						\
					for (int l = 0; l < n; l++) {						\
						size_t len = near_nullbyte(Q[l].QName, 253)+1;	\
						assert(len != -1);									\
						memcpy(buffer+offset, Q[l].QName, len);					\
						memcpy(buffer+offset+len, &Q[l].QType, 2);				\
						memcpy(buffer+offset+len+2, &Q[l].QClass, 2);		\
						offset += len+2+2;								\
					}												\
				})

#define COPY_DNS_RRSECTIONS(RR, buffer, offset, n) ({					\
					for (int i = 0; i < n; i++) {						\
						int len = RR[i].RData.size;						\
						memcpy(buffer+offset, 	&RR[i].Name, 2);		\
						memcpy(buffer+offset+2, &RR[i].Type, 2);		\
						memcpy(buffer+offset+4, &RR[i].Class, 2);		\
						memcpy(buffer+offset+6, &RR[i].TTL, 4);			\
						memcpy(buffer+offset+10, &RR[i].RDLen, 2);		\
						memcpy(buffer+offset+12, RR[i].RData.addr, len);		\
						offset += len+12;								\
					}												\
				})													\

int get_total_QSec_sz(Question_t *Q, int n) {			// no near_null, just the str, look up
	int size = 0
;	for (int i = 0; i < n; i++) {
		size_t nearnull = near_nullbyte(Q[i].QName, 253)+1;			// + 0x00
		assert(nearnull != -1 && nearnull < 512);
		size += sizeof(Question_t);
		size += nearnull;
		size -= sizeof(char*);
	}
	return size;
}

int get_total_RRSec_sz(ResRec_t *RR, int n) {
	int size = 0;
	for (int i = 0; i < n; i++) {
		size += sizeof(ResRec_t);
		size += RR[i].RData.size;
		size -= sizeof(rdata_t);
	}
	return size;
}

packed_dns_msg_t *DNS_Msg::pack_msg(dns_message_t *dns_msg) {			// x_malloc and x_realloc
	packed_dns_msg_t *output = (packed_dns_msg_t*)malloc(sizeof(packed_dns_msg_t));
	memset(output, 0, sizeof(packed_dns_msg_t));
	int offset = 0;

	int size  = sizeof(dns_msg->hdr);
	size += get_total_QSec_sz(dns_msg->Q, dns_msg->meta.Qnum);
	size += get_total_RRSec_sz(dns_msg->RRsec, dns_msg->meta.RRnum);
	size += get_total_RRSec_sz(dns_msg->NS, dns_msg->meta.NSnum);
	size += get_total_RRSec_sz(dns_msg->AR, dns_msg->meta.ARnum);

	char *buffer = (char*)malloc(size);
	memset(buffer, 0, size);
	output->addr = buffer;
	output->size = size;

	assert(sizeof(dns_msg->hdr) == 6*sizeof(uint16_t));
	// Copy the DNS Header - 6*2 octets
	memcpy(buffer, &dns_msg->hdr, sizeof(dns_msg->hdr));
	offset += sizeof(dns_msg->hdr);


// printf("%i[[[[[[[[[[[[[[[[[[[[[[[[[[[\n",dns_msg->meta.RRnum);
	// Copy the DNS Questions
	// memset(buffer+offset, 'A', 10);
	COPY_DNS_QSECTIONS(dns_msg->Q, buffer, offset, dns_msg->meta.Qnum);
	COPY_DNS_RRSECTIONS(dns_msg->RRsec, buffer, offset, dns_msg->meta.RRnum);
	COPY_DNS_RRSECTIONS(dns_msg->NS, buffer, offset, dns_msg->meta.NSnum);
	COPY_DNS_RRSECTIONS(dns_msg->AR, buffer, offset, dns_msg->meta.ARnum);

// printf("%i <= %i\n", offset, size);

	return output;
}



void DNS_Msg::Free(dns_message_t *st) {
		free(st->Q);
		free(st->RRsec);
		free(st->NS);
		free(st->AR);
		free(st);
}


void DNS_Msg::push_RR(dns_message_t *m, uint16_t name, uint16_t type, uint16_t cls, uint32_t ttl, uint16_t rdlen, rdata_t data) {
	ResRec_t *rr = this->CreateResRec(name, type, cls, ttl, rdlen, data);
	this->ResRec_push(&m->RRsec, m->meta.RRnum, rr);
	free(rr);
	m->meta.RRnum++;
}

void DNS_Msg::push_NS(dns_message_t *m, uint16_t name, uint16_t type, uint16_t cls, uint32_t ttl, uint16_t rdlen, rdata_t data) {
	ResRec_t *rr = this->CreateResRec(name, type, cls, ttl, rdlen, data);
	this->ResRec_push(&m->NS, m->meta.NSnum, this->CreateResRec(name, type, cls, ttl, rdlen, data));
	free(rr);
	m->meta.NSnum++;
}

// htons htonl
void DNS_Msg::push_AR(dns_message_t *m, uint16_t name, uint16_t type, uint16_t cls, uint32_t ttl, uint16_t rdlen, rdata_t data) {
	ResRec_t *rr = this->CreateResRec(name, type, cls, ttl, rdlen, data);
	this->ResRec_push(&m->AR, m->meta.ARnum, this->CreateResRec(name, type, cls, ttl, rdlen, data));
	free(rr);
	m->meta.ARnum++;
}

/* hexdump - to dns_message_t
 *
 */



int DNS_Msg::unpack_ALL_Qsec(dns_message_t *msg, int qnum, uint8_t *bytes, int pos, int size) {
	for (int i = 0; i < qnum; i++) {
		size_t name_len = until_char((char*)&bytes[pos], '\x00', size);
		assert(name_len < size);

		char *name = (char *)malloc(name_len*sizeof(char));
		memcpy(name, &bytes[pos], name_len);
		pos += name_len+1;		// 0x00

		uint16_t qtype =  (bytes[pos] << 8) | bytes[pos+1]; pos+=2;
		uint16_t qclass = (bytes[pos] << 8) | bytes[pos+1]; pos+=2;

		// for (int l = 0; l < name_len; l++) {
		// 	printf("%02x.", name[l]);
		// }

		assert(pos <= size);
		this->Qsec_push(msg, name, qtype, qclass, 0);
		// msg->meta.Qnum++
	}


	return pos;
}

ResRec_t *DNS_Msg::unpack_RR(uint8_t *bytes, int *pos, int size) {
	ResRec_t *rr = (ResRec_t*)malloc(sizeof(ResRec_t));
	memset(rr, 0, sizeof(ResRec_t));

	rr->Name 	= htons((bytes[*pos] << 8) | bytes[*pos+1]); *pos+=2;
	rr->Type 	= htons((bytes[*pos] << 8) | bytes[*pos+1]); *pos+=2;
	rr->Class 	= htons((bytes[*pos] << 8) | bytes[*pos+1]); *pos+=2;
	rr->TTL	 	= htonl((bytes[*pos] << 24)| (bytes[*pos+1] << 16) | (bytes[*pos+2] << 8) | bytes[*pos+3]); *pos+=4;
	rr->RDLen 	= htons((bytes[*pos] << 8) | bytes[*pos+1]); *pos+=2;
	uint16_t rr_rdlen = ntohs(rr->RDLen);
	// printf("RDLEN %i %x\n", rr->RDLen, rr->RDLen);
	// printf("%x %x %x %x %i\n\n", rr->Name, rr->Type, rr->Class, rr->TTL, rr->RDLen);
	assert(rr_rdlen < size);

	memset(&rr->RData, 0, sizeof(rdata_t));
	rr->RData.addr = (char*)malloc(rr_rdlen*sizeof(char));
	rr->RData.size = rr_rdlen;

	memset(rr->RData.addr, 0, sizeof(rr_rdlen));
	memcpy(rr->RData.addr, &bytes[*pos], rr_rdlen);
	*pos += rr_rdlen;


	assert(*pos <= size);
	return rr;
}


int DNS_Msg::unpack_ALL_Asec(dns_message_t *m, int anum, uint8_t *bytes, int pos, int size) {
	for (int i = 0; i < anum; i++, m->meta.RRnum++) {
		ResRec_t *rr = this->unpack_RR(bytes, &pos, size);
		this->ResRec_push(&m->RRsec, m->meta.RRnum, rr);
		free(rr);
	}

	return pos;
}

int DNS_Msg::unpack_ALL_NSsec(dns_message_t *m, int nsnum, uint8_t *bytes, int pos, int size) {
	for (int i = 0; i < nsnum; i++, m->meta.NSnum++) {
		ResRec_t *rr = this->unpack_RR(bytes, &pos, size);
		this->ResRec_push(&m->NS, m->meta.NSnum, rr);
		free(rr);
	}

	return pos;
}

int DNS_Msg::unpack_ALL_ARsec(dns_message_t *m, int addnum, uint8_t *bytes, int pos, int size) {
	for (int i = 0; i < addnum; i++, m->meta.ARnum++) {
		ResRec_t *rr = this->unpack_RR(bytes, &pos, size);
		this->ResRec_push(&m->AR, m->meta.ARnum, rr);
		free(rr);
	}

	return pos;
}


dns_err_tuple_t DNS_Msg::unpack_msg(char *bytes_ch, int size) {
	uint8_t *bytes = (uint8_t*)bytes_ch;		// 0xffffffff arise when using char*
	int pos = 0;								// 
	// COPY the DNS Header
	dns_message_t *msg = this->CreateHeader(0, 0, 0, 0, 0, 0);
	memcpy(&msg->hdr.id, bytes, 12);
	pos+=12;

	// If there is more Questions/RDATA than can fit in a UDP message (512) return err
	if (ntohs(msg->hdr.q_count) > MAX_DNS_QCOUNT) 			return NEW_ERR_TUPLE(msg, ERROR_QNUM_TOO_BIG);
	if (ntohs(msg->hdr.a_count) > MAX_DNS_RDATA_COUNT) 		return NEW_ERR_TUPLE(msg, ERROR_ANUM_TOO_BIG);
	if (ntohs(msg->hdr.auth_count) > MAX_DNS_RDATA_COUNT) 	return NEW_ERR_TUPLE(msg, ERROR_AUTHNUM_TOO_BIG);
	if (ntohs(msg->hdr.add_count) > MAX_DNS_RDATA_COUNT) 	return NEW_ERR_TUPLE(msg, ERROR_ADDNUM_TOO_BIG);

	pos = this->unpack_ALL_Qsec(msg, ntohs(msg->hdr.q_count), bytes, pos, size);
	pos = this->unpack_ALL_Asec(msg, ntohs(msg->hdr.a_count), bytes, pos, size);
	pos = this->unpack_ALL_NSsec(msg, ntohs(msg->hdr.auth_count), bytes, pos, size);
	pos = this->unpack_ALL_ARsec(msg, ntohs(msg->hdr.add_count), bytes, pos, size);


	assert(pos <= size);

	return NEW_ERR_TUPLE(msg, ALL_GOOD);
}