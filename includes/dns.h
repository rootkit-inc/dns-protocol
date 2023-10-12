#define _SERVER_CONF_H

#include "includes.h"
#include "error.h"





#define MAX_DNS_QCOUNT 100		// ( 512 - 12(HDR) ) / 5 ( QName (MIN 0x00 - 1) QClass (2) + QType (2) )
#define MAX_DNS_RDATA_COUNT 23	// ( 512 - 12(HDR) ) -  20 RDATA + 1 RDATA.addr  (if addr = 0x00)


#define ALL_GOOD 				0x1
#define ERROR_QNUM_TOO_BIG 		0x22
#define ERROR_ANUM_TOO_BIG 		0x23
#define ERROR_AUTHNUM_TOO_BIG	0x24
#define ERROR_ADDNUM_TOO_BIG	0x25

typedef struct {
	dns_message_t 	*dns_msg;
	int  			errnum;
} dns_err_tuple_t;

#define NEW_ERR_TUPLE(dns, err_code) ({					\
				dns_err_tuple_t err;				\
				err.dns_msg = (dns_message_t*)dns;	\
				err.errnum = (int)err_code;				\
				(dns_err_tuple_t)err;							\
})

// typedef dns_message_t (*new_dns_t)(uint16_t, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t);
typedef merror_t (*dns_handler_t)(int server_sock);

typedef struct {
	dns_handler_t 	*handler;
} dns_server_config;

typedef struct {
	char *addr;
	int size;
} packed_dns_msg_t;


class DNS_Msg {
public:
	dns_message_t *CreateHeader(uint16_t, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t);
	uint16_t Forge_Flagz(dns_flagz_t flags);
	uint16_t new_flagz(uint8_t,uint8_t,uint8_t,uint8_t,uint8_t,uint8_t,uint8_t,uint8_t);
	void stick_flagz(dns_message_t *, uint16_t);
	ResRec_t *CreateResRec(uint16_t, uint16_t, uint16_t, uint32_t, uint16_t, rdata_t);
	Question_t *CreateQuestion(char*, uint16_t, uint16_t, int);
	rdata_t new_rdata(const char * , int);

	void Qsec_push(dns_message_t *, char*, uint16_t, uint16_t, int);
	void ResRec_push(ResRec_t **, int, ResRec_t *);
	void push_RR(dns_message_t *, uint16_t, uint16_t, uint16_t, uint32_t, uint16_t, rdata_t);
	void push_NS(dns_message_t *, uint16_t, uint16_t, uint16_t, uint32_t, uint16_t, rdata_t);
	void push_AR(dns_message_t *, uint16_t, uint16_t, uint16_t, uint32_t, uint16_t, rdata_t);
	packed_dns_msg_t *pack_msg(dns_message_t *);
	void Free(dns_message_t *);

	ResRec_t *unpack_RR(uint8_t *, int*, int);
	int unpack_ALL_Asec(dns_message_t *, int, uint8_t *, int, int);
	int unpack_ALL_NSsec(dns_message_t *, int, uint8_t *, int, int);
	int unpack_ALL_ARsec(dns_message_t *, int, uint8_t *, int, int);
	int unpack_ALL_Qsec(dns_message_t *, int, uint8_t *, int, int);
	dns_err_tuple_t unpack_msg(char *, int);

};