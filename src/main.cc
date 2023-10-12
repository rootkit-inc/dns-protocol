/* * -L. -fno-rtti -fno-exceptions
*/

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include "../includes/includes.h"
#ifndef _SERVER_CONF_H
#include "../includes/dns.h"
#endif
#include "../includes/hexdump.h"

int main(int argc, char *argv[]) {
  int sockfd;
  struct sockaddr_in addr;
  char buffer[1024];
  socklen_t addr_size;
  char *ip = (char*)malloc(7*sizeof(char));
  memcpy(ip, "8.8.8.8", 7);

  DNS_Msg man;
  dns_message_t *msg = (dns_message_t*)man.CreateHeader(0xdede,0x0100,1,3,1,1);
  man.Qsec_push(msg, (char*)"test.com", 1, 1, 1);
  rdata_t rr = (rdata_t)man.new_rdata("2a00:1450:4014:80e::200e", AF_INET6);
  rdata_t rr1 = (rdata_t)man.new_rdata("1.2.9.255", AF_INET);
  man.push_RR(msg, 0xc00c, RR_TYPE_AAAA, 0x1, 0xff, rr.size, rr);
  man.push_RR(msg, 0xc00c, RR_TYPE_A, 0x1, 0xff, rr1.size, rr1);
  man.push_RR(msg, 0xc00c, RR_TYPE_A, 0x1, 0xff, rr1.size, rr1);
  man.push_AR(msg, 0xc00c, RR_TYPE_A, 0x1, 0xff, rr1.size, rr1);
  man.push_NS(msg, 0xc00c, RR_TYPE_A, 0x1, 0xff, rr1.size, rr1);
  // printf("%x %x %x\n=====================\n", rr.size, msg->RRsec[1].RDLen, msg->RRsec[2].RDLen);


  packed_dns_msg_t *sendit = man.pack_msg(msg);

  hexdump((char*)sendit->addr, sendit->size);



  man.Free(msg);
  // exit(0);
  // int port = atoi(argv[1]);
//  0000   d0 6d c9 88 f4 67 4c d5 77 5d 56 2d 08 00 45 00   .m...gL.w]V-..E.
// 0010   00 37 b6 56 40 00 40 11 00 f8 c0 a8 01 16 c0 a8   .7.V@.@.........
// 0020   01 01 e0 34 00 35 00 23 c2 47 96 67 01 00 00 01   ...4.5.#.G.g....
// 0030   00 00 00 00 ->>>>>[05] 68 65 6c 6c 6f [03] 6e 65 74   .......hello.net
// 0040   00 00 01 00 01                                    .....

 
  sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(53);
  addr.sin_addr.s_addr = inet_addr(ip);
 
  sendto(sockfd, sendit->addr, sendit->size, 0, (struct sockaddr*)&addr, sizeof(addr));
  // recvfrom(sockfd, buffer, 512, 0, (struct sockaddr*)&addr, sizeof(addr));

  // dns_err_tuple_t readit = man.unpack_msg((char*)buffer, 512);
  // if(readit.errnum != ALL_GOOD) {
  //   printf("ERROR %x\n\n", readit.errnum);
  //   exit(0);
  // }
  
  // packed_dns_msg_t *sendit = man.pack_msg(msg23);

 free(ip);
 close(sockfd);

	return 0;
}