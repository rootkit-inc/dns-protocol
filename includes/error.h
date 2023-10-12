#ifndef _ERROR_H
#define _ERROR_H

#include "includes.h"
#include <errno.h>

#define MAX_NEW_ERROR_LENGTH 120

#define SERVER_FUCKED 0xdead

typedef struct {
	int errno;
	int num;
	char msg[MAX_NEW_ERROR_LENGTH];
} merror_t;

#define NEW_ERROR(is_errno, err_num, str, ...) ({							\
					merror_t *err = (merror_t *)malloc(sizeof(merror_t));	\
					err->num 	  = err_num;		 						\
					snprintf(err->msg, MAX_NEW_ERROR_LENGTH-1, str, ##__VA_ARGS__); \
					err;								\
				})

#define FREE(addr) (free(addr))

#define DIE(str, ...) ({					\
			fprintf(stderr, str, ##__VA_ARGS__);	\
			exit(-1);								\
		})
#endif