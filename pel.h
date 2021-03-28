#ifndef _PEL_H
#define _PEL_H

#include <sodium.h>

#define BUFSIZE 4096 /* maximum message length */

#define PEL_SUCCESS 0
#define PEL_FAILURE -1

#define PEL_SYSTEM_ERROR           -1
#define PEL_KEY_GENERATION_ERROR   -2
#define PEL_KEY_AGREEMENT_ERROR    -3
#define PEL_SYNCHRONIZATION_ERROR  -4
#define PEL_CONN_CLOSED            -5
#define PEL_CORRUPTED_DATA         -6
#define PEL_BAD_MSG_LENGTH         -7
#define PEL_UNDEFINED_ERROR        -8

#define TAG_FINAL crypto_secretstream_xchacha20poly1305_TAG_FINAL
#define TAG_PUSH crypto_secretstream_xchacha20poly1305_TAG_PUSH

#define ENCRYPTED_LEN_SIZE (sizeof(unsigned int) + crypto_secretstream_xchacha20poly1305_ABYTES)

extern int pel_errno;

int pel_client_init( int server );

int pel_client_derive_kp( const char *seed, const unsigned char* salt);
void pel_client_pk( unsigned char *pk );

int pel_server_init( int client, const unsigned char *pk );

void pel_destroy();

int pel_send_msg( int sockfd, unsigned char *msg, unsigned int length, const unsigned char tag );
int pel_recv_msg( int sockfd, unsigned char *msg, unsigned int *length, unsigned char *tag );

#endif /* pel.h */
