/*
 * Packet Encryption Layer for Tiny SHell Sodium,
 * by Christophe Devine <devine@cr0.net>;
 * by Mateusz Nalewajski <mateusz@nalewajski.pl>
 * this program is licensed under the GPL.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "pel.h"

/* global data */

int pel_errno;

unsigned char *client_pk = NULL;
unsigned char *client_sk = NULL;

unsigned char *server_pk = NULL;
unsigned char *server_sk = NULL;

unsigned char *rx_key = NULL;
unsigned char *tx_key = NULL;

crypto_secretstream_xchacha20poly1305_state *rx_state = NULL;
crypto_secretstream_xchacha20poly1305_state *tx_state = NULL;

unsigned char buffer[CRYPTO_BUFSIZE];

/* internal function declaration */

int pel_write_iov( int s, struct iovec *iov, int iovcnt );
int pel_write_all( int s, void *buf, size_t len );
int pel_read_all( int s, void *buf, size_t len );

/* session setup - client side */

int pel_client_init( int server )
{
    int ret;

    /* initialize libsodium */

    if (sodium_init() == -1) {
        pel_errno = PEL_SYSTEM_ERROR;

        return( PEL_FAILURE );
    }

    /* allocate memory */

    server_pk = sodium_malloc(crypto_kx_PUBLICKEYBYTES);

    rx_key = sodium_malloc(crypto_kx_SESSIONKEYBYTES);
    tx_key = sodium_malloc(crypto_kx_SESSIONKEYBYTES);

    rx_state = sodium_malloc(sizeof(crypto_secretstream_xchacha20poly1305_state));
    tx_state = sodium_malloc(sizeof(crypto_secretstream_xchacha20poly1305_state));

    if ( server_pk == NULL || rx_key == NULL || tx_key == NULL || rx_state == NULL || tx_state == NULL ) {
        pel_errno = PEL_SYSTEM_ERROR;

        return( PEL_FAILURE );
    }

    /* receive public key from server */

    ret = pel_read_all( server, server_pk, crypto_kx_PUBLICKEYBYTES );

    if( ret != PEL_SUCCESS ) return( PEL_FAILURE );

    /* handshake - generate shared keys */

    ret = crypto_kx_client_session_keys( rx_key, tx_key, client_pk, client_sk, server_pk );

    if( ret == -1 ) {
        pel_errno = PEL_KEY_AGREEMENT_ERROR;

        return( PEL_FAILURE );
    }

    /* initialize client stream cipher state */

    ret = crypto_secretstream_xchacha20poly1305_init_push( tx_state, buffer, tx_key );

    if( ret == -1 ) {
        pel_errno = PEL_SYNCHRONIZATION_ERROR;

        return( PEL_FAILURE );
    }

    /* transmit client stream cipher header */

    ret = pel_write_all( server, buffer, crypto_secretstream_xchacha20poly1305_HEADERBYTES );

    if( ret != PEL_SUCCESS ) return( PEL_FAILURE );

    /* receive server stream cipher header */

    ret = pel_read_all( server, buffer, crypto_secretstream_xchacha20poly1305_HEADERBYTES );

    if( ret != PEL_SUCCESS ) return( PEL_FAILURE );

    /* initialize server stream cipher state */

    ret = crypto_secretstream_xchacha20poly1305_init_pull( rx_state, buffer, rx_key );

    if( ret == -1 ) {
        pel_errno = PEL_SYNCHRONIZATION_ERROR;

        return( PEL_FAILURE );
    }

    return( PEL_SUCCESS );
}

int pel_client_derive_kp( const char *password, const unsigned char *salt )
{
    int ret;

    unsigned char* seed;

    /* initialize libsodium */

    if (sodium_init() == -1)
    {
        pel_errno = PEL_SYSTEM_ERROR;

        return( PEL_FAILURE );
    }

    /* allocate memory */

    client_pk = sodium_malloc(crypto_kx_PUBLICKEYBYTES);
    client_sk = sodium_malloc(crypto_kx_SECRETKEYBYTES);

    seed = sodium_malloc(crypto_kx_SEEDBYTES);

    if ( client_pk == NULL || client_sk == NULL || seed == NULL ) {
        pel_errno = PEL_SYSTEM_ERROR;

        return( PEL_FAILURE );
    }

    /* generate seed from password */

    ret = crypto_pwhash(seed, crypto_kx_SEEDBYTES, password,
        strlen(password), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT);

    if ( ret == -1 ) {
        pel_errno = PEL_KEY_GENERATION_ERROR;

        return( PEL_FAILURE );
    }

    /* derive key pair */

    ret = crypto_kx_seed_keypair(client_pk, client_sk, seed);

    if ( ret == -1 ) {
        pel_errno = PEL_KEY_GENERATION_ERROR;

        return( PEL_FAILURE );
    }

    sodium_free(seed);

    return( PEL_SUCCESS );
}

void pel_client_pk( unsigned char *pk )
{
    memcpy(pk, client_pk, crypto_kx_PUBLICKEYBYTES);
}

/* session setup - server side */

int pel_server_init( int client, const unsigned char *pk )
{
    int ret;

    /* initialize libsodium */

    if (sodium_init() == -1)
    {
        pel_errno = PEL_SYSTEM_ERROR;

        return( PEL_FAILURE );
    }

    /* allocate memory */

    client_pk = sodium_malloc(crypto_kx_PUBLICKEYBYTES);

    server_pk = sodium_malloc(crypto_kx_PUBLICKEYBYTES);
    server_sk = sodium_malloc(crypto_kx_SECRETKEYBYTES);

    rx_key = sodium_malloc(crypto_kx_SESSIONKEYBYTES);
    tx_key = sodium_malloc(crypto_kx_SESSIONKEYBYTES);

    rx_state = sodium_malloc(sizeof(crypto_secretstream_xchacha20poly1305_state));
    tx_state = sodium_malloc(sizeof(crypto_secretstream_xchacha20poly1305_state));

    if ( client_pk == NULL || server_pk == NULL || server_sk == NULL || rx_key == NULL ||
        tx_key == NULL || rx_state == NULL || tx_state == NULL) {
        pel_errno = PEL_SYSTEM_ERROR;

        return( PEL_FAILURE );
    }

    /* copy client pk */

    memcpy(client_pk, pk, crypto_kx_PUBLICKEYBYTES);

    /* generate keypair */

    ret = crypto_kx_keypair(server_pk, server_sk);

    if ( ret == -1 )
    {
        pel_errno = PEL_KEY_GENERATION_ERROR;

        return( PEL_FAILURE );
    }

    /* and send public key to the client */

    ret = pel_write_all( client, server_pk, crypto_kx_PUBLICKEYBYTES );

    if( ret != PEL_SUCCESS ) return( PEL_FAILURE );

    /* handshake - generate shared key */

    ret = crypto_kx_server_session_keys(rx_key, tx_key, server_pk, server_sk, client_pk);

    if( ret == -1 ) {
        pel_errno = PEL_KEY_AGREEMENT_ERROR;

        return( PEL_FAILURE );
    }

    /* initialize server stream cipher state */

    ret = crypto_secretstream_xchacha20poly1305_init_push(tx_state, buffer, tx_key);

    if( ret == -1 ) {
        pel_errno = PEL_SYNCHRONIZATION_ERROR;

        return( PEL_FAILURE );
    }

    /* transmit server stream cipher header */

    ret = pel_write_all( client, buffer, crypto_secretstream_xchacha20poly1305_HEADERBYTES );

    if( ret != PEL_SUCCESS ) return( PEL_FAILURE );

    /* receive client stream cipher header */

    ret = pel_read_all( client, buffer, crypto_secretstream_xchacha20poly1305_HEADERBYTES );

    if( ret != PEL_SUCCESS ) return( PEL_FAILURE );

    /* initialize rx stream cipher state */

    ret = crypto_secretstream_xchacha20poly1305_init_pull(rx_state, buffer, rx_key);

    if( ret == -1 ) {
        pel_errno = PEL_SYNCHRONIZATION_ERROR;

        return( PEL_FAILURE );
    }

    return( PEL_SUCCESS );
}

/* deallocate memory and clear buffers */

void pel_destroy() {
    if (client_pk != NULL) {
        sodium_free(client_pk);
        client_pk = NULL;
    }

    if (client_sk != NULL) {
        sodium_free(client_sk);
        client_sk = NULL;
    }

    if (server_pk != NULL) {
        sodium_free(server_pk);
        server_pk = NULL;
    }

    if (server_sk != NULL) {
        sodium_free(server_sk);
        server_sk = NULL;
    }

    if (rx_key != NULL) {
        sodium_free(rx_key);
        rx_key = NULL;
    }

    if (tx_key != NULL) {
        sodium_free(tx_key);
        tx_key = NULL;
    }

    if (rx_state != NULL) {
        sodium_free(rx_state);
        rx_state = NULL;
    }

    if (tx_state != NULL) {
        sodium_free(tx_state);
        tx_state = NULL;
    }

    sodium_memzero(buffer, BUFSIZE);
}

/* encrypt and transmit a message */

int pel_send_msg( int sockfd, unsigned char *msg, unsigned int length, const unsigned char tag )
{
    int ret;

    struct iovec iov[2];

    unsigned int net_length;
    unsigned char encrypted_length[ENCRYPTED_LEN_SIZE];

    /* verify the message length */

    if( length > BUFSIZE )
    {
        pel_errno = PEL_BAD_MSG_LENGTH;

        return( PEL_FAILURE );
    }

    /* encrypt message size */

    net_length = htonl(length);

    ret = crypto_secretstream_xchacha20poly1305_push(tx_state,
        encrypted_length, NULL, (unsigned char*) &net_length, sizeof(unsigned int), NULL, 0, TAG_FINAL);

    if( ret == -1 ) {

        pel_errno = PEL_CORRUPTED_DATA;

        return( PEL_FAILURE );
    }

    /* encrypt the message */

    ret = crypto_secretstream_xchacha20poly1305_push(tx_state,
        buffer, NULL, msg, length, NULL, 0, tag);

    if( ret == -1 ) {

        pel_errno = PEL_CORRUPTED_DATA;

        return( PEL_FAILURE );
    }

    /* transmit encrypted message size and ciphertext */

    iov[0].iov_base = encrypted_length;
    iov[0].iov_len = ENCRYPTED_LEN_SIZE;
    iov[1].iov_base = buffer;
    iov[1].iov_len = length + crypto_secretstream_xchacha20poly1305_ABYTES;

    ret = pel_write_iov( sockfd, iov, 2);

    if( ret != PEL_SUCCESS ) return( PEL_FAILURE );

    pel_errno = PEL_UNDEFINED_ERROR;

    return( PEL_SUCCESS );
}

/* receive and decrypt a message */

int pel_recv_msg( int sockfd, unsigned char *msg, unsigned int *length, unsigned char *tag )
{
    int ret;

    unsigned int net_length;

    /* receive encrypted message size */

    ret = pel_read_all( sockfd, buffer, ENCRYPTED_LEN_SIZE );

    if( ret != PEL_SUCCESS ) return( PEL_FAILURE );

    /* decrypt message size */

    ret = crypto_secretstream_xchacha20poly1305_pull(rx_state,
        (unsigned char*) &net_length, NULL, tag, buffer, ENCRYPTED_LEN_SIZE, NULL, 0);

    if( ret == -1 || *tag != TAG_FINAL ) {
        pel_errno = PEL_CORRUPTED_DATA;

        return( PEL_FAILURE );
    }

    *length = ntohl(net_length);

    if ( *length > BUFSIZE ) {
        pel_errno = PEL_BAD_MSG_LENGTH;

        return( PEL_FAILURE );
    }

    /* receive encrypted bytes */

    ret = pel_read_all( sockfd, buffer, *length + crypto_secretstream_xchacha20poly1305_ABYTES );

    if( ret != PEL_SUCCESS ) return( PEL_FAILURE );

    /* decrypt the message */

    ret = crypto_secretstream_xchacha20poly1305_pull(rx_state,
        msg, NULL, tag, buffer, *length + crypto_secretstream_xchacha20poly1305_ABYTES, NULL, 0);

    if( ret == -1 ) {
        pel_errno = PEL_CORRUPTED_DATA;

        return( PEL_FAILURE );
    }

    pel_errno = PEL_UNDEFINED_ERROR;

    return( PEL_SUCCESS );
}

/* send/recv wrappers to handle fragmented TCP packets */

int pel_write_iov( int s, struct iovec *iov, int iovcnt )
{
    int n;
    size_t sum = 0, len = 0;

    for ( n = 0; n < iovcnt; n++ )
    {
        len += iov[n].iov_len;
    }

    while( sum < len )
    {
        n = writev( s, iov, iovcnt );

        if( n < 0 )
        {
            pel_errno = PEL_SYSTEM_ERROR;

            return( PEL_FAILURE );
        }

        sum += n;

        while( n > 0 )
        {
            if (iov[0].iov_len > n)
            {
                iov[0].iov_len -= n;
                iov[0].iov_base += n;
                n = 0;
            } else {
                n -= iov[0].iov_len;
                iov++;
                iovcnt--;
            }
        }
    }

    pel_errno = PEL_UNDEFINED_ERROR;

    return( PEL_SUCCESS );
}


int pel_write_all( int s, void *buf, size_t len )
{
    int n;
    size_t sum = 0;
    char *offset = buf;

    while( sum < len )
    {
        n = write( s, (void *) offset, len - sum );

        if( n < 0 )
        {
            pel_errno = PEL_SYSTEM_ERROR;

            return( PEL_FAILURE );
        }

        sum += n;

        offset += n;
    }

    pel_errno = PEL_UNDEFINED_ERROR;

    return( PEL_SUCCESS );
}

int pel_read_all( int s, void *buf, size_t len )
{
    int n;
    size_t sum = 0;
    char *offset = buf;

    while( sum < len )
    {
        n = read( s, (void *) offset, len - sum );

        if( n == 0 )
        {
            pel_errno = PEL_CONN_CLOSED;

            return( PEL_FAILURE );
        }

        if( n < 0 )
        {
            pel_errno = PEL_SYSTEM_ERROR;

            return( PEL_FAILURE );
        }

        sum += n;

        offset += n;
    }

    pel_errno = PEL_UNDEFINED_ERROR;

    return( PEL_SUCCESS );
}
