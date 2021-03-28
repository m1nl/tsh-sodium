/*
 * Tiny SHell Sodium version 0.1 - server side,
 * by Christophe Devine <devine@cr0.net>;
 * by Mateusz Nalewajski <mateusz@nalewajski.pl>
 * this program is licensed under the GPL.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>

#include "tsh.h"
#include "pel.h"
#include "hexutils.h"

unsigned char message[BUFSIZE + 1];
unsigned char tag;

unsigned char salt[] = { 0x25, 0x88, 0x9e, 0xd6, 0x53, 0x3e, 0x94, 0x3c, 0xb8, 0xc0, 0x95, 0x77, 0xc7, 0x74, 0x6e, 0xcb };

char *password;
unsigned char pk[crypto_kx_PUBLICKEYBYTES];

extern char *optarg;
extern int optind;

/* function declaration */

int tsh_get_file( int server, char *argv3, char *argv4 );
int tsh_put_file( int server, char *argv3, char *argv4 );
int tsh_runshell( int server, char *argv2 );

void pel_error( char *s );

/* program entry point */

void usage(char *argv0)
{
    fprintf(stderr, "Usage: %s [ -s key_seed ] [ -p port ] [command]\n"
        "\n"
        "   pubkey\n"
        "   <hostname|cb>\n"
        "   <hostname|cb> get <source-file> <dest-dir>\n"
        "   <hostname|cb> put <source-file> <dest-dir>\n", argv0);
    exit(1);
}

void cleanup(void) {
    pel_destroy();
}

void sig_handler(int signum) {
    (void)signum;

    cleanup();
    exit(1);
}

int main( int argc, char *argv[] )
{
    int ret, client, server;
    socklen_t n;
    int opt;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    struct hostent *server_host;
    char action;
    size_t password_len;

    /* initialize libsodium */

    if (sodium_init() == -1) {
        pel_errno = PEL_SYSTEM_ERROR;

        return( 1 );
    }

    /* setup signal handlers and cleanup routine */

    atexit(cleanup);
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);

    while ((opt = getopt(argc, argv, "p:s:")) != -1) {
        switch (opt) {
            case 'p':
                server_port = atoi(optarg); /* We hope ... */
                if (!server_port) usage(*argv);
                break;
            case 's':
                password_len = strlen(optarg); /* We hope ... */

                if (password_len == 0) {
                    break;
                }

                password = sodium_malloc(password_len + 1);
                if (password == NULL) {
                    perror("sodium_malloc");
                    return( 2 );
                }

                sodium_memzero(password, password_len + 1);

                memcpy(password, optarg, password_len);
                sodium_memzero(optarg, password_len);
                break;
            default: /* '?' */
                usage(*argv);
                break;
        }
    }

    argv+=(optind-1);
    argc-=(optind-1);
    action = 0;

    /* derive key pair from password */

    if (password == NULL || strlen(password) == 0) {
        fprintf( stderr, "Password is required.\n" );
        return( 3 );
    }

    ret = pel_client_derive_kp( password, salt );

    sodium_free(password);

    if( ret != PEL_SUCCESS )
    {
        /* key seed invalid, exit */

        fprintf( stderr, "Unable to generate key pair.\n" );
        return( 4 );
    }

    /* check the arguments */

    if( argc == 2 && ! strcmp( argv[1], "pubkey" ) )
    {
      /* print public key */

      pel_client_pk( pk );

      bin2hex( pk, crypto_kx_PUBLICKEYBYTES, (char*) message, BUFSIZE);
      printf( "%s\n", (char*) message );

      return 0;
    }

    if( argc == 5 && ! strcmp( argv[2], "get" ) )
    {
        action = GET_FILE;
    }

    if( argc == 5 && ! strcmp( argv[2], "put" ) )
    {
        action = PUT_FILE;
    }

    if( argc == 2 || argc == 3 )
    {
        action = RUNSHELL;
    }

    if( action == 0 ) return( 5 );

    if( strcmp( argv[1], "cb" ) != 0 )
    {
        /* create a socket */

        server = socket( AF_INET, SOCK_STREAM, 0 );

        if( server < 0 )
        {
            perror( "socket" );
            return( 6 );
        }

        server_host = gethostbyname( argv[1] );

        if( server_host == NULL )
        {
            perror( "gethostbyname");
            return( 7 );
        }

        memcpy( (void *) &server_addr.sin_addr,
                (void *) server_host->h_addr,
                server_host->h_length );

        server_addr.sin_family = AF_INET;
        server_addr.sin_port   = htons( server_port );

        /* connect to the remote host */

        ret = connect( server, (struct sockaddr *) &server_addr,
                       sizeof( server_addr ) );

        if( ret < 0 )
        {
            perror( "connect" );
            return( 8 );
        }
    }
    else
    {
        /* create a socket */

        client = socket( AF_INET, SOCK_STREAM, 0 );

        if( client < 0 )
        {
            perror( "socket" );
            return( 9 );
        }

        /* bind the client on the port the server will connect to */

        n = 1;

        ret = setsockopt( client, SOL_SOCKET, SO_REUSEADDR,
                          (void *) &n, sizeof( n ) );

        if( ret < 0 )
        {
            perror( "setsockopt" );
            return( 10 );
        }

        client_addr.sin_family      = AF_INET;
        client_addr.sin_port        = htons( server_port );
        client_addr.sin_addr.s_addr = INADDR_ANY;

        ret = bind( client, (struct sockaddr *) &client_addr,
                    sizeof( client_addr ) );

        if( ret < 0 )
        {
            perror( "bind" );
            return( 11 );
        }

        if( listen( client, 5 ) < 0 )
        {
            perror( "listen" );
            return( 12 );
        }

        fprintf( stderr, "Waiting for the server to connect..." );
        fflush( stderr );

        n = sizeof( server_addr );

        server = accept( client, (struct sockaddr *)
                         &server_addr, &n );

        if( server < 0 )
        {
            perror( "accept" );
            return( 13 );
        }

        fprintf( stderr, "connected.\n" );

        close( client );
    }

    /* setup the packet encryption layer */

    ret = pel_client_init( server );

    if( ret != PEL_SUCCESS )
    {
        pel_error( "pel_client_init" );
        shutdown( server, 2 );
        return( 14 );
    }

    /* send the action requested by the user */

    ret = pel_send_msg( server, (unsigned char *) &action, 1, TAG_FINAL );

    if( ret != PEL_SUCCESS )
    {
        pel_error( "pel_send_msg" );
        shutdown( server, 2 );
        return( 15 );
    }

    /* howdy */

    switch( action )
    {
        case GET_FILE:

            ret = tsh_get_file( server, argv[3], argv[4] );
            break;

        case PUT_FILE:

            ret = tsh_put_file( server, argv[3], argv[4] );
            break;

        case RUNSHELL:

            ret = ( ( argc == 3 )
                ? tsh_runshell( server, argv[2] )
                : tsh_runshell( server, "exec bash --login" ) );
            break;

        default:

            ret = -1;
            break;
    }

    shutdown( server, 2 );

    return( ret );
}

int tsh_get_file( int server, char *argv3, char *argv4 )
{
    char *temp, *pathname;
    int ret, total, fd;
    unsigned int len;

    /* send remote filename */

    len = strlen( argv3 );

    ret = pel_send_msg( server, (unsigned char *) argv3, len, TAG_FINAL );

    if( ret != PEL_SUCCESS )
    {
        pel_error( "pel_send_msg" );
        return( 16 );
    }

    /* create local file */

    temp = strrchr( argv3, '/' );

    if( temp != NULL ) temp++;
    if( temp == NULL ) temp = argv3;

    len = strlen( argv4 );

    pathname = (char *) malloc( len + strlen( temp ) + 2 );

    if( pathname == NULL )
    {
        perror( "malloc" );
        return( 17 );
    }

    strcpy( pathname, argv4 );
    strcpy( pathname + len, "/" );
    strcpy( pathname + len + 1, temp );

    /* create local file */

    fd = creat( (char *) pathname, 0644 );

    if( fd < 0 )
    {
        return( 18 );
    }

    free( pathname );

    /* transfer from server */

    total = 0;

    while( 1 )
    {
        ret = pel_recv_msg( server, message, &len, &tag );

        if( ret != PEL_SUCCESS )
        {
            pel_error( "pel_recv_msg" );
            fprintf( stderr, "Transfer failed.\n" );
            return( 19 );
        }

        if( write( fd, message, len ) != len )
        {
            perror( "write" );
            return( 20 );
        }

        total += len;

        printf( "%d\r", total );
        fflush( stdout );

        if ( tag == TAG_FINAL ) {
            break;
        }
    }

    printf( "%d done.\n", total );

    return( 0 );
}

int tsh_put_file( int server, char *argv3, char *argv4 )
{
    char *temp, *pathname;
    int ret, total, eof, fd;
    struct stat st;
    unsigned int len;

    /* send remote filename */

    temp = strrchr( argv3, '/' );

    if( temp != NULL ) temp++;
    if( temp == NULL ) temp = argv3;

    len = strlen( argv4 );

    pathname = (char *) malloc( len + strlen( temp ) + 2 );

    if( pathname == NULL )
    {
        perror( "malloc" );
        return( 21 );
    }

    strcpy( pathname, argv4 );
    strcpy( pathname + len, "/" );
    strcpy( pathname + len + 1, temp );

    len = strlen( pathname );

    ret = pel_send_msg( server, (unsigned char *) pathname, len, TAG_FINAL );

    if( ret != PEL_SUCCESS )
    {
        pel_error( "pel_send_msg" );
        return( 22 );
    }

    free( pathname );

    /* open local file */

    fd = open( argv3, O_RDONLY );

    if( fd < 0 )
    {
        perror( "open" );
        return( 23 );
    }

    /* get file stat */

    ret = stat( argv3, &st );

    if( ret < 0 )
    {
        perror( "stat" );
        return( 24 );
    }

    /* transfer to server */

    total = 0;

    while( 1 )
    {
        ret = read( fd, message, BUFSIZE );

        if( ret < 0 )
        {
            perror( "read" );
            return( 24 );
        }

        len = (unsigned int) ret;

        eof = total == st.st_size;

        ret = pel_send_msg( server, message, len, eof ? TAG_FINAL : TAG_PUSH );

        if( ret != PEL_SUCCESS )
        {
            pel_error( "pel_send_msg" );
            fprintf( stderr, "Transfer failed.\n" );
            return( 21 );
        }

        total += len;

        printf( "%d\r", total );
        fflush( stdout );

        if ( eof ) {
            break;
        }
    }

    printf( "%d done.\n", total );

    return( 0 );
}

int tsh_runshell( int server, char *argv2 )
{
    fd_set rd;
    char *term;
    int ret, imf;
    unsigned int len;

    struct winsize ws;
    struct termios tp, tr;

    /* send the TERM environment variable */

    term = getenv( "TERM" );

    if( term == NULL )
    {
        term = "vt100";
    }

    len = strlen( term );

    ret = pel_send_msg( server, (unsigned char *) term, len, TAG_FINAL );

    if( ret != PEL_SUCCESS )
    {
        pel_error( "pel_send_msg" );
        return( 22 );
    }

    /* send the window size */

    imf = 0;

    if( isatty( 0 ) )
    {
        /* set the interactive mode flag */

        imf = 1;

        if( ioctl( 0, TIOCGWINSZ, &ws ) < 0 )
        {
            perror( "ioctl(TIOCGWINSZ)" );
            return( 23 );
        }
    }
    else
    {
        /* fallback on standard settings */

        ws.ws_row = 25;
        ws.ws_col = 80;
    }

    message[0] = ( ws.ws_row >> 8 ) & 0xFF;
    message[1] = ( ws.ws_row      ) & 0xFF;

    message[2] = ( ws.ws_col >> 8 ) & 0xFF;
    message[3] = ( ws.ws_col      ) & 0xFF;

    ret = pel_send_msg( server, message, 4, TAG_FINAL );

    if( ret != PEL_SUCCESS )
    {
        pel_error( "pel_send_msg" );
        return( 24 );
    }

    /* send the system command */

    len = strlen( argv2 );

    ret = pel_send_msg( server, (unsigned char *) argv2, len, TAG_FINAL );

    if( ret != PEL_SUCCESS )
    {
        pel_error( "pel_send_msg" );
        return( 25 );
    }

    /* set the tty to RAW */

    if( isatty( 1 ) )
    {
        if( tcgetattr( 1, &tp ) < 0 )
        {
            perror( "tcgetattr" );
            return( 26 );
        }

        memcpy( (void *) &tr, (void *) &tp, sizeof( tr ) );

        tr.c_iflag |= IGNPAR;
        tr.c_iflag &= ~(ISTRIP|INLCR|IGNCR|ICRNL|IXON|IXANY|IXOFF);
        tr.c_lflag &= ~(ISIG|ICANON|ECHO|ECHOE|ECHOK|ECHONL|IEXTEN);
        tr.c_oflag &= ~OPOST;

        tr.c_cc[VMIN]  = 1;
        tr.c_cc[VTIME] = 0;

        if( tcsetattr( 1, TCSADRAIN, &tr ) < 0 )
        {
            perror( "tcsetattr" );
            return( 27 );
        }
    }

    /* let's forward the data back and forth */

    while( 1 )
    {
        FD_ZERO( &rd );

        if( imf != 0 )
        {
            FD_SET( 0, &rd );
        }

        FD_SET( server, &rd );

        if( select( server + 1, &rd, NULL, NULL, NULL ) < 0 )
        {
            perror( "select" );
            ret = 28;
            break;
        }

        if( FD_ISSET( server, &rd ) )
        {
            ret = pel_recv_msg( server, message, &len, &tag );

            if( ret != PEL_SUCCESS )
            {
                if( pel_errno == PEL_CONN_CLOSED )
                {
                    ret = 0;
                }
                else
                {
                    pel_error( "pel_recv_msg" );
                    ret = 29;
                }
                break;
            }

            if( write( 1, message, len ) != len )
            {
                perror( "write" );
                ret = 30;
                break;
            }
        }

        if( imf != 0 && FD_ISSET( 0, &rd ) )
        {
            ret = read( 0, message, BUFSIZE );

            if( ret < 0 )
            {
                perror( "read" );
                ret = 31;
                break;
            }

            len = (unsigned int) ret;

            if( len == 0 )
            {
                fprintf( stderr, "stdin: end-of-file\n" );
                ret = 32;
                break;
            }


            ret = pel_send_msg( server, message, len, TAG_FINAL );

            if( ret != PEL_SUCCESS )
            {
                pel_error( "pel_send_msg" );
                ret = 33;
                break;
            }
        }
    }

    /* restore the terminal attributes */

    if( isatty( 1 ) )
    {
        tcsetattr( 1, TCSADRAIN, &tp );
    }

    return( ret );
}

void pel_error( char *s )
{
    switch( pel_errno )
    {
        case PEL_CONN_CLOSED:

            fprintf( stderr, "%s: Connection closed.\n", s );
            break;

        case PEL_SYSTEM_ERROR:

            perror( s );
            break;

        case PEL_KEY_GENERATION_ERROR:

            fprintf( stderr, "%s: Key generation error.\n", s );
            break;

        case PEL_KEY_AGREEMENT_ERROR:

            fprintf( stderr, "%s: Key agreement error.\n", s );
            break;

        case PEL_SYNCHRONIZATION_ERROR:

            fprintf( stderr, "%s: Synchronization error.\n", s );
            break;

        case PEL_CORRUPTED_DATA:

            fprintf( stderr, "%s: Corrupted data.\n", s );
            break;

        case PEL_BAD_MSG_LENGTH:

            fprintf( stderr, "%s: Bad message length.\n", s );
            break;

        case PEL_UNDEFINED_ERROR:

            fprintf( stderr, "%s: No error.\n", s );
            break;

        default:

            fprintf( stderr, "%s: Unknown error code.\n", s );
            break;
    }
}
