#ifndef _SETPROCTITLE_H
#define _SETPROCTITLE_H

void spt_init(int argc, char *argv[]);
void setproctitle(const char *fmt, ...);

#endif /* setproctitle.h */
