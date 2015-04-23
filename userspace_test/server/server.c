/*

Borrowed from: http://www.tldp.org/LDP/LGNET/91/misc/tranter/server.c.txt

Server portion of sendfile example.

usage: server [port]

Copyright (C) 2003 Jeff Tranter.


This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/


#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <linux/limits.h>

#include "sendfile_aes_client.h"

int main(int argc, char **argv)
{
  int port = 1234;           /* port number to use */
  int sock;                  /* socket desciptor */
  int desc;                  /* file descriptor for socket */
  int fd;                    /* file descriptor for file to send */
  struct sockaddr_in addr;   /* socket parameters for bind */
  struct sockaddr_in addr1;  /* socket parameters for accept */
  socklen_t addrlen;         /* argument to accept */
  struct stat stat_buf;      /* argument to fstat */
  off_t offset = 0;          /* file offset */
  char filename[PATH_MAX];   /* filename to send */
  int rc;                    /* holds return code of system calls */
  int sendfile_aes_handle;   /* holds the handle to our fancy sendfile_aes */

  /* check command line arguments, handling an optional port number */
  if (argc == 2) {
    port = atoi(argv[1]);
    if (port <= 0) {
      fprintf(stderr, "invalid port: %s\n", argv[1]);
      exit(1);
    }
  } else if (argc != 1) {
    fprintf(stderr, "usage: %s [port]\n", argv[0]);
    exit(1);
  }

  /* create Internet domain socket */
  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1) {
    fprintf(stderr, "unable to create socket: %s\n", strerror(errno));
    exit(1);
  }

  /* initiate the sendfile_aes session */
  sendfile_aes_handle = sendfile_aes_open(5, "hello"); /* just a dummy key as of now */
  if (sendfile_aes_handle < 0) {
    fprintf(stderr, "unable to call sendfile_aes_open: %s\n", strerror(errno));
    exit(1);
  }

  /* fill in socket structure */
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  /* bind socket to the port */
  rc =  bind(sock, (struct sockaddr *)&addr, sizeof(addr));
  if (rc == -1) {
    fprintf(stderr, "unable to bind to socket: %s\n", strerror(errno));
    exit(1);
  }

  /* listen for clients on the socket */
  rc = listen(sock, 1);
  if (rc == -1) {
    fprintf(stderr, "listen failed: %s\n", strerror(errno));
    exit(1);
  }

  while (1) {

    /* wait for a client to connect */
    desc = accept(sock, (struct sockaddr *)  &addr1, &addrlen);
    if (desc == -1) {
      fprintf(stderr, "accept failed: %s\n", strerror(errno));
      exit(1);
    }

    /* get the file name from the client */
    rc = recv(desc, filename, sizeof(filename), 0);
    if (rc == -1) {
      fprintf(stderr, "recv failed: %s\n", strerror(errno));
      exit(1);
    }

    /* null terminate and strip any \r and \n from filename */
		filename[rc] = '\0';
    if (filename[strlen(filename)-1] == '\n')
      filename[strlen(filename)-1] = '\0';
    if (filename[strlen(filename)-1] == '\r')
      filename[strlen(filename)-1] = '\0';

    /* exit server if filename is "quit" */
    if (strcmp(filename, "quit") == 0) {
      fprintf(stderr, "quit command received, shutting down server\n");
      break;
    }

    fprintf(stderr, "received request to send file %s\n", filename);

    /* open the file to be sent */
    fprintf(stdout, "opening file %s\n", filename);
    fflush(stdout);
    fd = open(filename, O_RDONLY);
    if (fd == -1) {
      fprintf(stderr, "unable to open '%s': %s\n", filename, strerror(errno));
      exit(1);
    }

    /* get the size of the file to be sent */
    fstat(fd, &stat_buf);

    /* copy file using sendfile */
    offset = 0;
    /*
    rc = sendfile (desc, fd, &offset, stat_buf.st_size);
    */
    fprintf(stdout, "sendfile()\n");
    fflush(stdout);
    rc = sendfile_aes_send(sendfile_aes_handle, desc, fd, &offset, stat_buf.st_size);
    fprintf(stdout, "sendfile() done\n");
    fflush(stdout);

    if (rc == -1) {
      fprintf(stderr, "error from sendfile: %s\n", strerror(errno));
      exit(1);
    }
    if (rc != stat_buf.st_size) {
      fprintf(stderr, "incomplete transfer from sendfile: %d of %d bytes\n",
              rc,
              (int)stat_buf.st_size);
      exit(1);
    }

    fprintf(stdout, "closing file\n");
    fflush(stdout);

    /* close descriptor for file that was sent */
    close(fd);

    /* close socket descriptor */
    close(desc);
  }

  /* close socket */
  close(sock);

  /* close sendfile_aes_handle */
  sendfile_aes_close(sendfile_aes_handle);

  return 0;
}
