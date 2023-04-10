/*
Copyright (c) 2017 Darren Smith

ssl_examples is free software; you can redistribute it and/or modify
it under the terms of the MIT license. See LICENSE for details.
*/

#include "common.h"


int main(int argc, char **argv)
{
#if defined(_WIN32) || defined(_WIN64)
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

  char str[INET_ADDRSTRLEN];
  const int port = (argc>1)? atoi(argv[1]):55555;

  const int servfd = socket(AF_INET, SOCK_STREAM, 0);
  if (servfd < 0)
    Die("socket()");

  const char enable = 1;
  if (setsockopt(servfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
    Die("setsockopt(SO_REUSEADDR)");

  /* Specify socket address */
  sockaddr_in servaddr = {0};
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(port);

  if (bind(servfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    Die("bind()");

  if (listen(servfd, 128) < 0)
    Die("listen()");

  sockaddr_in peerAddr = { 0 };
  socklen_t peerAddr_len = sizeof(peerAddr);

  pollfd fdset[2] = { 0 };
  fdset[0].fd = STDIN_FILENO;
  fdset[0].events = POLLIN;

  SSLInit("server.crt", "server.key"); // see README to create these files

  while (true) {
    printf("waiting for next connection on port %d\n", port);

    int clientfd = accept(servfd, reinterpret_cast<sockaddr*>(&peerAddr), &peerAddr_len);
    if (clientfd < 0)
      Die("accept()");

    SSLClientInit(&sslClient, clientfd, SSLMODE_SERVER);

    inet_ntop(peerAddr.sin_family, &peerAddr.sin_addr, str, INET_ADDRSTRLEN);
    printf("new connection from %s:%d\n", str, ntohs(peerAddr.sin_port));

    fdset[1].fd = clientfd;

    /* event loop */

    fdset[1].events = POLLERR | POLLHUP | POLLNVAL | POLLIN;
#ifdef POLLRDHUP
    fdset[1].events |= POLLRDHUP;
#endif

    while (true) {
      fdset[1].events &= ~POLLOUT;
      fdset[1].events |= (SSLClientWantWrite(&sslClient)? POLLOUT : 0);

      const int numReady = WSAPoll(&fdset[0], 2, -1);

      if (numReady == 0)
        continue; /* no fd ready */

      const int readEvents = fdset[1].revents;
      if (readEvents & POLLIN)
        if (DoSockRead() == -1)
          break;
      if (readEvents & POLLOUT)
        if (DoSockWrite() == -1)
          break;
      if (readEvents & (POLLERR | POLLHUP | POLLNVAL))
        break;
#ifdef POLLRDHUP
      if (revents & POLLRDHUP)
        break;
#endif
      if (fdset[0].revents & POLLIN)
        DoStdinRead();
      if (sslClient.encrypt_len>0)
        DoEncrypt();
    }

    _close(fdset[1].fd);
    SSLClientCleanup(&sslClient);
  }

#if defined(_WIN32) || defined(_WIN64)
  WSACleanup();
#endif


  return 0;
}
