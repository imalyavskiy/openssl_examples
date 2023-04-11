/*
Copyright (c) 2017 Darren Smith

ssl_examples is free software; you can redistribute it and/or modify
it under the terms of the MIT license. See LICENSE for details.
*/

#include "SSLClient.h"
#include "WSAInitGuard.h"

int main(int argc, char **argv)
{
  wsa::guard wsaInitGuard;

  const cmn::Config config = cmn::Configure(argc, argv);

  char str[INET_ADDRSTRLEN] = {0};

  const int servfd = socket(config.ipFamily, SOCK_STREAM, 0);
  if (servfd < 0)
    cmn::Die("socket()");

  constexpr char enable = 1;
  if (setsockopt(servfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
    cmn::Die("setsockopt(SO_REUSEADDR)");

  /* Specify socket address */
  sockaddr_in servaddr = {0};
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = config.ipFamily;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(config.port);

  if (bind(servfd, reinterpret_cast<sockaddr*>(&servaddr), sizeof(servaddr)) < 0)
    cmn::Die("bind()");

  if (listen(servfd, 128) < 0)
    cmn::Die("listen()");

  sockaddr_in peerAddr = { 0 };
  socklen_t peerAddr_len = sizeof(peerAddr);

  pollfd fdset[2] = { 0 };
  fdset[0].fd = STDIN_FILENO;
  fdset[0].events = POLLIN;

  cmn::SSLContext::init("server.crt", "server.key"); // see README to create these files

  while (true) 
  {
    printf("waiting for next connection on port %d\n", config.port);

    SOCKET clientSocket = ::accept(servfd, reinterpret_cast<sockaddr*>(&peerAddr), &peerAddr_len);
    if (clientSocket < 0)
      cmn::Die("accept()");

    ssl::client sslClient(clientSocket, ssl::client::mode::server);

    inet_ntop(peerAddr.sin_family, &peerAddr.sin_addr, str, INET_ADDRSTRLEN);
    printf("new connection from %s:%d\n", str, ntohs(peerAddr.sin_port));

    fdset[1].fd = clientSocket;
    fdset[1].events = POLLERR | POLLHUP | POLLNVAL | POLLIN;

    /* event loop */
    while (true) 
    {
      fdset[1].events &= ~POLLOUT;
      fdset[1].events |= sslClient.wannaWrite() ? POLLOUT : 0;

      const int numReady = WSAPoll(fdset, 2, -1);

      if (numReady == 0)
        continue; /* no descriptors ready */

      const int readEvents = fdset[1].revents;
      if (readEvents & POLLIN)
      {
        if (sslClient.doSockRead() == -1)
          break;
      }

      if (readEvents & POLLOUT)
      {
        if (sslClient.doSockWrite() == -1)
          break;
      }

      if (readEvents & (POLLERR | POLLHUP | POLLNVAL))
        break;

      if (fdset[0].revents & POLLIN)
        sslClient.doStdInRead();

      if (sslClient.doHaveDataToEncrypt())
        sslClient.doEncrypt();
    }

    _close(fdset[1].fd);
  }

  return 0;
}
