/*
  Copyright (c) 2017 Darren Smith

  ssl_examples is free software; you can redistribute it and/or modify
  it under the terms of the MIT license. See LICENSE for details.
*/

#include "WSAInitGuard.h"
#include "SSLClient.h"

int main(int argc, char **argv)
{
  wsa::guard wsaGuard;

  const cmn::Config config = cmn::Configure(argc, argv);

  SOCKET serverSocket = ::socket(config.ipFamily, SOCK_STREAM, 0);
  if (serverSocket < 0)
    cmn::Die("socket()");

  /* Specify socket address */
  sockaddr_in addr = {0};
  addr.sin_family = config.ipFamily;
  addr.sin_port = htons(config.port);

  if (inet_pton(config.ipFamily, config.hostIP.c_str(), &(addr.sin_addr)) <= 0)
    cmn::Die("inet_pton()");

  if (connect(serverSocket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
    cmn::Die("connect()");

  printf("socket connected\n");

  pollfd fdset[2] = { 0 };
  fdset[0].fd = STDIN_FILENO;
  fdset[0].events = POLLIN;
  fdset[1].fd = serverSocket;
  fdset[1].events = POLLERR | POLLHUP | POLLNVAL | POLLIN;

  cmn::SSLContext::init();
  ssl::client sslClient(serverSocket, ssl::client::mode::client, config.hostName);

  sslClient.doSSLHandshake();

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
    {
      if (sslClient.doEncrypt() < 0)
        break;
    }
  }

  _close(fdset[1].fd);
  sslClient.printSSLState();
  cmn::PrintSSLError();

  return 0;
}

