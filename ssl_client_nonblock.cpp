/*
  Copyright (c) 2017 Darren Smith

  ssl_examples is free software; you can redistribute it and/or modify
  it under the terms of the MIT license. See LICENSE for details.
*/
#include "common.h"

int main(int argc, char **argv)
{
  WSADATA wsaData;
  if(0 != WSAStartup(MAKEWORD(2, 2), &wsaData))
    Die("WSAStartup");

  /* --- CONFIGURE PEER SOCKET --- */

  // port name, optionally take from args
  int port = argc > 1 ? atoi(argv[1]) : 55555;

  // host IP address. Attention! This must be a numeric address, not a server
  // host name, because this example code does not perform address lookup.
  //  char* host_ip = "2600:9000:225d:600:14:c251:2440:93a1";
  const char hostIP[] = "127.0.0.1";

  // provide the hostname if this SSL client needs to use SNI to tell the server
  // what certificate to use
  const char hostName[] = "api.huobi.pro";

  // socket family, AF_INET (ipv4) or AF_INET6 (ipv6), must match host_ip above
  const int ipFamily = AF_INET;

  /* Example for localhost connection
     int port = argc>1? atoi(argv[1]):55555;
     const char* host_ip = "127.0.0.1";
     const char * host_name = NULL;
     int ip_family = AF_INET;
  */


  /* --- CONFIGURATION ENDS --- */

  const int sockfd = socket(ipFamily, SOCK_STREAM, 0);

  if (sockfd < 0)
    Die("socket()");

  /* Specify socket address */
  sockaddr_in addr = {0};
  addr.sin_family = ipFamily;
  addr.sin_port = htons(port);

  if (inet_pton(ipFamily, hostIP, &(addr.sin_addr)) <= 0)
    Die("inet_pton()");

  if (connect(sockfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
    Die("connect()");

  printf("socket connected\n");

  pollfd fdset[2] = { 0 };
  fdset[0].fd = STDIN_FILENO;
  fdset[0].events = POLLIN;
  fdset[1].fd = sockfd;
  fdset[1].events = POLLERR | POLLHUP | POLLNVAL | POLLIN;

  SSLInit(nullptr,nullptr);
  SSLClientInit(&sslClient, sockfd, SSLMODE_CLIENT);

  if (hostName)
    SSL_set_tlsext_host_name(sslClient.ssl, hostName); // TLS SNI

  DoSSLHandshake();

  /* event loop */
  while (true) {
    fdset[1].events &= ~POLLOUT;
    fdset[1].events |= SSLClientWantWrite(&sslClient)? POLLOUT : 0;

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
    if (fdset[0].revents & POLLIN)
      DoStdinRead();
    if (sslClient.encrypt_len>0)
      if (DoEncrypt() < 0)
        break;
  }

  _close(fdset[1].fd);
  PrintSSLState();
  PrintSSLError();
  SSLClientCleanup(&sslClient);

  WSACleanup();

  return 0;
}

