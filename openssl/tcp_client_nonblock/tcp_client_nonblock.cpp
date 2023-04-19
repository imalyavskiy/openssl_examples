#include "common.h"
#include "WSAInitGuard.h"
#include "tcpclient.h"

int main(int argc, char** argv)
{
  wsa::guard wsaGuard;

  const cmn::config config = cmn::Configure(argc, argv);

  tcp::client tcpClient(config);

  if(false == tcpClient.connect())
    cmn::die("tcp::client::connect: failed");



  return 0;
}