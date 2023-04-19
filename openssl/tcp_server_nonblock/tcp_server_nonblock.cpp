#include "common.h"
#include "WSAInitGuard.h"
#include "tcpserver.h"
#include "tcpconnection.h"

int main(int argc, char** argv)
{
    wsa::guard wsaGuard;

  const cmn::config config = cmn::Configure(argc, argv);

  tcp::server tcpServer(config);

  std::cout << "Hello world!" << std::endl;

  return 0;
}