#include "common.h"
#include "WSAInitGuard.h"

namespace wsa
{
  guard::guard()
  {
    WSADATA wsaData;
    if(0 != WSAStartup(MAKEWORD(2, 2), &wsaData))
      cmn::Die("Fatal error: WSAStartup - failed!");
  }

  guard::~guard()
  {
    WSACleanup();
  }
}