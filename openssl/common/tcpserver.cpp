#include "common.h"
#include "tcpserver.h"
namespace tcp{
server::server(const cmn::config& config)
: config_(config)
{
}

server::~server()
{
  if(INVALID_SOCKET != socket_)
  {
    _close(socket_);
    socket_ = INVALID_SOCKET;
  }
}
}
