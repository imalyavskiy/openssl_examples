#include "common.h"
#include "tcpconnection.h"
namespace tcp{
connection::connection(SOCKET socket)
  : socket_(socket)
{
}

connection::connection(connection&& other) noexcept
  : socket_(other.socket_)
{
  other.socket_ = INVALID_SOCKET;
}

connection::~connection()
{
  if(INVALID_SOCKET != socket_)
  {
    _close(socket_);
    socket_ = INVALID_SOCKET;
  }
}

auto connection::operator=(connection&& other) noexcept -> connection&
{
  if(INVALID_SOCKET != socket_)
    _close(socket_);

  socket_ = other.socket_;
  other.socket_ = INVALID_SOCKET;

  return *this;
}
}