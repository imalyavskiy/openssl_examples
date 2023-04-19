#include "common.h"
#include "tcpclient.h"

tcp::client::client(const cmn::config& config)
: config_(config)
{
}

bool tcp::client::connect(bool blocking)
{
  socket_ = ::socket(config_.ipFamily, SOCK_STREAM, 0);
  if (INVALID_SOCKET == socket_)
    return false;

  sockaddr_in addr = {0};
  addr.sin_family = config_.ipFamily;
  addr.sin_port = htons(config_.port);

  if (inet_pton(config_.ipFamily, config_.hostIP.c_str(), &(addr.sin_addr)) <= 0)
    return false;

  // TODO: non blocking

  if (::connect(socket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
    return false;

  return true;
}

tcp::client::~client()
{
  if(INVALID_SOCKET != socket_)
  {
    _close(socket_);
    socket_ = INVALID_SOCKET;
  }
}
