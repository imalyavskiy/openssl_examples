#ifndef __TCP_CONNECTION_H__
#define __TCP_CONNECTION_H__
#pragma once
#include <WinSock2.h>

namespace tcp
{
class connection
{
  friend class server;
  connection(SOCKET socket);

public:
  connection() = default;
  connection(const connection&) = delete;
  connection(connection&& other) noexcept;
  ~connection();

  connection& operator=(const connection&) = delete;
  connection& operator=(connection&& other) noexcept;

protected:
  SOCKET socket_ = INVALID_SOCKET;
};
}

#endif // __TCP_CONNECTION_H__