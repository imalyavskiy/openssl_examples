#ifndef __TCP_SERVER_H__
#define __TCP_SERVER_H__
#pragma once
#include "common.h"

namespace tcp{
class server
{
public:
  server(const cmn::config& config);
  ~server();

protected:
  const cmn::config config_;

  SOCKET socket_ = INVALID_SOCKET;
};
}
#endif // __TCP_SERVER_H__