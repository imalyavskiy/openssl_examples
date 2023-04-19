#ifndef __TCP_CLIENT_H__
#define __TCP_CLIENT_H__
#pragma once
#include "common.h"

namespace tcp{
class client
{
public:
  client(const cmn::config& config);

  bool connect(bool blocking = true);

  ~client();

protected:
  const cmn::config config_;

  SOCKET socket_ = INVALID_SOCKET;
};
}
#endif // __TCP_CLIENT_H__