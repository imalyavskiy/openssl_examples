#ifndef __WSA_GUIARD_H__
#define __WSA_GUIARD_H__
#pragma once
namespace wsa
{
  class guard
  {
  public:
    guard(const guard&) = delete;
    guard(guard&&) = delete;
    guard& operator=(const guard&) = delete;
    guard& operator=(guard&&) = delete;

    guard();

    ~guard();
  };
}
#endif // __WSA_GUIARD_H__