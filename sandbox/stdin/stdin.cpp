#include <Windows.h>
#include <iostream>
#include <iomanip>
#include <sstream>

BOOL processStdIn(HANDLE hStdIn)
{
  BYTE buffer[256] = {0};
  DWORD dwBytesRead = 0;
  BOOL bResult = ReadFile(hStdIn, static_cast<LPVOID>(buffer), sizeof buffer, &dwBytesRead, nullptr);

  if(TRUE != bResult)
    return FALSE;

  for(DWORD dwIndex = 0; dwIndex < dwBytesRead; ++dwIndex)
  {
    std::stringstream sstr;
    sstr << "0x" << std::hex << std::setw(2) << std::setfill('0') << buffer[dwIndex];
    std::cout << sstr.str() << " : \'" << (std::isalnum(buffer[dwIndex]) ? buffer[dwIndex] : '?') << "\"\n";
  }

  return TRUE;
}

int main()
{
  HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);
  HANDLE hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
  HANDLE handles[2] = {hStdIn, hEvent};

  while(true)
  {
    DWORD dwResult = WaitForMultipleObjects(2, handles, FALSE, 500);
    switch(dwResult)
    {
    case WAIT_OBJECT_0:
      processStdIn(hStdIn);
      break;
    case WAIT_OBJECT_0 + 1:
      break;
    case WAIT_FAILED:
    case WAIT_ABANDONED:
      return 1;
    default:
      break;
    }
  }

  return 0;
}