//#include <WinSock2.h>
#include <Windows.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <queue>
#include <array>

std::string tmpLine;

std::string processStdIn(HANDLE hStdIn)
{
  std::string result;

  INPUT_RECORD inputRecordArr[8] = {0};
  DWORD recordsRead = 0;
  constexpr DWORD inputRecordArrSize = std::size(inputRecordArr);

  BOOL bResult = ReadConsoleInputA(hStdIn, inputRecordArr, inputRecordArrSize, &recordsRead);

  for(int recordIndex = 0; recordIndex < recordsRead; ++recordIndex)
  {
    const INPUT_RECORD& record = inputRecordArr[recordIndex];
    if(record.EventType == KEY_EVENT)
    {
       const char ch = record.Event.KeyEvent.uChar.AsciiChar;
       if(std::isprint(ch) && record.Event.KeyEvent.bKeyDown && 1 == record.Event.KeyEvent.wRepeatCount)
       {
         tmpLine += record.Event.KeyEvent.uChar.AsciiChar;
         std::cout << ch;
       }
       else if(ch == '\r' && false == tmpLine.empty())
       {
         result = std::move(tmpLine);
         std::cout << "\r\n";
       }
    }
  }

  return result;
}

BOOL Init(std::array<HANDLE, 2>& handles)
{
  // STDIO
//  WSAData data = {0};
//  if(0 > WSAStartup(MAKEWORD(2,2), &data))
//    return FALSE;

  handles[0] = GetStdHandle(STD_INPUT_HANDLE);
  if(INVALID_HANDLE_VALUE == handles[0])
    return FALSE;

//  // SOCKET
//  DWORD dwConsoleMode = 0;
//  if(FALSE == GetConsoleMode(handles[0], &dwConsoleMode))
//    return FALSE;
//
//  const int listenSocket = ::socket(AF_INET, SOCK_STREAM, 0);
//  if (listenSocket < 0)
//    return FALSE;
//
//  constexpr char enable = 1;
//  if (setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
//    return FALSE;
//
//  sockaddr_in servaddr = {0};
//  memset(&servaddr, 0, sizeof(servaddr));
//  servaddr.sin_family = AF_INET;
//  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
//  servaddr.sin_port = htons(32123);
//
//  if (bind(listenSocket, reinterpret_cast<sockaddr*>(&servaddr), sizeof(servaddr)) < 0)
//    return FALSE;
//
//  if (listen(listenSocket, 128) < 0)
//    return FALSE;
//
//  sockaddr_in peerAddr = { 0 };
//  int peerAddr_len = sizeof(peerAddr);
//
//  SOCKET clientSocket = ::accept(listenSocket, reinterpret_cast<sockaddr*>(&peerAddr), &peerAddr_len);
//  if (clientSocket < 0)
//    return FALSE;
//
//  handles[1] = reinterpret_cast<HANDLE>(clientSocket);
  handles[1] = CreateEvent(nullptr, FALSE, FALSE, nullptr);
  if(INVALID_HANDLE_VALUE == handles[1])
    return FALSE;

  return TRUE;
}

int main()
{
  std::array<HANDLE, 2> handles {};
  if(FALSE == Init(handles))
    return 1;

  std::string line;

  while(true)
  {
    const DWORD dwResult = WaitForMultipleObjects(2, handles.data(), FALSE, 500);
    switch(dwResult)
    {
    case WAIT_OBJECT_0:
      line = processStdIn(handles[0]);
      if(false == line.empty())
        std::cout << "> " << line << std::endl;
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