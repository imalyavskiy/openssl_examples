// SEE https://stackoverflow.com/questions/4993119/redirect-io-of-process-to-windows-socket
//     https://www.techpowerup.com/forums/threads/c-c-c-console-redirection-with-sockets-win32.62350/

#include <corecrt_io.h>
#include <stdio.h>

#include "WinSock2.h"
#if 1
#define STDIN_FILENO _fileno(stdin)
#define DEFAULT_BUF_SIZE 64

void Die(int code)
{
  WSACleanup();
  exit(code);
}

int main(int argc, char** argv)
{
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2, 2), &wsaData);

  struct pollfd fdset[1] = { 0 };
  fdset[0].fd = STDIN_FILENO;
  fdset[0].events = POLLIN;

  for(;;)
  {
    const int numReady = WSAPoll(fdset, 1, -1);
    if (numReady == SOCKET_ERROR)
    {
      const int err = WSAGetLastError();
      printf("Error: %d", err);
      Die(1);
    }
    if (numReady == 0)
      continue; /* no descriptors ready */
    
    if (fdset[0].revents & POLLIN)
    {
      char buf[DEFAULT_BUF_SIZE] = {0};
      const size_t n = _read(STDIN_FILENO, buf, sizeof(buf) - 1);
      printf("STDIN: \"%s\"\n", buf);
    }
  }

  Die(0);
}
#else
void ProcessKeyEvent(const INPUT_RECORD* record)
{
  printf("key down: %c\n", record->Event.KeyEvent.uChar.AsciiChar);
}

void ProcessStdin(void)
{
  INPUT_RECORD record;
  DWORD numRead;
  if (!ReadConsoleInput(GetStdHandle(STD_INPUT_HANDLE), &record, 1, &numRead)) {
    // hmm handle this error somehow...
    return;
  }

  switch(record.EventType)
  {
    case KEY_EVENT:
      printf("key event\n");
      ProcessKeyEvent(&record);
      break;
    case MOUSE_EVENT:
      printf("mouse event\n");
      break;
    case WINDOW_BUFFER_SIZE_EVENT:
      printf("window buffer size event\n");
      break;
    case MENU_EVENT:
      printf("menu event\n");
      break;
    case FOCUS_EVENT:
      printf("focus event\n");
      break;
    default:
      printf("unknown event\n");
      break;
  }
} // end ProcessStdin

int main(char argc, char* argv[])
{
  HANDLE eventHandles[] = 
  {
      GetStdHandle(STD_INPUT_HANDLE)
      // ... add more handles and/or sockets here
  };

  for (;;) 
  {
    DWORD result = WSAWaitForMultipleEvents(sizeof(eventHandles) / sizeof(eventHandles[0]),
      &eventHandles[0],
      FALSE,
      1000,
      TRUE
    );

    switch (result)
    {
      case WSA_WAIT_TIMEOUT: // no I/O going on right now
        break;
      case WSA_WAIT_EVENT_0 + 0: // stdin at array index 0
        ProcessStdin();
        break;
      case WSA_WAIT_EVENT_0 + 1: // handle/socket at array index 1
        break;
      case WSA_WAIT_EVENT_0 + 2: // ... and so on
        break;
      default: // handle the other possible conditions
        break;
    } // end switch result
  }
}
#endif