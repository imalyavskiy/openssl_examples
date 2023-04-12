#define _CRT_SECURE_NO_WARNINGS

// this turns off depracation for "read" function call
#define _CRT_NONSTDC_NO_DEPRECATE

#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <stdlib.h>
int main(void)
{
  int fd;
  char buffer[100];
  if ((fd = open("TEST.TST", O_RDONLY)) == -1) {
    printf("Cannot open file.\n");
    exit(1);
  }
  if (read(fd, buffer, 100) != 100)
    printf("Possible read error.");
  return 0;
}