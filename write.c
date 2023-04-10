#define _CRT_SECURE_NO_WARNINGS

// this turns off depracation for "read" function call
#define _CRT_NONSTDC_NO_DEPRECATE

#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <stdlib.h>

#define HALF_ARR 50
#define FULL_ARR 2 * HALF_ARR

int main(void)
{
  int fd;
  char buffer[FULL_ARR];
  memset(buffer, 0xFA, HALF_ARR);
  memset(buffer + HALF_ARR, 0xAF, HALF_ARR);

  if ((fd = open("TEST.TST", O_CREAT|O_WRONLY)) == -1) {
    printf("Cannot create file.\n");
    exit(1);
  }
  if (write(fd, buffer, FULL_ARR) != FULL_ARR)
    printf("Possible read error.");

  close(fd);

  return 0;
}