//go:build ignore

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define FILE_TO_READ "file.txt"
#define FILE_TO_WRITE "write.txt"

int main(int argc, char **argv) {
  char ch;
  FILE *fptr, *wptr;

  while (1) {
    if ((fptr = fopen(FILE_TO_READ, "w+")) == NULL) {
      printf("Error! opening file");
      // Program exits if the file pointer returns NULL.
      exit(1);
    }
    printf("Read %s\n", FILE_TO_READ);

    fclose(fptr);

    //char *line = NULL;
    //size_t read;

    //if ((wptr = fopen(FILE_TO_WRITE, "w+")) == NULL) {
    //  printf("Error! opening file");
    //  // Program exits if the file pointer returns NULL.
    //  exit(1);
    //}
    //fprintf(wptr, "hello\n");
    //printf("Wrote %s\n", FILE_TO_WRITE);

    //fclose(wptr);
    //if (line)
    //  free(line);

    sleep(2);
  }

  return 0;
}
