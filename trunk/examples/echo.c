#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  int i;

  printf("Running echo!\n");

  for (i = 0; i < argc; i++)
  {
    printf ("%s\n", argv[i]);
  }

  printf ("About to return...\n");
  return EXIT_SUCCESS;
}
