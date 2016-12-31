//gutman.cpp

// "Secure Deletion of Data from Magnetic and Solid-State Memory" Peter Gut-
// mann: http://www.cs.auckland.ac.nz/~pgut001/pubs/secure_del.html

#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
   
#define SPC_WIPE_BUFSIZE 4096

// Plase see "secure programming cookbook for c and c++" problem "2.5 Erasing Files Securely"
   
static int write_data(int fd, const void *buf, size_t nbytes) {
  size_t  towrite, written = 0;
  ssize_t result;
   
  do {
    if (nbytes - written > SSIZE_MAX) towrite = SSIZE_MAX;
    else towrite = nbytes - written;
    if ((result = write(fd, (const char *)buf + written, towrite)) >= 0)
      written += result;
    else if (errno != EINTR) return 0;
  } while (written < nbytes);
  return 1;
}   
   
static int pattern_pass
(int fd, unsigned char *buf, size_t bufsz, size_t filesz) {
  size_t towrite;
   
  if (!bufsz || lseek(fd, 0, SEEK_SET) != 0) return -1;
  while (filesz > 0) {
    towrite = (filesz > bufsz ? bufsz : filesz);
    if (!write_data(fd, buf, towrite)) return -1;
    filesz -= towrite;
  }
  fsync(fd);
  return 0;
}
   
int spc_fd_wipe(int fd) {
  int           count, i, pass, patternsz;
  struct stat   st;
  unsigned char buf[SPC_WIPE_BUFSIZE], *pattern;

//	write 33 pass takes a lot of time, so it just write one   
  static unsigned char single_pats[1] = { 0xff};
   
  if (fstat(fd, &st) == -1) return -1;
  if (!st.st_size) return 0;      
   
  for (pass = 0;  pass < sizeof(single_pats);  pass++) {
    memset(buf, single_pats[pass], sizeof(buf));
    if (pattern_pass(fd, buf, sizeof(buf), st.st_size) == -1) return -1;
  }
   

   
  return 0;
}
   
int spc_file_wipe(FILE *f) {
  return spc_fd_wipe(fileno(f));
}

 int gutman(const char * ftex)
{
 FILE * pFile;
 pFile = fopen (ftex,"r+w");
 if (pFile!=NULL)
  {	 spc_file_wipe(pFile);
	  fclose (pFile);
	  if( remove( ftex ) != 0 )
      perror( "Error deleting file\n" );
   else
      puts( "File successfully deleted\n" );
  }
  else printf("%s\n","error");

return 0;
}

// Delete file
int srfdel(const char * ftex)
{
 FILE * pFile;
 pFile = fopen (ftex,"r+w");
 if (pFile!=NULL)
  {	 fclose (pFile);
	  if( remove( ftex ) != 0 )
      perror( "Error deleting file\n" );
   else
      puts( "File successfully deleted\n" );
  }
  else printf("%s","error");

return 0;
}
