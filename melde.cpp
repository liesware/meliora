//	See melen.cpp , it is the same code

#include "melcrypt.h"
#include "config.h"

#define _XOPEN_SOURCE_EXTENDED 1	

#include <stdio.h>
#include <errno.h>
#include <ftw.h>	
#include <limits.h> 
#include <unistd.h>	

#include <stdlib.h>
#include <string.h>
#include <regex.h>

#define SPARE_FDS 5	

#define MAX_ERROR_MSG 0x1000

extern int process(const char *file, const struct stat *sb,
		   int flag, struct FTW *s);

static int compile_regex (regex_t * r, const char * regex_text)
{
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

static int match_regex (regex_t * r, const char * to_match)
{
    const char * p = to_match;
    const int n_matches = NFILES;
    regmatch_t m[n_matches];

    int i = 0;
    int nomatch = regexec (r, p, n_matches, m, 0);
    if (nomatch) {
       printf ("No more matches.\n");
        return nomatch;
    }
	printf("%s\n", to_match);

//	call unransome to decrypt files, see melcrypt.h	
	unransome(to_match);
	
    return 0;
}


int main(int argc, char **argv)
{
	int i, c, nfds;
	int errors = 0;
	int flags = FTW_PHYS;
	flags |= FTW_CHDIR;

	nfds = getdtablesize() - SPARE_FDS;

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
//	EXTENSION is a macron in config.h		
		const char * regex_text=EXTENSION;
	
		getcwd(dir, sizeof dir);
		snprintf (fi, PATH_MAX,"%s/%s", dir, name);	
		
		compile_regex (& r, regex_text);
		match_regex (& r, fi);
		regfree (& r);
		
	}

	return retval;
}

