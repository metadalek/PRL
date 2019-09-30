
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "prl.h"

#undef	PRIME
#define	PRIME   (7919)

static char *	myname;
static int 	ignore_case = 0;
static int	negated = 0;
static int	color = 0;
static int	numbers = 0;
static int	simple = 0;
static int	filenames_only = 0;
static int	filenames = 0;
static char *	regex;

static uint16_t	flags = 0;

static prl_t 	pattern;

static void 	compile_pattern	(const char * pat);
static void 	process		(const char * name, FILE *fp);
static void	usage		(void);

int main(int argc, char **argv)
{
	int		c;
	int		i;
	FILE *		fp;

	myname = argv[0];
	if (isatty(1)) color = 1;
	while ((c = getopt(argc, argv, "fivCln")) != -1)
	{
		switch (c)
		{
			case 'n':
				numbers = 1;
				break;
			case 'l':
				filenames_only = 1;
				break;
			case 'i':
				ignore_case = 1;
				break;
			case 'C':
				color = !color;
				break;
			case 'v':
				negated = 1;
				break;
			case 'f':
				simple = 1;
				break;
			default:
				usage();
				break;
		}
	}

	if (optind == argc) usage();

	regex = argv[optind];
	compile_pattern(regex);	/* compile the pattern */
	optind++;

	if (optind == argc)
	{
		process("standard input", stdin);
	}
	else
	{
		if (argc - optind > 1) filenames = 1;
		/* loop over files */
		for (i = optind; i < argc; i++)
		{
			if (strcmp(argv[i], "-") == 0)
			{
				process("stdin", stdin);
			}
			else if ((fp = fopen(argv[i], "r")) != NULL)
			{
				process(argv[i], fp);
				(void)fclose(fp);
			}
			else
			{
				(void) fprintf(stderr, "%s: %s: could not open: %s\n",
					argv[0], argv[i], strerror(errno));
			}
		}
	}

	prl_free(pattern);
	return(0);
}

/* compile_pattern --- compile the pattern */

static
void
compile_pattern(const char * pat)
{
	const char *	t;
	int		ret;

	if (pat == NULL) usage();

	pattern = NULL;
	ret = prl_compile((unsigned char *) pat, &pattern);
	if (ret != PRL_OK)
	{
		t = prl_get_error(pattern);
		(void) fprintf(stderr, "%s: pattern `%s': %s\n", myname, pat, t);
		exit(1);
	}
}

static
void
process(const char * name, FILE * fp)
{
	const char *	t;
	char *		buf;
	int64_t		ret;
	size_t	 	size;
	char *		cap_start;
	int64_t		cap_len;
	char *		p;
	long		i;
	long		lineno;
	int		found;
	int		active;
	int64_t		regex_len;
	char		fpbuf[1024*256];

	/*LINTED*/
	if (ignore_case) flags |= (int16_t) PRL_ICASE;
	/*LINTED*/
	if (simple) flags |= (int16_t) PRL_SIMPLE;
	buf = NULL;
	size = 0;
	cap_start = NULL;
	lineno = 0;
	found = 0;
	/*LINTED*/
	regex_len = (int64_t) strlen(regex);
	(void) setvbuf(fp, fpbuf, _IOFBF, sizeof(fpbuf));
	for(;;)
	{
		if (getline(&buf, &size, fp) <= 0) break;
		p = buf;
		lineno++;

		ret = (int64_t) prl_search(pattern, (unsigned char *) p, flags);

		active = 0;
		if (ret == PRL_MATCH)
		{
			active = !negated;
		}
		else if (ret == PRL_NOMATCH)
		{
			active = negated;
		}
		else
		{
			t = prl_get_error(pattern);
			(void) fprintf(stderr, "%s: file %s: %s\n", myname, name, t);
			exit(1);
		}

		if (!active) continue;

		found = 1;
		if (filenames_only)
		{
			(void) printf("%s\n", name);
			if (buf != NULL) free(buf);
			return;
		}

		prl_capture(pattern, 0, NULL, (unsigned const char **) &cap_start, &cap_len);
		p = buf;
		if (filenames) (void) printf("%s: ", name);
		if (numbers) (void) printf("%6ld: ", (long) lineno);
		while (p < cap_start) (void) putchar(*p++);
		if (color) (void) printf("\33[01:31m");
		for(i=0;i<cap_len;i++) (void) putchar(*p++);
		if (color) (void) printf("\33[00m");
		if (*p != '\0') (void) printf("%s", p);
	}
	if (buf != NULL) free(buf);
	buf = NULL;
	if (!found && negated && filenames_only) (void) printf("%s\n", name);
	return;
}

static
void
usage(void)
{
	(void) fprintf(stderr, "usage: %s [-iCvlnf] pattern [ files ... ]\n", myname);
	exit(1);
}
