
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include "prl.h"


static int 	lineno = 0;
static int	ok = 0;
static int	notok = 0;
static int	total = 0;
static int	search = 1;

static prl_t	gr = NULL;
static char	regex[1024];
static int 	status = 0;
static char	string[1024];
static char	buffer[1024];
static char	expected;
static long	num_capture;
static long	capture;
static char	expected_capture[1024];
static FILE *	fp = NULL;
static char *	filename = NULL;

static int64_t	flags = 0;
static char	sflags[32];

static void multiple	(void);
static void try	(void);
static void error	(void);
static void complain	(char * s1);
static void fix	(char *, char *);



static
void
usage(int argc, char *argv[])
/*ARGSUSED*/
{
	(void) fprintf(stderr, "\nUsage: %s [-msinrad] [-F filename] [regex string]\n\n", argv[0]);
	(void) fprintf(stderr,	"Options:\n"
				"\t-m	match regex rather than search\n"
		       		"\t-s	search for regex in string (default)\n"
		       		"\t-i	ignore case (set flag PRL_ICASE)\n"
		       		"\t-n	set flag PRL_NLISEOS\n"
		       		"\t-r	set flag PRL_CRNLISEOS\n"
		       		"\t-a	set flag PRL_ANCHORED\n"
		       		"\t-d	set flag PRL_DOTNOEOS\n\n"
		       		"\t-f	set flag PRL_SIMPLE\n\n"
		       		"\t-F filename\tread tests from file\n\n");
	(void) fprintf(stderr,	"See file test_input for a description of a test file.\n\n");
	(void) fprintf(stderr,	"If not reading from a file, the first argument is a regex to test\n"
		      		"and the second arguement is a string to match.\n\n");

	exit(1);
}

static
void
error(void)
{
	char *	s2;

	s2 = "None";
	if (gr != NULL) s2 = (char *) prl_get_error(gr);
	(void) printf("PRL error: \"%s\"\n", s2);
	prl_status(gr);
	return;
}

static
void
multiple(void)
{
	char 		rbuf[1024*8];
	int 		i;
	char *		p;
	int		exact;

	lineno = 0;
	(void) memset(rbuf, 0, sizeof(rbuf));
	while (fgets(rbuf, sizeof(rbuf)-1, fp) != NULL)
	{

		if (rbuf[0] == '#')
		{
			lineno++;
			continue;
		}

//		prl_free(gr);
		gr = NULL;
		lineno++;

		// 0 = regex
		// 1 = string
		// 2 = c or e or m or n
		//	e = compile error
		//	y = matches
		//	n = does not match
		// 3 = num captures
		// 4 = capture number
		// 5 = capture value

		i = sscanf(rbuf, "%1024s %1024s %c %ld %ld %1024s %1024s", regex, string, &expected, &num_capture, &capture,
			   expected_capture, sflags);

		if (i != 7)
		{
			(void) fprintf(stderr, "Error in input (%ld) , line %ld\n", (long) i, (long) lineno);
			exit(1);
		}

		flags = 0;
		exact = 0;
		if (strchr(sflags, 'X') != NULL) exact = 1;
		if (strchr(sflags, 'i') != NULL) flags |= PRL_ICASE;
		if (strchr(sflags, 'a') != NULL) flags |= PRL_ANCHORED;
		if (strchr(sflags, 's') != NULL) search = 1;
		if (strchr(sflags, 'm') != NULL) search = 0;
		if (strchr(sflags, 'n') != NULL) flags |= PRL_NLISEOS;
		if (strchr(sflags, 'r') != NULL) flags |= PRL_CRNLISEOS;
		if (strchr(sflags, 'd') != NULL) flags |= PRL_DOTNOEOS;
		if (strcmp(expected_capture, "-") == 0) expected_capture[0] = '\0';
		if (strcmp(string, "-") == 0) string[0] = '\0';

		p = string;
		while (!exact && *p != '\0')
		{
			if (*p == '@') *p = ' ';
			if (*p == '&' && (*(p+1) == '&')) { *p = '\r'; *(p+1) = '\n'; p++; }
			if (*p == '&') *p = '\n';
			p++;
		}

		p = expected_capture;
		while (!exact && *p != '\0')
		{
			if (*p == '@') *p = ' ';
			if (*p == '&' && (*(p+1) == '&')) { *p = '\r'; p++; *p = '\n'; }
			if (*p == '&') *p = '\n';
			p++;
		}

		p = regex;
		while (!exact && *p != '\0')
		{
			if (*p == '@') *p = ' ';
			p++;
		}

		try();
	}

	return;
}

static
void
try(void)
{
	int	t;
	char *	s;
	long	i;

	total++;

//	prl_free(gr);
	gr = NULL;

	if (prl_compile((unsigned char *) regex, &gr) != PRL_OK)
	{
		if (expected  == 'c') ok++;
		else complain("unexpected compile failure");
		prl_free(gr);
		return;
	}

	if (expected == 'c')
	{
		complain("unexpected compile success");
		prl_free(gr);
		return;
	}

	/*LINTED*/
	expected = tolower(expected);
	fix(buffer, string);
	if (search) t = prl_search(gr, (unsigned char *) buffer, flags);
	else t = prl_match(gr, (unsigned char *) buffer, flags);

	if (t == PRL_MATCH)
	{
		if (expected == 'n') complain("unexepected match success");
	}
	else if (t == PRL_NOMATCH)
	{
		if (expected == 'y') complain("unexpected match failure");
		ok++;
		prl_free(gr);
		return;
	}
	else
	{
		complain("prl error, abort.");
		prl_free(gr);
		exit(1);
	}

	i = prl_capture_count(gr);

	if (i != num_capture)
	{
		complain("capture count mismatch");
		prl_free(gr);
		return;
	}

	s = (char *) prl_capture_string(gr, capture, NULL);
	if (s == NULL) complain("capture returned NULL");

	if (strcmp(s, expected_capture) != 0)
	{
		free(s);
		complain("capture value mismatch");
		prl_free(gr);
		return;
	}
	free(s);
	ok++;
	prl_free(gr);
	return;
}

static
void
complain(char * s1)
{
	char *	s2;

	s2 = (char *) prl_get_error(gr);
	(void) fprintf(stderr, "\n\ncomplain: error \"%s\" line %d, regex \"%s\"\n", s1, lineno, regex);
	if (gr != NULL) s2 = (char *) prl_get_error(gr);
	(void) fprintf(stderr, "prl error: %s\n", s2);
	prl_status(gr);
	status = 1;
	notok++;
	exit(1);
}

static
void
fix(char * b, char * s)
{
	while(*s != '\0')
	{
		if (*s == '\\')
		{
			if (*(s+1) == 'n')
			{
				*b = '\n';
				b++;
				s+= 2;
			}
			else if (*(s+1) == 'r')
			{
				*b = '\r';
				b++;
				s+=2;
			}
			else
			{
				*b = *s;
				b++; s++;
			}
			continue;
		}

		*b++ = *s++;
	}
	*b = '\0';
	return;
}

int
main(int argc, char *argv[])
{
	int	i;
	int	c;

	while((c = getopt(argc, argv, "F:ifmnrasd")) != EOF)
	{
		switch(c)
		{
			case 'f':	flags |= PRL_SIMPLE;
					break;
			case 'i':	flags |= PRL_ICASE;
					break;
			case 'n':	flags |= PRL_NLISEOS;
					break;
			case 'r':	flags |= PRL_CRNLISEOS;
					break;
			case 'a':	flags |= PRL_ANCHORED;
					break;
			case 'm':	search = 0;
					break;
			case 's':	search = 1;
					break;
			case 'd':	flags |= PRL_DOTNOEOS;
					break;
			case 'F':	filename = optarg;
					break;
			default:	usage(argc, argv);
		}
	}

	if (filename != NULL)
	{
		if (strcmp(filename, "-") == 0) fp = stdin;
		else fp = fopen(filename, "r");
		if (fp == NULL)
		{
			(void) fprintf(stderr, "Unable to open file \"%s\".\n", filename);
			exit(1);
		}
		multiple();
		goto end;
	}


	if (argc != optind+2) usage(argc, argv);
	if (prl_compile((unsigned char *) argv[optind], &gr) != PRL_OK)
	{
		error();
		exit(1);
	}

	prl_set_parameter(gr, PRL_MAX_LOOKBEHIND, 3);
	buffer[0] = '\0';
	fix(buffer, argv[optind+1]);

	if (search) i = prl_search(gr, (unsigned char *) buffer, flags);
	else i = prl_match(gr, (unsigned char *) buffer, flags);

	if (i == PRL_MATCH) (void) printf("\nMatch\n");
	else if (i == PRL_NOMATCH) (void) printf("\nNo match\n");
	else (void) printf("Failure");
	prl_status(gr);
	prl_free(gr);
	exit(0);
end:
	(void) printf("PASSED: %d, FAILED: %d\n", ok, notok);
	exit(status);
}
