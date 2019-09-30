

#ifndef	__PRL_H__

#	include	<stdint.h>

#	define	__PRL_H__


#	ifndef	__PRL
		typedef struct prl *	prl_t;
#	endif

	int		prl_compile		(const unsigned char * re, prl_t *);
	int		prl_match		(prl_t, unsigned const char * s, int64_t flags);
	int		prl_search		(prl_t, unsigned const char * s, int64_t flags);
	unsigned char *	prl_capture_string	(prl_t, int64_t, const char *);
	void		prl_capture		(prl_t, int64_t, const char *, const unsigned char **,
						 int64_t *);
	int64_t		prl_capture_count	(prl_t);
	char *		prl_capture_name	(prl_t, int64_t);
	void		prl_free		(prl_t);
	const char *	prl_get_error		(prl_t);
	void		prl_status		(prl_t);
	void		prl_internals		(prl_t);
	void		prl_set_parameter	(prl_t, int64_t, int64_t);
	prl_t		prl_clone		(prl_t);


#	undef	PRL_MATCH
#	define	PRL_MATCH			0

#	undef	PRL_NOMATCH
#	define	PRL_NOMATCH			1

#	undef	PRL_OK
#	define	PRL_OK				0

#	undef	PRL_USAGE_ERROR
#	define	PRL_USAGE_ERROR			1

#	undef	PRL_COMPILE_ERROR
#	define	PRL_COMPILE_ERROR		2

#	undef	PRL_MATCH_ERROR
#	define	PRL_MATCH_ERROR			3

#	undef	PRL_SYSTEM_ERROR
#	define	PRL_SYSTEM_ERROR		4

#	undef	PRL_INTERNAL_ERROR
#	define	PRL_INTERNAL_ERROR		5

#	undef	PRL_CORRUPTION
#	define	PRL_CORRUPTION			6

#	undef	PRL_NULL
#	define	PRL_NULL			7

// DANGER, flags must fit in 16 bits (uint16_t)
// and follow rules below


// flags in the bottom 8 bits can be used to alter behaviours as the
// regex is processed, ie can be altered by options changing subexpressions
//
// flags in the top 8 bits cannot be altered my options in the regex
// and are set when entering search or match


// Case invarient
#	undef	PRL_ICASE
#	define	PRL_ICASE	((uint16_t) ((uint16_t) 1) << 0)

// Newline char is end of string
#	undef	PRL_NLISEOS
#	define	PRL_NLISEOS	((uint16_t) ((uint16_t) 1) << 1)

// Carriage return newline is end of string
#	undef	PRL_CRNLISEOS
#	define	PRL_CRNLISEOS	((uint16_t) ((uint16_t) 1) << 2)

// Dot does not match end of string
#	undef	PRL_DOTNOEOS
#	define	PRL_DOTNOEOS	((uint16_t) ((uint16_t) 1) << 3)

// Result is negated
#	undef	PRL_NEGATED
#	define	PRL_NEGATED	((uint16_t) ((uint16_t) 1) << 4)

// Words are more like real words
#	undef	PRL_ALTWORDS
#	define	PRL_ALTWORDS	((uint16_t) ((uint16_t) 1) << 5)

// Subexression is atomic
#	undef	PRL_ATOMIC
#	define	PRL_ATOMIC	((uint16_t) ((uint16_t) 1) << 6)


// these cannot be altered as options inside the regex

#	undef	PRL_ANCHORED
#	define	PRL_ANCHORED	((uint16_t) ((uint16_t) 1) << 8)

#	undef	PRL_NARROW
#	define	PRL_NARROW	((uint16_t) ((uint16_t) 1) << 9)

#	undef	PRL_DEADEND
#	define	PRL_DEADEND	((uint16_t) ((uint16_t) 1) << 10)

#	undef	PRL_FRANCHORED
#	define	PRL_FRANCHORED	((uint16_t) ((uint16_t) 1) << 11)

#	undef	PRL_SIMPLE
#	define	PRL_SIMPLE	((uint16_t) ((uint16_t) 1) << 12)

// flags for specific nodes

#	undef	PRL_REPEAT_POSSESSIVE
#	define	PRL_REPEAT_POSSESSIVE	((uint16_t) ((uint16_t) 1) << 1)

// names for API

#	undef	PRL_MAX_RECURSION_DEPTH
#	define	PRL_MAX_RECURSION_DEPTH		(1)

#	undef	PRL_MAX_LOOKBEHIND
#	define	PRL_MAX_LOOKBEHIND		(2)
#endif
