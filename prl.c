/*

Copyright 2019 Peter D. Gray

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/


#define	__PRL

#undef	__PRL_MEMORY__
#define	__PRL_MEMORY__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <setjmp.h>

#ifdef	HAVE_RLIMIT
#	include <sys/resource.h>
#endif

#undef	PRINT_COMPILED
#define	PRINT_COMPILED	0

#undef	TRUE
#undef	FALSE
#define	TRUE	(1)
#define	FALSE	(0)

#undef	SANE
#undef	INSANE
#define	SANE	TRUE
#define	INSANE	FALSE

#undef	SET_FLAGS
#undef	UNSET_FLAGS
#undef	ZERO_FLAGS
#define	SET_FLAGS(f,m)		((f) |= (m))
#define	CLEAR_FLAGS(f,m)	((f) &= (~(m)))
#define	ZERO_FLAGS(f)		((f) = 0)

#undef	FLAGS_ARE_SET
#undef	FLAGS_ARE_UNSET
#define FLAGS_ARE_SET(f,m)	(((f) & (m)) == (m))
#define FLAGS_ARE_UNSET(f,m)	(!FLAGS_ARE_SET(f, m))

#undef	OP_SET
#undef	OP_CLEAR
#define	OP_SET		TRUE
#define	OP_CLEAR	FALSE

#undef	COPY_JMPBUF
#define	COPY_JMPBUF(dest,src)	(safe_memmove((void *) (dest), (const void *) (src), sizeof(jmp_buf)))

#undef	FINALIZE
#define FINALIZE(x)		{ rval = (x); goto finalize; }

#undef	ZERO_PIECE
#define	ZERO_PIECE(r)		{ r->piece.start = r->piece.end = NULL; }

#undef	NEGATED
#undef	NARROW
#define	NEGATED(f)		FLAGS_ARE_SET(f, PRL_NEGATED)
#define	NARROW(f)		FLAGS_ARE_SET(f, PRL_NARROW)

#undef	DEADEND
#undef	BEHIND
#define	DEADEND(r)		FLAGS_ARE_SET(r, PRL_DEADEND)
#define	BEHIND(f)		FLAGS_ARE_SET(f, PRL_BEHIND)

#undef	ICASE
#define	ICASE(f)		FLAGS_ARE_SET(f, PRL_ICASE)

#undef	MATCH_COMMENT
#define	MATCH_COMMENT		match_passthru

#undef	MATCH_FUNCTION
#define	MATCH_FUNCTION		match_passthru

#undef	__PRL
#define	__PRL

#undef	STR
#undef	STRINGIFY
#define STR(x)		#x
#define STRINGIFY(x)	STR(x)

#undef	SLABSIZE
#undef	SUBCHARSET_LEN
#undef	STACK_INC

// size of memory slab for nodes etc
#define	SLABSIZE		(1024*32)
// how many characters can we store in block for bracket node
// when exceeded we chain on more nodes
#define	SUBCHARSET_LEN		(16)
// General purpose stack increases in size by this many items
#define	STACK_INC		(64)

#undef	MAX_LOOKBEHIND
#undef	MAX_RECURSION_DEPTH
// How far do we allow lookbehind (default only)
#define	MAX_LOOKBEHIND			(1024)
// How deep do we allow recursion (default only)
#define	MAX_RECURSION_DEPTH		(1024)

typedef	int	mybool_t;

#undef	INTERNAL_ERROR
#define	INTERNAL_ERROR	error(r, "internal error at line " STRINGIFY(__LINE__), PRL_INTERNAL_ERROR)

typedef unsigned char	CHAR;

static int64_t	INFINITY = (int64_t) 0xfffffffffffff;

#undef	MINIMUM_LOOKBEHIND
#define	MINIMUM_LOOKBEHIND	(4)

#undef	MINIMUM_RECURSION_DEPTH
#define	MINIMUM_RECURSION_DEPTH	(8)

// general purpose stack data structure
// this is used to save captures and positions as we recurse
// or match the other branch. Its not fast.
typedef struct
{
	int64_t		max_items;
	int64_t		num_items;
	int64_t		item_size;
	int64_t		bytes;
	CHAR *		items;
} * gp_stack_t;

typedef struct node *	node_t;

typedef	uint16_t	flags_t;

// See man page about pieces
typedef struct
{
	node_t	start;
	node_t	end;
} piece_t;

typedef struct
{
	const CHAR *	start;
	int64_t		len;
} string_t;

typedef struct
{
	int64_t		used;
	CHAR		chars[SUBCHARSET_LEN];
} subcharset_t;

typedef struct
{
	node_t	tail; // chain
} charset_t;

typedef struct
{
	node_t		tail;
	flags_t		flags;
} bracket_t;

typedef struct
{
	int64_t		min_repeat;
	int64_t		max_repeat;
	node_t		tail;
	mybool_t	possessive;
} repeat_t;

typedef struct
{
	int64_t		backref;
	CHAR		charclass;
	CHAR		simple;
	mybool_t	negated;
	mybool_t	narrow;
} backslash_t;

typedef struct
{
	node_t	left;
	node_t	right;
} branch_t;

typedef struct
{
	int64_t		capture_id;
	node_t		tail;
	node_t		backref;
	string_t *	name;
	flags_t		flags;
} subexpr_t;

typedef struct named_node
{
	node_t			node;
	struct named_node *	next;
} * named_node_t;

typedef struct
{
	CHAR	start;
	CHAR	end;
} range_t;

typedef struct prl *	prl_t;

// Each node is a taged union. This burns a bit more space than
// necessary, but makes life simple.

struct node
{
	struct node *	container;	// containing subexpression
	mybool_t	(*match)(prl_t, struct node *);
	struct node *	next;

	int64_t		id;
	union
	{
		subexpr_t	subexpr;
		string_t	string;
		bracket_t	bracket;
		repeat_t	repeat;
		backslash_t	backslash;
		range_t		range;
		branch_t	branch;
		charset_t	charset;
		subcharset_t	subcharset;
	};

	uint64_t		type;
};

// This is the base unit of memory allocation from malloc.
// Makes freeing the node list easy and fast

struct slab
{
	struct slab *	next;
	uint8_t *	top;
	int64_t		left;
	uint8_t		space[SLABSIZE];
};

typedef struct slab * slab_t;

// This is the thing retuned by compile. Lots of internal state kept here

struct prl
{
	const CHAR *	regex_base;
	const CHAR *	regex_offset;

	const CHAR *	string_base;
	const CHAR *	string_offset;

	slab_t		slablist;
	slab_t		current_slab;

	int64_t		node_count;
	node_t		nodelist;
	node_t		node_current;
	node_t		container;
	node_t		atom;
	piece_t		piece;

	struct prl *	address;	// small attempt to catch bad
					// things
	named_node_t	named_nodes;

	int64_t		size_captures;
	string_t *	captures;

	int64_t		num_subexpr;
	int64_t		parse_depth;
	int64_t		subexpression_depth;
	int64_t		recursion_depth;

	int64_t		max_recursion_depth;
	int64_t		max_lookbehind;

	const char *	errmsg;
	node_t		first_wide_node;
	node_t		end_node;		// for anchored searches

	jmp_buf		jmpbuf;

	node_t		bos;			// for anchored searches
	node_t		eos;
	node_t		noop;			// saves allocating more than 1
	node_t		simple;			// regex as a simple string

	int		exit_status;
	mybool_t	used;
	mybool_t	done;			// when match is complete

	flags_t		flags;
	flags_t		passed_flags;
};

#include "prl.h"


typedef node_t		(*parsefunc_t)(prl_t);
typedef mybool_t	(*matchfunc_t)(prl_t, node_t);

// Nearly all node types have a parse function and a match function

static void	out_of_memory		(void);
static void	zero			(prl_t);
static void	zero_captures		(prl_t);
static node_t	parse_regex		(prl_t);
static node_t	parse_subexpr		(prl_t);
static node_t	parse_string		(prl_t);
static node_t	parse_dot		(prl_t);
static node_t	parse_ends		(prl_t);
static node_t	parse_repeat		(prl_t);
static node_t	parse_backslash		(prl_t);
static node_t	parse_bracket		(prl_t);
static node_t	parse_range		(prl_t);
static node_t	parse_branch		(prl_t);
static node_t	parse_subexpr_internal	(prl_t, node_t, node_t);

static void	start_capture		(prl_t, node_t, const CHAR *);
static void	end_capture		(prl_t, node_t, const CHAR *);

static void	zero_capture		(prl_t, node_t);
static void	append_piece		(prl_t, node_t);
static void	prstr			(char *, string_t *, char *);
static void	safe_strncpy		(void *, const void *, int64_t);
static void	safe_memset		(void *, int, int64_t);

static mybool_t	match_noop		(prl_t, node_t);
static mybool_t match_regex		(prl_t, node_t);
static mybool_t	match_subexpr		(prl_t, node_t);
static mybool_t	match_function_call	(prl_t, node_t);
static mybool_t	match_passthru		(prl_t, node_t);
static mybool_t	match_string		(prl_t, node_t);
static mybool_t	match_dot		(prl_t, node_t);
static mybool_t	match_bos		(prl_t, node_t);
static mybool_t	match_eos		(prl_t, node_t);
static mybool_t	match_eos_internal	(prl_t);
static mybool_t match_repeat_greedy	(prl_t, node_t);
static mybool_t match_repeat_non_greedy	(prl_t, node_t);
static mybool_t match_backslash		(prl_t, node_t);
static mybool_t match_branch		(prl_t, node_t);
static mybool_t	match_charset		(prl_t, node_t);
static mybool_t	match_subcharset	(prl_t, node_t);
static mybool_t	match_range		(prl_t, node_t);
static mybool_t	match_bracket		(prl_t, node_t);
static mybool_t match_behind		(prl_t, node_t);

static void	error			(prl_t, const char *, int);

static void		insert_named_node	(prl_t, node_t, named_node_t *);
static node_t		find_named_node		(prl_t, string_t *, int64_t, named_node_t);
static string_t *	get_capture		(prl_t, int64_t, string_t *);
static CHAR		lowercase		(CHAR);
static mybool_t		cmp_string		(string_t *, string_t *, mybool_t);
static int64_t		pdiff			(const CHAR *, const CHAR *);
static void		update_container	(prl_t, node_t, node_t);
static void		safe_memmove		(void *, const void *, int64_t);
static void		prl_print_node_list	(prl_t, char *, node_t);
static const char *	nodename		(prl_t r, node_t node);
static void		parse_paren		(prl_t, int64_t *, int64_t *);
static CHAR		hex			(prl_t);
static mybool_t		isin			(prl_t, CHAR *, CHAR);
static CHAR		simple_backslash	(prl_t);
static mybool_t		isrepeatchar		(prl_t, CHAR, CHAR);
static mybool_t		match_to_end		(prl_t, node_t);

static gp_stack_t	new_stack		(prl_t, int64_t);
static void		destroy_stack		(prl_t, gp_stack_t);
static void		push			(gp_stack_t, void *);
static mybool_t		pop			(gp_stack_t, void *);

// we cheat by mapping these posix classes to our
// backslash class
static struct posix_class_map_entry
{
	CHAR *	name;
	CHAR *	backslash;
	int8_t	len;
} posix_class_map[] =
{
	{ (CHAR *) "[:lower:]",  (CHAR *) "\\l", (int64_t) 9 },
	{ (CHAR *) "[:upper:]",  (CHAR *) "\\u", (int64_t) 9 },
	{ (CHAR *) "[:punct:]",  (CHAR *) "\\p", (int64_t) 9 },
	{ (CHAR *) "[:space:]",  (CHAR *) "\\s", (int64_t) 9 },
	{ (CHAR *) "[:digit:]",  (CHAR *) "\\d", (int64_t) 9 },
	{ (CHAR *) "[:xdigit:]", (CHAR *) "\\h", (int64_t) 10 },
	{ (CHAR *) "[:cntrl:]",  (CHAR *) "\\c", (int64_t) 9 },
	{ (CHAR *) "[:alpha:]",  (CHAR *) "\\a", (int64_t) 9 },
	{ (CHAR *) "[:print:]",  (CHAR *) "\\o", (int64_t) 9 },
	{ (CHAR *) "[:blank:]",  (CHAR *) "\\y", (int64_t) 9 },
	{ (CHAR *) "[:graph:]",  (CHAR *) "\\g", (int64_t) 9 },
	{ (CHAR *) "[:alnum:]",  (CHAR *) "\\m", (int64_t) 9 }
};

// map current char to parse function
static struct parser
{
	CHAR	c;
	parsefunc_t	parserfunc;
} parsers[] =
{
	{ (CHAR) '(',	parse_subexpr },
	{ (CHAR) '.',	parse_dot },
	{ (CHAR) '^',	parse_ends },
	{ (CHAR) '$',	parse_ends },
	{ (CHAR) '*',	parse_repeat },
	{ (CHAR) '?',	parse_repeat },
	{ (CHAR) '+',	parse_repeat },
	{ (CHAR) '{',	parse_repeat },
	{ (CHAR) '\\',	parse_backslash },
	{ (CHAR) '[',	parse_bracket },
	{ (CHAR) '|',	parse_branch }
};

// Node types
#undef		N_NOOP
#undef		N_STRING
#undef		N_SUBEXPR
#undef		N_DOT
#undef		N_BOS
#undef		N_EOS
#undef		N_REPEAT_GREEDY
#undef		N_REPEAT_NON_GREEDY
#undef		N_BACKSLASH
#undef		N_BRACKET
#undef		N_RANGE
#undef		N_CHARSET
#undef		N_SUBCHARSET
#undef		N_BRANCH
#undef		N_DOTSTAR

#define		N_NOOP			0
#define		N_STRING		1
#define		N_SUBEXPR		2
#define		N_DOT			4
#define		N_BOS			5
#define		N_EOS			6
#define		N_REPEAT_GREEDY		7
#define		N_REPEAT_NON_GREEDY	8
#define		N_BACKSLASH		9
#define		N_BRACKET		10
#define		N_RANGE			11
#define		N_CHARSET		12
#define		N_SUBCHARSET		13
#define		N_BRANCH		14
#define		N_DOTSTAR		15	// really just repeat_greedy
						// but used for a bit of optimisation

// Just for printing purposes

static struct nodenames
{
	int64_t	type;
	char *	name;
} names[] =
{
	{ N_DOTSTAR,		"DOTSTAR"		},
	{ N_NOOP,		"NOOP"			},
	{ N_STRING,		"STRING"		},
	{ N_SUBEXPR,		"SUB_EXPRESSION"	},
	{ N_DOT,		"DOT"			},
	{ N_BOS,		"BOS"			},
	{ N_EOS,		"EOS"			},
	{ N_REPEAT_GREEDY,	"REPEAT_GREEDY"		},
	{ N_REPEAT_NON_GREEDY,	"REPEAT_NON_GREEDY"	},
	{ N_BACKSLASH,		"BACKSLASH"		},
	{ N_BRACKET,		"BRACKET"		},
	{ N_CHARSET,		"CHARSET"		},
	{ N_RANGE,		"RANGE"			},
	{ N_BRANCH,		"BRANCH"		}
};

// Stuff to aid readability
#define		M_NOMSG			(0)
#define		M_EMPTY			(1)
#define		M_MATCH_COMPLETE	(2)

#define		QUOTEDSIMPLECHARS	(CHAR *) "\\enrtvx"
#define		ISQUOTEDSIMPLECHAR(r,c)	(isin(r, QUOTEDSIMPLECHARS, c))

#define		CHARCLASSCHARS		((CHAR *) "<>lLuUpPwWsSdDhHcCaAoOmMbByYgGzZ")
#define		METACHARS		((CHAR *) "(.^$\\[|")
#define		REPEATCHARS		((CHAR *) "*?+{")
#define		ENDCHAR			((CHAR) ')')
#define		BRANCHCHAR		((CHAR) '|')
#define		OPTIONCHARS		((CHAR *) "-+inrdz>!")

#define		ISMETACHAR(r, c)	(isin(r, METACHARS, c))
#define		ISBRANCHCHAR(c)		(c == BRANCHCHAR)
#define		ISENDCHAR(c)		(c == ENDCHAR)
#define		ISCHARCLASSCHAR(r,c)	(isin(r, CHARCLASSCHARS, c))
#define		CHARISNULL(c)		((CHAR) (c) == (CHAR) '\0')
#define		ATSTRINGEND		(CHARISNULL(*(r->string_offset)))
#define		NARROWCHARCLASS		((CHAR *) "bB<>")
#define		ISNARROWCHARCLASS(r,c)	(isin(r, NARROWCHARCLASS, c))
#define		ISOPTIONCHAR(r,c)	(isin(r, OPTIONCHARS, c))

#ifdef __PRL_MEMORY__

#define	FREE(x)	FREEIT((void **) (&(x)))

static
void *
MALLOC(register int64_t len)
{
	// return a piece of zeroed memory off the heap
	// Memory returned is always zeroed so
	// initializations are rarely needed
	register void *	rval;

	/*LINTED*/
	rval = malloc((size_t) len);
	if (rval == NULL) out_of_memory();
	safe_memset(rval, 0, len);
	return(rval);
}

static
void
FREEIT(void ** p)
{
	// idempotent
	if (p == NULL) return;
	if (*p == NULL) return;
	(void) free(*p);
	*p = NULL;
	return;
}

#endif

static
void
new_slab(register prl_t r)
{
	register slab_t	rval;

	/*LINTED*/
	rval = MALLOC((int64_t) (sizeof(*rval)));
	rval->next = r->slablist;
	r->slablist = rval;
	r->current_slab = rval;
	rval->left = SLABSIZE;
	rval->top = rval->space;
	return;
}

static
void
free_slablist(register prl_t r, register slab_t * in) /*ARGSUSED*/
{
	// free all the slabs in the list

	slab_t		t;	// address taken
	register slab_t	slab;

	if (in == NULL) return;
	slab = *in;
	*in = NULL;
	for(;;)
	{
		if (slab == NULL) return;
		t = slab;
		slab = slab->next;
		FREE(t);
	}
	/*NOTREACHED*/
}

static
void *
fromslab(register prl_t r, register int64_t size)
{
	register void *	rval;

	/*LINTED*/
	if (size <= 0) INTERNAL_ERROR;
	// round up to 8 bytes boundary
	if ((size & 0x7) != 0) size = (size + 7) & (~(0x7));
	if (r->current_slab == NULL) new_slab(r);
	else if (r->current_slab->left < size) new_slab(r);

	rval = r->current_slab->top;
	r->current_slab->top += size;
	r->current_slab->left -= size;
	return(rval);
}


static
node_t
new_node(register prl_t r, register uint8_t type, register matchfunc_t f, register string_t * name)
{
	register node_t		rval;
	register CHAR *		p;
	register int64_t	len;

	if (name == NULL)
	{
		// name will be a number
		p = fromslab(r, 28);
		name = fromslab(r, sizeof(*name));
		len = snprintf((char *) p, 26, "%lld", (long long) r->num_subexpr);
		name->start = p;
		name->len = len;
	}

	rval = (node_t) fromslab(r, sizeof(*rval));
	rval->type = type;
	rval->id = r->node_count;
	r->node_count++;
	rval->container = r->container;
	if (type == N_SUBEXPR)
	{
		rval->subexpr.capture_id = r->num_subexpr;
		rval->subexpr.name = name;
		insert_named_node(r, rval, &r->named_nodes);
		r->num_subexpr++;
	}

	rval->match = f;
	return(rval);
}

static
void
error(register prl_t r, const char * msg, register int status)
{
	r->errmsg = msg;
	r->exit_status = status;
	longjmp(r->jmpbuf, 1);
	/*NOTREACHED*/
}

static
mybool_t
sane_wordchar(register prl_t r, register CHAR c)
/*ARGSUSED*/
{
	if (isalpha(c) || (c == (CHAR) '-')) return(TRUE);
	return(FALSE);
}

static
mybool_t
wordchar(register prl_t r, register CHAR c)
{
	if (FLAGS_ARE_SET(r->flags, PRL_ALTWORDS)) return(sane_wordchar(r, c));
	if (isalnum(c) || ((CHAR) c == '_')) return(TRUE);
	return(FALSE);
}

static
node_t
simple_string(register prl_t r)
{
	register node_t	rval;

	rval = new_node(r, N_STRING, match_string, NULL);
	rval->string.start = r->regex_base;
	rval->string.len = pdiff(r->regex_base, r->regex_offset);
	return(rval);
}

static
parsefunc_t
get_parser(register prl_t r)
{
	register int64_t i;
	register CHAR	c;

	// hunt for the correct parser, default is string
	c = *r->regex_offset;
	if (CHARISNULL(c)) INTERNAL_ERROR;
	for(i=0; i<sizeof(parsers)/sizeof(struct parser);i++)
	{
		if (c == parsers[i].c) return(parsers[i].parserfunc);
	}
	return(parse_string);
}

// main parser starts here

static
node_t
parse_regex(register prl_t r)
{
	register parsefunc_t	f;
	register CHAR		c;
	register node_t		node;

	r->parse_depth++;
	ZERO_PIECE(r);
	node = NULL;

	for(;;)
	{
		c = *r->regex_offset;
		if (CHARISNULL(c)) break;
		if (ISENDCHAR(c) && r->parse_depth > 1) break;
		f = get_parser(r);
		if (f != parse_repeat) append_piece(r, node);
		node = f(r);
		if (node == NULL) break;
		r->atom = node;
	}
	r->parse_depth--;
	if (node != NULL) append_piece(r, node);
	return(r->piece.start);
}

int
prl_compile(register const CHAR * regex, register prl_t * prl)
{
	register prl_t		r;
	register node_t		node;
	register int64_t	bytes;
#ifdef	HAVE_RLIMIT
	struct rlimit		rlim;
#endif

	// user must supply an address which will point to the
	// new compiled regex. If they do not, return an error.
	if (prl == NULL) return(PRL_NULL);
	r = MALLOC(sizeof(*r));
	*prl = r;

	r->address = r;
	r->used = FALSE;
	r->max_recursion_depth = MAX_RECURSION_DEPTH;
	r->max_lookbehind = MAX_LOOKBEHIND;
#ifdef	HAVE_RLIMIT
	if (getrlimit(RLIMIT_STACK, &rlim) == 0)
	{
		/*LINTED*/
		r->max_recursion_depth = (uint64_t) (rlim.rlim_cur / 1024);
		if (r->max_recursion_depth > MAX_RECURSION_DEPTH)
			r->max_recursion_depth = MAX_RECURSION_DEPTH;
	}
#endif
	*prl = r;
	if (regex == NULL)
	{
		r->errmsg = "NULL regex";
		r->exit_status = PRL_USAGE_ERROR;
		return(PRL_USAGE_ERROR);
	}

	// I assume traditional semantics for setjmp,
	// namely that they stack and the state is
	// returned to exactly what it was when setjmp was called.
	if (setjmp(r->jmpbuf) != 0) return(r->exit_status);

	/*LINTED*/
	bytes = (int64_t) strlen((char *) regex) + 1;
	r->regex_base = MALLOC(bytes);
	safe_memmove((void *) r->regex_base, regex, bytes);

	r->regex_offset = r->regex_base;

	r->bos = new_node(r, N_BOS, match_bos, NULL);
	r->eos = new_node(r, N_EOS, match_eos, NULL);
	r->noop = new_node(r, N_NOOP, match_noop, NULL);

	r->nodelist = new_node(r, N_SUBEXPR, match_subexpr, NULL);

	node = parse_regex(r);
	r->nodelist->subexpr.tail = node;
	if (node != NULL)
	{
		// last real node
		// so we can later add anchors if needed
		while(node->next != NULL) node = node->next;
		r->end_node = node;
	}

	/*LINTED*/
	r->size_captures = (int64_t) (sizeof(string_t) * r->num_subexpr);
	r->captures = MALLOC(r->size_captures);

	node = r->nodelist;

	for(;;)
	{
		if (node == NULL) break;
		if (node->type != N_SUBEXPR) break;
		if (NARROW(node->subexpr.flags)) break;
		node = node->subexpr.tail;
	}

	if (node != NULL)
	{
		if (node->type == N_BOS)
		{
			/*LINTED*/
			SET_FLAGS(r->flags, PRL_FRANCHORED);
			node = node->next;
		}

		if (node != NULL)
		{
			if ((node->type == N_STRING) || node->type == N_DOTSTAR)
			{
				r->first_wide_node = node;
			}
		}
	}

	// Set up the special node for treating the entire
	// regex as a string, for PRL_SIMPLE flag.
	r->simple = fromslab(r, sizeof(*r->simple));
	*r->simple = *r->nodelist;
	r->simple->subexpr.tail = simple_string(r);
	if (r->first_wide_node == NULL) r->first_wide_node = r->noop;
#if	PRINT_COMPILED
	prl_print_node_list(r, "Compiled node list", r->nodelist);
#endif

	return(PRL_OK);
}

// Try to catch obvious corruption or stupidity by the caller
static
void
check_prl(register prl_t r)
{
	if ((r == NULL) || (r->address != r))
	{
		(void) fprintf(stderr, "Null PRL address or corrupted PRL structure. ABORT!\n");
		exit(PRL_CORRUPTION);
	}
	return;
}


void
prl_internals(register prl_t r)
{
	check_prl(r);
	prl_print_node_list(r, "Compiled PRL", r->nodelist);
	return;
}

static
void
anchor(register prl_t r)
{
	register node_t	node;

	// add bos to start of regex and add eos to the end
	// idempotent
	node = r->nodelist;
	if (node == NULL) return;
	// first node is always a subexpr
	if (node->subexpr.tail == NULL) return;
	if (node->subexpr.tail == r->bos) return; // already anchored
	r->bos->next = node->subexpr.tail;
	node->subexpr.tail = r->bos;
	r->end_node->next = r->eos;
	/*LINTED*/
	SET_FLAGS(r->flags, PRL_FRANCHORED); // no need to unset
	return;
}

static
void
unanchor(register prl_t r)
{
	register node_t	node;

	// remove previous anchor, idempotent
	node = r->nodelist;
	if (node == NULL) return;
	if (node->subexpr.tail != r->bos) return; // not anchored
	node->subexpr.tail = r->bos->next;
	r->bos->next = NULL;
	r->end_node->next = NULL;
	return;
}

static
int
prl_match_internal(register prl_t r, register flags_t flags, node_t list)
{
	r->used = TRUE;
	r->done = FALSE;

	if (setjmp(r->jmpbuf) != 0) return(r->exit_status);
	if (r->string_base == NULL) error(r, "NULL string", PRL_USAGE_ERROR);

	ZERO_FLAGS(r->flags);
	SET_FLAGS(r->flags, flags);

	r->passed_flags = r->flags;
	r->exit_status = PRL_NOMATCH;
	if (match_regex(r, list))
	{
		r->exit_status = PRL_MATCH;
		return(PRL_MATCH);
	}

	return(PRL_NOMATCH);
}

int
prl_match(register prl_t r, register const CHAR * string, register int64_t in_flags)
{
	register flags_t	flags;
	register int		rval;
	register node_t		nodelist;


	check_prl(r);
	zero(r);
	/*LINTED*/
	flags = (flags_t) (in_flags & 0xffff);

	nodelist = r->nodelist;
	if (FLAGS_ARE_SET(flags, PRL_SIMPLE)) nodelist = r->simple;

	r->string_base = string;
	r->string_offset = string;
	rval = prl_match_internal(r, flags, nodelist);
	if (rval != PRL_MATCH) return(rval);
	if (!CHARISNULL(*(r->string_offset)))
	{
		rval = PRL_NOMATCH;
		r->exit_status = PRL_NOMATCH;
	}
	return(rval);
}

static
const CHAR *
advance(register const CHAR * s)
{
	if (*s != '\r') return(s+1);
	if (*(s+1) == '\n') return(s+2);
	return(s+1);
}

int
prl_search(register prl_t r, register const CHAR * string, register int64_t in_flags)
{
	register const CHAR *	s;
	register mybool_t	icase;
	register CHAR		c;
	register CHAR		first_char;
	register flags_t	flags;
	register node_t		nodelist;
	register mybool_t	crnl;

	check_prl(r);
	zero(r);
	/*LINTED*/
	flags = (flags_t) (in_flags & 0xffff);

	nodelist = r->nodelist;
	if (FLAGS_ARE_SET(flags, PRL_SIMPLE)) nodelist = r->simple;

	r->flags = flags;
	icase = FALSE;
	if (ICASE(flags)) icase = TRUE;

	if (FLAGS_ARE_SET(flags, PRL_ANCHORED)) anchor(r);
	else unanchor(r);

	s = string;
	c = *s;

	r->string_base = string;
	r->string_offset = string;
	// the first match is special
	(void) prl_match_internal(r, flags, nodelist);
	if (r->exit_status == PRL_MATCH) return(PRL_MATCH);
	if (r->exit_status != PRL_NOMATCH) return(r->exit_status);

	// We did not match
	// If we are front anchored and we did not match then we
	// will never match, unless BOS matches a LF or CRLF
	// sequence further into the string. For that to happen
	// the flages must allow it.
	if (FLAGS_ARE_SET(r->flags, PRL_FRANCHORED) &&
	   (FLAGS_ARE_UNSET(r->flags, PRL_NLISEOS)) &&
	   (FLAGS_ARE_UNSET(r->flags, PRL_CRNLISEOS)))
	{
		// This string can never match
		return(PRL_NOMATCH);
	}

	// If the first node is a dotstar then we can never match either, except
	// if the flags say that dot does not match EOS in which
	// its possible we can match further into the string (I think).
	if ((r->first_wide_node->type == N_DOTSTAR) &&
	    FLAGS_ARE_UNSET(r->flags, PRL_DOTNOEOS))
	{
		return(PRL_NOMATCH);
	}

	first_char = (CHAR) '\0';

	if (r->first_wide_node->type == N_STRING)
	{
		first_char = *(r->first_wide_node->string.start);
	}

	zero_captures(r);
	crnl = FALSE;
	if (FLAGS_ARE_SET(r->flags, PRL_CRNLISEOS)) crnl = TRUE;

	if (CHARISNULL(first_char))
	{
		// the slow way
		for(;;)
		{
			r->string_offset = s;
			zero_captures(r);
			(void) prl_match_internal(r, flags, nodelist);
			if (r->exit_status == PRL_MATCH) return(PRL_MATCH);
			if (r->exit_status != PRL_NOMATCH) return(r->exit_status);
			if (CHARISNULL(c)) return(PRL_NOMATCH);
			if (crnl) s = advance(s);
			else s++;
			c = *s;
		}
		/*NOTREACHED*/
	}

	// we can optimize by looking at the first char
	/*LINTED*/
	if (icase) first_char = (CHAR) tolower(first_char);

	for(;;)
	{
		/*LINTED*/
		if (icase) c = (CHAR) tolower(c);

		if ((!CHARISNULL(c)) && (c != first_char))
		{
			s++;
			c = *s;
			continue;
		}

		zero_captures(r);
		r->string_offset = s;
		zero_captures(r);
		(void) prl_match_internal(r, flags, nodelist);
		if (r->exit_status == PRL_MATCH) return(PRL_MATCH);
		if (r->exit_status != PRL_NOMATCH) return(r->exit_status);
		if (CHARISNULL(*s)) return(PRL_NOMATCH);
		if (crnl) s = advance(s);
		else s++;
		c = *s;
	}

	/*NOTREACHED*/
}

static
mybool_t
match_regex(register prl_t r, register node_t node)
{
	register mybool_t	rval;

	if (node == NULL) return(TRUE);
	rval = FALSE;

	while(node != NULL)
	{
		rval = node->match(r, node);
		if (r->done)
		{
			rval = TRUE;
			break;
		}

		if (!rval)
		{
			rval = FALSE;
			break;
		}

		node = node->next;
	}
	return(rval);
}

static
mybool_t
match_named_capture(register prl_t r, register node_t node)
{
	register string_t *	capture;
	string_t		str;	// address taken
	register mybool_t	rval;

	capture = get_capture(r, node->subexpr.backref->subexpr.capture_id, NULL);
	str.start = r->string_offset;
	str.len = capture->len;

	if (str.len < 0) str.len = pdiff(r->string_offset, str.start);
	rval = cmp_string(&str, capture, (mybool_t) ICASE(r->flags));
	if (rval)
	{
		start_capture(r, node, r->string_offset);
		r->string_offset += capture->len;
		(void) end_capture(r, node, r->string_offset);
	}
	else zero_capture(r, node);
	return(rval);
}

static
const CHAR *
eat(register const CHAR * p, register CHAR end) /*ARGSUSED*/
{
	for(;;)
	{
		if (CHARISNULL(*p)) return(NULL);
		if (*p == (CHAR) '\\') p++;
		else if (*p == end) return(p);
		p++;
	}
	/*NOTREACHED*/
}

static
int64_t
pdiff(register const CHAR * start, register const CHAR * end)
{
	/*LINTED*/
	return((uint64_t) (end - start));
}

static
node_t
parse_comment(register prl_t r)
{
	register node_t		rval;
	register const CHAR *	p;
	register string_t *	name;

	if (*r->regex_offset != '#') INTERNAL_ERROR;
	r->regex_offset++;
	p = eat(r->regex_offset, ')');
	if ((p == NULL) || (CHARISNULL(*p))) error(r, "unterminated comment", PRL_COMPILE_ERROR);
	name = fromslab(r, sizeof(*name));
	name->start = r->regex_offset;
	name->len = pdiff(r->regex_offset, p);
	rval = new_node(r, N_SUBEXPR, MATCH_COMMENT, name);
	r->regex_offset = p;
	/*LINTED*/
	SET_FLAGS(rval->subexpr.flags, PRL_NARROW);
	return(parse_subexpr_internal(r, rval, NULL));
}

static
mybool_t
match_capture(register prl_t r, register int64_t ref)
{
	register mybool_t	rval;
	register string_t *	capture;
	string_t		str; // address taken
	register int64_t	save_len;

	capture = get_capture(r, ref, NULL);
	if (capture == NULL) INTERNAL_ERROR;
	if (capture->start == NULL) return(TRUE);
	save_len = capture->len;
	if (capture->len < 0) capture->len = pdiff(capture->start, r->string_offset);

	str.start = r->string_offset;
	str.len = capture->len;
	rval = cmp_string(&str, capture, (mybool_t) ICASE(r->flags));
	if (rval) r->string_offset += capture->len;
	capture->len = save_len;
	return(rval);
}

static
mybool_t
match_passthru(register prl_t r, register node_t node)
{
	start_capture(r, node, node->subexpr.name->start);
	end_capture(r, node, node->subexpr.name->start + node->subexpr.name->len);
	if (node->next == NULL) r->done = TRUE;
	return(TRUE);
}

static
mybool_t
alldigits(register string_t * str)
{
	register int64_t	len;
	register const CHAR *	p;

	len = str->len;
	p = str->start;
	while(len > 0)
	{
		if (!isdigit(*p)) return(FALSE);
		p++; len--;
	}
	return(TRUE);
}

static
mybool_t
string_to_number(register string_t * str, register int64_t * result)
{
	register int64_t		i;
	register const CHAR *		p;
	register int			c;
	register mybool_t		negative;

	// number is not a C string, so do conversion by hand
	*result = 0;
	negative = FALSE;
	i = str->len;
	// loop invarient
	p = str->start; c = *p;

	if ((p == NULL) || (CHARISNULL(*p))) return(FALSE);

	if (c == (CHAR) '-')
	{
		negative = TRUE;
		p++; i--; c = *p;
	}
	else if (c == (CHAR) '+')
	{
		p++; i--; c = *p;
	}

	if (!isdigit(c)) return(FALSE);

	while(i > 0)
	{
		if (!isdigit(c)) return(FALSE);
		*result = (*result * 10) + (c - '0');
		p++; i--; c = *p;
	}
	if (negative) *result = -(*result);
	return(TRUE);
}


static
node_t
find_named_node(register prl_t r, register string_t * name, int64_t number, // address taken
		register named_node_t list)
{
	// linear search
	if (name == NULL)
	{
		// by number
		while(list != NULL)
		{
			if (number == list->node->subexpr.capture_id) return(list->node);
			list = list->next;
		}
		return(NULL);
	}

	if (alldigits(name))
	{
		// name is all digits, convert to integer and search on that
		// in the hope its quicker
		if (!string_to_number(name, &number)) INTERNAL_ERROR;
		return(find_named_node(r, NULL, number, list));
	}

	// search by name
	while(list != NULL)
	{
		if (cmp_string(name, list->node->subexpr.name, FALSE)) return(list->node);
		list = list->next;
	}
	return(NULL);
}

static
void
insert_named_node(register prl_t r, register node_t node, register named_node_t * list)
{
	register named_node_t	named_node;
	register node_t		t;

	t = find_named_node(r, node->subexpr.name, -1, *list);
	if (t != NULL) error(r, "duplicate group or function", PRL_COMPILE_ERROR);

	named_node = fromslab(r, sizeof(*named_node));
	named_node->node = node;
	named_node->next = *list;
	*list = named_node;
	return;
}

static
mybool_t
match_recursion(register prl_t r, register node_t node)
{
	register mybool_t	rval;
	string_t *		saved_captures;	// address taken
	jmp_buf			saved_jmpbuf;

	r->recursion_depth++;
	if (r->recursion_depth > r->max_recursion_depth)
		error(r, "maximum recursion depth exceeded", PRL_SYSTEM_ERROR);
	saved_captures = NULL;
	/*LINTED*/
	COPY_JMPBUF(saved_jmpbuf, r->jmpbuf);
	if (setjmp(r->jmpbuf) != 0)
	{
		// if we have a problem, return thru here
		// poor mans exceptions
		FREE(saved_captures);
		COPY_JMPBUF(r->jmpbuf, saved_jmpbuf);
		r->recursion_depth--;
		longjmp(r->jmpbuf, r->exit_status);
	}


	saved_captures = r->captures;
	r->captures = MALLOC(r->size_captures);
	safe_memmove((void *) r->captures, (const void *) saved_captures, r->size_captures);
	rval = match_regex(r, node->subexpr.backref);
	FREE(r->captures);
	r->captures = saved_captures;
	COPY_JMPBUF(r->jmpbuf, saved_jmpbuf);
	r->recursion_depth--;
	return(rval);
}


static
node_t
parse_recursion(register prl_t r)
{
	register CHAR		c;
	string_t		name;	// address taken
	register node_t		backref_node;
	register const CHAR *	p;
	register node_t		rval;

	c = *r->regex_offset;
	if (c != 'R') INTERNAL_ERROR;
	r->regex_offset++;
	c = *r->regex_offset;

	if (c == (CHAR) ')')
	{
		backref_node = find_named_node(r, NULL, 0, r->named_nodes);
		if (backref_node == NULL) INTERNAL_ERROR;
		rval = new_node(r, N_SUBEXPR, match_recursion, NULL);
		rval->subexpr.backref = backref_node;
		return(parse_subexpr_internal(r, rval, NULL));
	}

	if (c != '=') error(r, "missing recursion name", PRL_COMPILE_ERROR);
	r->regex_offset++;
	c = *r->regex_offset;
	if (c == (CHAR) ')') error(r, "missing recursion name", PRL_COMPILE_ERROR);

	name.start = r->regex_offset;
	p = eat(r->regex_offset, ')');
	if (p == NULL) error(r, "unterminated recursion name", PRL_COMPILE_ERROR);
	r->regex_offset = p;
	c = *r->regex_offset;

	/*LINTED*/
	name.len = (int64_t) (p - name.start);
	backref_node = find_named_node(r, &name, 0, r->named_nodes);
	if (backref_node == NULL) error(r, "bad recursion name", PRL_COMPILE_ERROR);
	rval = new_node(r, N_SUBEXPR, match_recursion, NULL);
	rval->subexpr.backref = backref_node;
	return(parse_subexpr_internal(r, rval, NULL));
}



static
node_t
parse_function(register prl_t r)
{
	register CHAR		c;
	register const CHAR *	p;
	register node_t		rval;
	register string_t *	name;
	string_t		local_name; // address taken
	register node_t		function;


	c = *r->regex_offset;
	if (c != 'F') INTERNAL_ERROR;
	r->regex_offset++;
	c = *r->regex_offset;

	if (c == (CHAR) '=')
	{
		// function call
		r->regex_offset++;
		c = *r->regex_offset;
		local_name.start = r->regex_offset;
		p = eat(r->regex_offset, ')');
		if (p == NULL) error(r, "unterminated function name", PRL_COMPILE_ERROR);
		r->regex_offset = p;
		rval = new_node(r, N_SUBEXPR, match_function_call, NULL);
		/*LINTED*/
		local_name.len = (int64_t) (p - local_name.start);
		// is the name numeric
		if (local_name.len == 0) error(r, "mission function name", PRL_COMPILE_ERROR);
		function = find_named_node(r, &local_name, 0, r->named_nodes);
		if (function == NULL) error(r, "reference to undefined named subexpression", PRL_COMPILE_ERROR);
		return(parse_subexpr_internal(r, rval, function->subexpr.tail));
	}

	name = fromslab(r, sizeof(*name));
	if (c != '<') error(r, "bad function subexpression", PRL_COMPILE_ERROR);
	r->regex_offset++;
	name->start = r->regex_offset;
	p = eat(r->regex_offset, '>');
	if (p == NULL) error(r, "unterminated function name", PRL_COMPILE_ERROR);
	/*LINTED*/
	name->len = (int64_t) (p - name->start);
	if (name->len == 0) error(r, "empty function name", PRL_COMPILE_ERROR);

	rval = new_node(r, N_SUBEXPR, MATCH_FUNCTION, name);
	/*LINTED*/
	SET_FLAGS(rval->subexpr.flags, PRL_DEADEND);
	r->regex_offset = p + 1;
	return(parse_subexpr_internal(r, rval, NULL));
}

static
node_t
parse_named_subexpr(register prl_t r)
{
	register CHAR		c;
	register const CHAR *	p;
	register node_t		rval;
	register string_t *	name;
	string_t		tmpname; // address taken
	register node_t		backref;

	c = *r->regex_offset;
	if (c != 'P') INTERNAL_ERROR;
	r->regex_offset++;
	c = *r->regex_offset;

	if (c == (CHAR) '=')
	{
		// backreference
		r->regex_offset++;
		c = *r->regex_offset;
		tmpname.start = r->regex_offset;

		p = eat(r->regex_offset, ')');
		if (p == NULL) error(r, "unterminated subexpression", PRL_COMPILE_ERROR);
		/*LINTED*/
		tmpname.len = (int64_t) (p - tmpname.start);
		backref = find_named_node(r, &tmpname, -1, r->named_nodes);

		if (backref == NULL)
			error(r, "reference to undefined named subexpression", PRL_COMPILE_ERROR);
		name = fromslab(r, sizeof(*name));
		*name = tmpname;
		rval = new_node(r, N_SUBEXPR, match_named_capture, NULL);
		rval->subexpr.backref = backref;
		return(parse_subexpr_internal(r, rval, NULL));
	}


	name = fromslab(r, sizeof(*name));
	if (c != '<') error(r, "bad named capture subexpression", PRL_COMPILE_ERROR);
	r->regex_offset++;
	name->start = r->regex_offset;
	p = eat(r->regex_offset, '>');
	if (p == NULL) error(r, "unterminated subexpression name", PRL_COMPILE_ERROR);
	/*LINTED*/
	name->len = (int64_t) (p - name->start);
	if (alldigits(name)) error(r, "all numeric subexpression name", PRL_COMPILE_ERROR);
	if (name->len == 0) error(r, "empty subexpression name", PRL_COMPILE_ERROR);
	rval = new_node(r, N_SUBEXPR, match_subexpr, name);
	r->regex_offset = p + 1;
	return(parse_subexpr_internal(r, rval, NULL));
}

static
node_t
parse_lookahead(register prl_t r)
{
	register node_t	rval;
	register CHAR	c;

	c = *r->regex_offset;
	if ((c != '=') && (c != '!')) INTERNAL_ERROR;

	rval = new_node(r, N_SUBEXPR, match_subexpr, NULL);
	/*LINTED*/
	SET_FLAGS(rval->subexpr.flags, PRL_NARROW);
	/*LINTED*/
	if (c == (CHAR) '!') SET_FLAGS(rval->subexpr.flags, PRL_NEGATED);
	r->regex_offset++;
	return(parse_subexpr_internal(r, rval, NULL));
}

static
node_t
parse_lookbehind(register prl_t r)
{
	register node_t	rval;
	register CHAR	c;

	c = *r->regex_offset;
	if (c != '<') INTERNAL_ERROR;

	r->regex_offset++;
	c = *r->regex_offset;

	if ((c != '=') && (c != '!')) error(r, "bad lookbehind syntax", PRL_COMPILE_ERROR);

	rval = new_node(r, N_SUBEXPR, match_behind, NULL);
	/*LINTED*/
	SET_FLAGS(rval->subexpr.flags, PRL_NARROW);

	/*LINTED*/
	if (c == (CHAR) '!') SET_FLAGS(rval->subexpr.flags, PRL_NEGATED);

	r->regex_offset++;
	return(parse_subexpr_internal(r, rval, NULL));
}

static
node_t
parse_subexpr_internal(register prl_t r, node_t rval, register node_t tail)
{
	register node_t		subexpr_node;
	register node_t *	tnode;
	register CHAR		c;
	register node_t		my_container;
	register piece_t	my_piece;

	c = *r->regex_offset;

	if (CHARISNULL(c)) error(r, "opening brace at end of regex", PRL_COMPILE_ERROR);

	my_container = rval->container;
	r->container = rval;
	my_piece = r->piece;
	ZERO_PIECE(r);

	if (c == (CHAR) ')')
	{
		rval->subexpr.tail = tail;
		if (tail == NULL) rval->subexpr.tail = r->noop;
		r->regex_offset++;
		r->container = my_container;
		r->piece = my_piece;
		return(rval);
	}

	tnode = &rval->subexpr.tail;

	for(;;)
	{
		subexpr_node = parse_regex(r);
		*tnode = subexpr_node;
		tnode = &subexpr_node->next;
		c = *r->regex_offset;
		if (c == (CHAR) ')')
		{
			r->regex_offset++;
			r->container = my_container;
			r->piece = my_piece;
			return(rval);
		}

		if (CHARISNULL(c)) error(r, "unmatched opening brace", PRL_COMPILE_ERROR);
	}
	/*NOTREACHED*/
}

static
flags_t
set_or_clear(register flags_t rval, register flags_t value, register mybool_t negated)
{
	/*LINTED*/
	if (negated) rval |= (flags_t) (value << (flags_t) 8);
	else rval |= value;
	return(rval);
}

static
node_t
parse_option(register prl_t r)
{
	register node_t		rval;
	register CHAR		c;
	register mybool_t	negated;

	negated = FALSE;
	c = *r->regex_offset;
	rval = new_node(r, N_SUBEXPR, match_subexpr, NULL);

	if (c == (CHAR) '>')
	{
		rval->subexpr.flags = set_or_clear(rval->subexpr.flags, PRL_ATOMIC, FALSE);
		r->regex_offset++;
		c = *r->regex_offset;
		return(parse_subexpr_internal(r, rval, NULL));
	}

	while(c != ':')
	{
		switch(c)
		{
			case '-':	negated = TRUE;
					break;
			case '+':	negated = FALSE;
					break;
			case '!':	rval->subexpr.flags = set_or_clear(rval->subexpr.flags, PRL_NEGATED, negated);
					break;
			case '>':	rval->subexpr.flags = set_or_clear(rval->subexpr.flags, PRL_ATOMIC, negated);
					break;
			case 'i':	rval->subexpr.flags = set_or_clear(rval->subexpr.flags, PRL_ICASE, negated);
					break;
			case 'n':	rval->subexpr.flags = set_or_clear(rval->subexpr.flags, PRL_NLISEOS, negated);
					break;
			case 'r':	rval->subexpr.flags = set_or_clear(rval->subexpr.flags, PRL_CRNLISEOS, negated);
					break;
			case 'd':	rval->subexpr.flags = set_or_clear(rval->subexpr.flags, PRL_DOTNOEOS, negated);
					break;
			case 'z':	rval->subexpr.flags = set_or_clear(rval->subexpr.flags, PRL_ALTWORDS, negated);
					break;
			case '\0':	error(r, "unterminated subexpression", PRL_COMPILE_ERROR);
					break;
			default:	error(r, "bad subexpression option", PRL_COMPILE_ERROR);
					break;
		}

		r->regex_offset++;
		c = *r->regex_offset;
	}

	r->regex_offset++;
	c = *r->regex_offset;
	return(parse_subexpr_internal(r, rval, NULL));
}

static
node_t
parse_subexpr(register prl_t r)
{
	register CHAR	c;
	register node_t	rval;

	c = *r->regex_offset;
	if (c != '(') INTERNAL_ERROR;
	r->regex_offset++;
	c = *r->regex_offset;
	if (c != '?')
	{
		rval = new_node(r, N_SUBEXPR, match_subexpr, NULL);
		return(parse_subexpr_internal(r, rval, NULL));
	}

	r->regex_offset++;
	c = *r->regex_offset;

	if (c == (CHAR) '#') return(parse_comment(r));
	if (c == (CHAR) 'P') return(parse_named_subexpr(r));
	if (c == (CHAR) '<') return(parse_lookbehind(r));
	if (c == (CHAR) '!') return(parse_lookahead(r));
	if (c == (CHAR) '=') return(parse_lookahead(r));
	if (c == (CHAR) 'F') return(parse_function(r));
	if (c == (CHAR) 'T') return(parse_function(r));
	if (c == (CHAR) 'R') return(parse_recursion(r));

	if (ISOPTIONCHAR(r, c)) return(parse_option(r));
	error(r, "unknown subexpression extension", PRL_COMPILE_ERROR);
	/*NOTREACHED*/
	return(NULL);
}

static
mybool_t
match_noop(register prl_t r, register node_t node) /*ARGSUSED*/
{
	return(TRUE);
}

static
void
zero_capture(register prl_t r, register node_t node)
{
	register string_t *	capture;

	capture = get_capture(r, node->subexpr.capture_id, NULL);
	capture->start = NULL;
	capture->len = 0;
	return;
}


static
void
start_capture(register prl_t r, register node_t node, register const CHAR * start)
{
	register string_t *	capture;

	if (start == NULL) start = r->string_offset;
	capture = get_capture(r, node->subexpr.capture_id, NULL);
	if (capture == NULL) INTERNAL_ERROR;
	capture->start = start;
	capture->len = -1;
	return;
}

static
void
end_capture(register prl_t r, register node_t node, register const CHAR * end)
{
	register string_t *	capture;
	register int64_t	len;

	if (end == NULL) end = r->string_offset;
	capture = get_capture(r, node->subexpr.capture_id, NULL);
	if (capture == NULL) INTERNAL_ERROR;

	// if we have no end, zero capture
	if (end == NULL)
	{
		capture->start = NULL;
		capture->len = -1;
		return;
	}

	if (capture->start == NULL)
	{
		capture->len = -1;
		return;
	}

	if (capture->len >= 0) return;
	len = pdiff(capture->start, end);
	capture->len = len;
	if (len <= 0)
	{
		capture->start = NULL;
		capture->len = -1;
	}
	return;
}

static
mybool_t
match_behind(register prl_t r, register node_t node)
{
	register mybool_t	rval;
	register int64_t	len;
	register int64_t	offset;
	register const CHAR *	save_offset;
	register const CHAR *	save_base;
	CHAR *			tmp_string; // address taken
	jmp_buf			save_jmpbuf;

	rval = FALSE;
	save_offset = (CHAR *) r->string_offset;
	save_base = (CHAR *) r->string_base;
	// 2 cases
	// 1) We have a single simple string, hopefully the most common case
	if ((node->subexpr.tail->type == N_STRING) && (node->subexpr.tail->next == NULL))
	{
		len = node->subexpr.tail->string.len;
		/*LINTED*/
		offset = (int64_t) (r->string_offset - r->string_base);
		if (offset < len) return(FALSE);
		r->string_offset -= len;
		start_capture(r, node, r->string_offset);
		rval = match_regex(r, node->subexpr.tail);
		if (rval) (void) end_capture(r, node, r->string_offset);
		else zero_capture(r, node);
		if (NEGATED(node->subexpr.flags)) rval = (mybool_t) !rval;
		r->done = FALSE;
		r->string_base = save_base;
		r->string_offset = save_offset;
		return(rval);
	}

	// 2) the hard case
	// we have to copy stuff around and do a search

	tmp_string = NULL;
	// we need to make sure we come back thru here
	// to fix things up
	COPY_JMPBUF(save_jmpbuf, r->jmpbuf);
	if (setjmp(r->jmpbuf) != 0)
	{
		// poor mans exceptions again
		FREE(tmp_string);
		r->string_base = save_base;
		r->string_offset = save_offset;
		r->done = FALSE;
		COPY_JMPBUF(r->jmpbuf, save_jmpbuf);
		longjmp(r->jmpbuf, 1);
	}

	/*LINTED*/
	len = (int64_t) sizeof(CHAR) * (int64_t) (r->string_offset - r->string_base);
	if (len > r->max_lookbehind) len = r->max_lookbehind;

	tmp_string = MALLOC(len + 2);
	safe_memmove((void *) tmp_string, (const void *) (r->string_offset - len), len);
	r->string_base = (const CHAR *) tmp_string;

	for(;;) // search backwards is hopefully quicker
	{
		len--;
		if (len < 0) break;
		r->string_offset = r->string_base + len;
		start_capture(r, node, save_base + len);
		rval = match_regex(r, node->subexpr.tail);
		if (rval) (void) end_capture(r, node, r->string_offset);
		else zero_capture(r, node);
		if (NEGATED(node->subexpr.flags)) rval = (mybool_t) !rval;
		if (rval) break;
	}

	FREE(tmp_string);
	r->string_base = save_base;
	r->string_offset = save_offset;
	r->done = FALSE;
	COPY_JMPBUF(r->jmpbuf, save_jmpbuf);
	return(rval);
}

static
mybool_t
match_function_call(register prl_t r, register node_t node)
{
	// this routine is not needed but its neater and the compiler
	// should optimise it out
	return(match_subexpr(r, node));
}

static
mybool_t
match_subexpr(register prl_t r, register node_t node)
{
	register mybool_t	rval;
	register const CHAR *	save_offset;
	register flags_t	save_flags;

	save_offset = (CHAR *) r->string_offset;
	save_flags = r->flags;

	// bits in the bottom 8 bits we turn on
	/*LINTED*/
	SET_FLAGS(r->flags, node->subexpr.flags & (flags_t) 0xFF);

	// bits in the top 8 bits we turn off in the bottem bits
	/*LINTED*/
	CLEAR_FLAGS(r->flags, ((node->subexpr.flags & (flags_t) 0xFF00) >> (flags_t) 8));
	start_capture(r, node, r->string_offset);
	rval = match_regex(r, node->subexpr.tail);
	if (rval) end_capture(r, node, r->string_offset);
	else zero_capture(r, node);

	r->flags = save_flags;

	if (NEGATED(node->subexpr.flags)) rval = !rval;
	if (NARROW(node->subexpr.flags))
	{
		r->done = FALSE;
		r->string_offset = (CHAR *) save_offset;
	}

	return(rval);
}


static
node_t
parse_char(register prl_t r)
{
	register node_t		rval;

	rval = new_node(r, N_STRING, match_string, NULL);
	rval->string.start = r->regex_offset;
	rval->string.len = 1;
	r->regex_offset++;
	return(rval);
}

static
node_t
parse_string(register prl_t r)
{
	register node_t		rval;
	register CHAR		c;
	register CHAR		ahead1;
	register CHAR		ahead2;

	ahead1 = *(r->regex_offset + 1);
	ahead2 = (CHAR) '\0';
	if (!CHARISNULL(ahead1)) ahead2 = *(r->regex_offset + 2);
	if (isrepeatchar(r, ahead1, ahead2)) return(parse_char(r));

	rval = new_node(r, N_STRING, match_string, NULL);
	rval->string.start = r->regex_offset;
	rval->string.len = 1;
	r->regex_offset++;

	for(;;)
	{
		c = *r->regex_offset;
		if (CHARISNULL(c)) return(rval);
		if (ISENDCHAR(c) && (r->parse_depth > 1)) return(rval);
		if (ISMETACHAR(r, c)) return(rval);

		ahead1 = *(r->regex_offset + 1);
		ahead2 = (CHAR) '\0';
		if (!CHARISNULL(ahead1)) ahead2 = *(r->regex_offset + 2);
		if (isrepeatchar(r, ahead1, ahead2)) return(rval);

		if ((r->parse_depth > 1) && ISENDCHAR(c)) return(rval);
		rval->string.len++;
		r->regex_offset++;
	}
	/*NOTREACHED*/
}


static
mybool_t
match_string(register prl_t r, register node_t node)
{
	string_t		ts;	// address taken
	register mybool_t	rval;

	if (ATSTRINGEND) return(FALSE);
	ts.start = r->string_offset;
	ts.len = node->string.len;
	rval = cmp_string(&(node->string), &ts, (mybool_t) ICASE(r->flags));
	if (rval) r->string_offset += node->string.len;
	return(rval);
}

static
node_t
parse_ends(register prl_t r)
{
	register node_t		rval;
	register CHAR		c;

	rval = NULL; // for lint
	c = *r->regex_offset;
	if (c == (CHAR) '^') rval = new_node(r, N_BOS, match_bos, NULL);
	else if (c == (CHAR) '$') rval = new_node(r, N_EOS, match_eos, NULL);
	else INTERNAL_ERROR;
	r->regex_offset++;
	return(rval);
}

static
mybool_t
match_bos(register prl_t r, register node_t node)
/*ARGSUSED*/
{
	register const CHAR *	behind;

	if (r->string_offset == r->string_base) return(TRUE);
	if (ATSTRINGEND) return(FALSE);
	behind = r->string_offset - 1;	// safe, we are past string_base
	if (FLAGS_ARE_SET(r->flags, PRL_CRNLISEOS))
	{
		if (*behind != (CHAR) '\n') return(FALSE);
		if (behind == r->string_base) return(FALSE);
		behind--; //safe
		if (*behind == (CHAR) '\r') return(TRUE);
		return(FALSE);

	}

	if (FLAGS_ARE_SET(r->flags, PRL_NLISEOS))
	{
		if (*behind == (CHAR) '\n') return(TRUE);
	}
	return(FALSE);
}

static
mybool_t
match_eos_internal(register prl_t r)
{
	if (ATSTRINGEND) return(TRUE);

	if (FLAGS_ARE_SET(r->flags, PRL_CRNLISEOS))
	{
		if ((*(r->string_offset) == (CHAR) '\r') &&
		    (*(r->string_offset+1) == (CHAR) '\n')) // safe
		{
			return(TRUE);
		}
		return(FALSE);
	}

	if (FLAGS_ARE_SET(r->flags, PRL_NLISEOS))
	{
		if (*(r->string_offset) == (CHAR) '\n')
		{
			return(TRUE);
		}
	}

	return(FALSE);
}

static
mybool_t
match_eos(register prl_t r, register node_t node)
/*ARGSUSED*/
{
	// Again, not needed but adds clarity maybe
	return(match_eos_internal(r));
}


static
node_t
parse_dot(register prl_t r)
{
	register node_t	rval;

	if (*r->regex_offset != '.') INTERNAL_ERROR;
	r->regex_offset++;
	rval = new_node(r, N_DOT, match_dot, NULL);
	return(rval);
}

static
mybool_t
match_dot(register prl_t r, register node_t node)
/*ARGSUSED*/
{
	if (ATSTRINGEND) return(FALSE);
	if (FLAGS_ARE_SET(r->flags, PRL_DOTNOEOS))
	{
		if (match_eos_internal(r)) return(FALSE);
	}

	r->string_offset++;
	return(TRUE);
}

static
node_t
parse_repeat(prl_t r)
{
	register node_t		rval;
	int64_t			min_repeat; // address taken
	int64_t			max_repeat; // address taken
	register CHAR		c;
	register mybool_t	is_star;

	min_repeat = 0;
	max_repeat = INFINITY;

	c = *r->regex_offset;

	if (r->atom == NULL) error(r, "repeat follows emtpy regex", PRL_COMPILE_ERROR);

	if ((r->atom->type == N_REPEAT_GREEDY) ||
	    (r->atom->type == N_REPEAT_NON_GREEDY))
		error(r, "repeat follows repeat", PRL_COMPILE_ERROR);

	is_star = FALSE;
	if (c == (CHAR) '*')
	{
		min_repeat = 0;
		max_repeat = INFINITY;
		is_star = TRUE;

	}
	else if (c == (CHAR) '+')
	{
		min_repeat = 1;
		max_repeat = INFINITY;
	}
	else if (c == (CHAR) '?')
	{
		min_repeat = 0;
		max_repeat = 1;
	}
	else if (c == (CHAR) '{')
	{
		parse_paren(r, &min_repeat, &max_repeat);
	}

	if ((max_repeat < min_repeat) || (max_repeat == 0)) error(r, "illegal repeat range", PRL_COMPILE_ERROR);

	r->regex_offset++;
	c = *r->regex_offset;

	if (c == (CHAR) '?')
	{
		rval = new_node(r, N_REPEAT_NON_GREEDY, match_repeat_non_greedy, NULL);
		r->regex_offset++;
		c = *r->regex_offset;
	}
	else
	{
		rval = new_node(r, N_REPEAT_GREEDY, match_repeat_greedy, NULL);
		if (c == (CHAR) '+')
		{
			rval->repeat.possessive = TRUE;
			r->regex_offset++;
			c = *r->regex_offset;
		}
	}

	rval->repeat.min_repeat = min_repeat;
	rval->repeat.max_repeat = max_repeat;
	rval->repeat.tail = r->atom;
	r->atom = NULL;
	update_container(r, rval, rval->repeat.tail);

	if (is_star)
	{
		// help with optimization
		if ((rval->repeat.tail->type == N_DOT) && (rval->repeat.tail->next == NULL))
		{
			rval->type = N_DOTSTAR;
		}
	}

	return(rval);
}

static
mybool_t
match_repeat_greedy(register prl_t r, register node_t node)
{
	register mybool_t		rval;
	register int64_t		min;
	register int64_t		max;
	register int64_t		count;
	register const CHAR *		start;
	register const CHAR *		t;
	register int64_t		i;
	register gp_stack_t		offsets;
	register gp_stack_t		capture_arrays;
	jmp_buf				save_jmpbuf;

	offsets = NULL;
	capture_arrays = NULL;

	COPY_JMPBUF(save_jmpbuf, r->jmpbuf);

	if (setjmp(r->jmpbuf) != 0)
	{
		destroy_stack(r, offsets);
		destroy_stack(r, capture_arrays);
		COPY_JMPBUF(r->jmpbuf, save_jmpbuf);
		longjmp(r->jmpbuf, r->exit_status);
	}
	offsets = new_stack(r, sizeof(CHAR *));
	capture_arrays = new_stack(r, r->size_captures);
	start = r->string_offset;
	min = node->repeat.min_repeat;
	max = node->repeat.max_repeat;
	count = 0;

	for(;;)
	{
		if (count >= max) break;
		t = r->string_offset;
		push(offsets, (void *) &(r->string_offset));
		push(capture_arrays, (void *) r->captures);
		rval = match_regex(r, node->repeat.tail);
		r->done = FALSE;
		if ((!rval) || (t == r->string_offset))
		{
			(void) pop(offsets, (void *) &(r->string_offset));
			(void) pop(capture_arrays, (void *) r->captures);
			break;
		}

		count++;
	}

	if (count < min)
	{
		// we can never match
		r->string_offset = start;
		destroy_stack(r, offsets);
		destroy_stack(r, capture_arrays);
		COPY_JMPBUF(r->jmpbuf, save_jmpbuf);
		return(FALSE);
	}

	if (count == 0)
	{
		// try to get to the end
		rval = match_to_end(r, node);
		if (!rval) r->string_offset = start;
		destroy_stack(r, offsets);
		destroy_stack(r, capture_arrays);
		COPY_JMPBUF(r->jmpbuf, save_jmpbuf);
		return(rval);
	}


	if (FLAGS_ARE_SET(r->flags, PRL_ATOMIC) || node->repeat.possessive)
	{
		rval = TRUE;
		destroy_stack(r, offsets);
		destroy_stack(r, capture_arrays);
		COPY_JMPBUF(r->jmpbuf, save_jmpbuf);
		return(rval);
	}


	for(i=0;;i++)
	{
		rval = match_to_end(r, node);
		if (rval)
		{
			destroy_stack(r, offsets);
			destroy_stack(r, capture_arrays);
			COPY_JMPBUF(r->jmpbuf, save_jmpbuf);
			return(TRUE);
		}


		// safe, pop will return error
		(void) pop(offsets, (void *) &(r->string_offset));
		(void) pop(capture_arrays, (void *) r->captures);
		count--;
		if (count < min)
		{
			destroy_stack(r, offsets);
			destroy_stack(r, capture_arrays);
			r->string_offset = start;
			COPY_JMPBUF(r->jmpbuf, save_jmpbuf);
			return(FALSE);
		}
	}
	/*NOTREACHED*/
}

static
mybool_t
match_repeat_non_greedy(register prl_t r, register node_t node)
{
	register mybool_t	rval;
	register int64_t	min;
	register int64_t	max;
	register int64_t	count;
	register const CHAR *	start;

	start = r->string_offset;
	min = node->repeat.min_repeat;
	max = node->repeat.max_repeat;
	count = 0;

	for(;;)
	{
		if (count >= min) break;
		rval = match_regex(r, node->repeat.tail);
		if (!rval)
		{
			r->string_offset = start;
			return(FALSE);
		}
		count++;
	}

	for(;;)
	{
		if (match_to_end(r, node)) return(TRUE);
		if (count >= max) break;
		rval = match_regex(r, node->repeat.tail);
		if (!rval) break;
		count++;
	}

	r->string_offset = start;
	return(FALSE);
}

static
CHAR
simple_backslash(register prl_t r)
{
	register CHAR		rval;
	register CHAR		c;
	register int64_t	inc;

	inc = 1;
	c = *r->regex_offset;
	switch(c)
	{
		case (CHAR) '\\':
			rval = (CHAR) '\\';
			break;
		case (CHAR) 'e':
			rval = (CHAR) '\033';
			break;
		case (CHAR) 'n':
			rval = (CHAR) '\n';
			break;
		case (CHAR) 'r':
			rval = (CHAR) '\r';
			break;
		case (CHAR) 't':
			rval = (CHAR) '\t';
			break;
		case (CHAR) 'v':
			rval = (CHAR) '\v';
			break;
		case (CHAR) 'x':
			rval = hex(r);
			inc = 0;
			break;
		default:
			rval = c;
			break;
	}

	r->regex_offset += inc;
	return(rval);
}

static
node_t
parse_backslash(register prl_t r)
{
	register node_t		rval;
	register CHAR		c;
	register int8_t		ref;

/*
 *	Backslash is either a simple quote which matches a single
 *	character (hex is an exception), or a character class like a word
 *	or a backref (integer).
*/

	c = *r->regex_offset;
	if (c != '\\') INTERNAL_ERROR;

	r->regex_offset++;
	c = *r->regex_offset;
	if (CHARISNULL(c)) error(r, "backslash at end of regex", PRL_COMPILE_ERROR);
	rval = new_node(r, N_BACKSLASH, match_backslash, NULL);
	rval->backslash.backref = -1;

	if (isdigit(c))
	{
		/*LINTED*/
		ref = (int8_t) (c - '0');
		if ((ref < 0) || (ref >= r->num_subexpr))
			error(r, "backreference range error", PRL_COMPILE_ERROR);
		rval->backslash.backref = ref;
		r->regex_offset++;
		return(rval);
	}

	if (!ISCHARCLASSCHAR(r, c))
	{
		rval->backslash.simple = simple_backslash(r);
		return(rval);
	}

	if (isupper(c)) rval->backslash.negated = TRUE;
	if (ISNARROWCHARCLASS(r, c)) rval->backslash.narrow = TRUE;
	rval->backslash.charclass = lowercase(c);

	r->regex_offset++;
	return(rval);
}

static
mybool_t
start_of_word(register prl_t r)
{
	register CHAR	c;

	c = *r->string_offset;
	if (r->bos->match(r, r->bos)) return(wordchar(r, c));
	if (wordchar(r, c))
	{
		if (!wordchar(r, *(r->string_offset - 1))) return(TRUE);
		return(FALSE);
	}
	return(FALSE);
}


static
mybool_t
end_of_word(register prl_t r)
{
	register CHAR	c;

	c = *r->string_offset;
	if (r->eos->match(r, r->eos))
	{
		if (r->string_offset > r->string_base) return(wordchar(r, *(r->string_offset - 1)));
		return(FALSE);
	}

	if (!wordchar(r, c))
	{
		if (wordchar(r, *(r->string_offset - 1))) return(TRUE);
		return(FALSE);
	}

	return(FALSE);
}

static
mybool_t
word_boundary(register prl_t r)
{
	return(end_of_word(r) || start_of_word(r));
}

static
mybool_t
match_eol(register prl_t r)
{
	register CHAR	c;

	c = *r->string_offset;
	if (c == (CHAR) '\n')
	{
		r->string_offset++;
		return(TRUE);
	}
	if (c == (CHAR) '\r')
	{
		c = *(r->string_offset + 1);
		if (c != '\n') return(FALSE);
		r->string_offset += 2;
		return(TRUE);
	}

	return(FALSE);
}


static
mybool_t
match_backslash(register prl_t r, register node_t node)
{
	register mybool_t	rval;
	register CHAR		c;
	register mybool_t	advance;

	if ((!node->backslash.narrow) && ATSTRINGEND) return(FALSE);

	rval = FALSE;
	c = *r->string_offset;
	advance = TRUE;

	if (node->backslash.backref >= 0) return(match_capture(r, node->backslash.backref));

	if (!CHARISNULL(node->backslash.simple))
	{
		if (ICASE(r->flags))
		{
			if (tolower(c) != tolower(node->backslash.simple)) return(FALSE);
		}
		else
		{
			if (c != node->backslash.simple) return(FALSE);
		}

		r->string_offset++;
		return(TRUE);
	}

	switch(node->backslash.charclass)
	{
		case (CHAR) 'n': rval = match_eol(r); advance = FALSE; break;
		case (CHAR) 'l': rval = (mybool_t) islower((int) c); break;
		case (CHAR) 'u': rval = (mybool_t) isupper((int) c); break;
		case (CHAR) 'p': rval = (mybool_t) ispunct((int) c); break;
		case (CHAR) 'w': rval = wordchar(r, c); break;
		case (CHAR) 'z': rval = sane_wordchar(r, c); break;
		case (CHAR) 's': rval = (mybool_t) isspace((int) c); break;
		case (CHAR) 'd': rval = (mybool_t) isdigit((int) c); break;
		case (CHAR) 'h': rval = (mybool_t) isxdigit((int) c); break;
		case (CHAR) 'c': rval = (mybool_t) iscntrl((int) c); break;
		case (CHAR) 'a': rval = (mybool_t) isalpha((int) c); break;
		case (CHAR) 'o': rval = (mybool_t) isprint((int) c); break;
		case (CHAR) 'y': rval = (mybool_t) isblank((int) c); break;
		case (CHAR) 'g': rval =(mybool_t)  isgraph((int) c); break;
		case (CHAR) 'm': rval = (mybool_t) isalnum((int) c); break;
		case (CHAR) 'b': rval = word_boundary(r); advance = FALSE; break;
		case (CHAR) '<': rval = start_of_word(r); advance = FALSE; break;
		case (CHAR) '>': rval = end_of_word(r); advance = FALSE; break;

		default:	 INTERNAL_ERROR;
	}

	if (node->backslash.negated) rval = (mybool_t) !rval;
	if (advance && rval) r->string_offset++;
	return(rval);
}

static
node_t
parse_range(register prl_t r)
{
	register node_t		rval;

	rval = new_node(r, N_RANGE, match_range, NULL);
	rval->range.start = *r->regex_offset;
	r->regex_offset += 2;
	rval->range.end = *r->regex_offset;
	if (rval->range.start > rval->range.end)
		error(r, "invalid range", PRL_COMPILE_ERROR);
	r->regex_offset++;
	return(rval);
}

static
mybool_t
match_range(register prl_t r, register node_t node)
{
	register CHAR		c;
	register mybool_t	match;

	if (ATSTRINGEND) return(FALSE);
	c = *r->string_offset;
	if (ICASE(r->flags))
	{
		c = lowercase(c);
		match = ((c >= lowercase(node->range.start)) &&
			 (c <= lowercase(node->range.end)));
	}
	else
	{
		match = ((c >= node->range.start) && (c <= node->range.end));
	}

	if (!match) return(FALSE);
	r->string_offset++;
	return(TRUE);
}

static
mybool_t
match_subcharset(register prl_t r, register node_t node)
{
	if (ATSTRINGEND) return(FALSE);
	if (isin(r, node->subcharset.chars, *r->string_offset))
	{
		r->string_offset++;
		return(TRUE);
	}
	return(FALSE);
}

static
mybool_t
match_charset(register prl_t r, register node_t node)
{
	if (ATSTRINGEND) return(FALSE);

	node = node->charset.tail;
	while(node != NULL)
	{
		if (match_subcharset(r, node)) return(TRUE);
		node = node->next;
	}

	return(FALSE);
}

static
void
add_char_to_set(register prl_t r, register CHAR c, register node_t charset)
{
	register node_t		t;
	register node_t		subcharset;

	if (charset->charset.tail == NULL)
		charset->charset.tail = new_node(r, N_SUBCHARSET, match_subcharset, NULL);
	subcharset = charset->charset.tail;

	if (subcharset->subcharset.used >= (SUBCHARSET_LEN-1))
	{
		// grabs a new charset node, put it at the front
		t = new_node(r, N_SUBCHARSET, match_subcharset, NULL);
		t->next = subcharset;
		subcharset = t;
	}
	// stuff in the current charset
	subcharset->subcharset.chars[subcharset->subcharset.used] = c;
	subcharset->subcharset.used++;
	return;
}

static
node_t
parse_posix_class(register prl_t r)
{
	register struct posix_class_map_entry *	entry;
	register int64_t			i;
	register node_t				rval;
	register const CHAR *			save_offset;

	if ((*(r->regex_offset) != '[') || (*(r->regex_offset+1) != ':'))
		INTERNAL_ERROR;

	entry = NULL;
	for(i=0; i<sizeof(posix_class_map)/sizeof(struct posix_class_map_entry); i++)
	{
		entry = &(posix_class_map[i]);
		if (strncasecmp((const char *) entry->name, (const char *) r->regex_offset,
				/*LINTED*/
			        (size_t) entry->len) == 0)
					break;
		entry = NULL;
	}

	if (entry == NULL) error(r, "unknown character class name", PRL_COMPILE_ERROR);

	save_offset = r->regex_offset;
	r->regex_offset = entry->backslash;
	rval = parse_backslash(r);
	r->regex_offset = save_offset;
	if (isupper(*(r->regex_offset + 2))) rval->backslash.negated = TRUE;
	/*LINTED*/
	r->regex_offset += (int64_t) entry->len;
	return(rval);
}

static
node_t
parse_bracket(register prl_t r)
{
	register CHAR		c;
	register CHAR		ahead1;
	register CHAR		ahead2;
	register const CHAR *	p;
	register node_t		rval;
	register node_t		charsets;
	register node_t	*	current_node;
	register node_t		my_container;

	charsets = new_node(r, N_CHARSET, match_charset, NULL);

	c = *r->regex_offset;
	if (c != (CHAR) '[') INTERNAL_ERROR;

	r->regex_offset++;
	c = *r->regex_offset;
	p = r->regex_offset;

	rval = new_node(r, N_BRACKET, match_bracket, NULL);
	my_container = rval->container;
	r->container = rval;
	current_node = &rval->bracket.tail;

	if (c == (CHAR) '\\')
	{
		ahead1 = *(r->regex_offset+1);
		if (isdigit(ahead1)) error(r, "backreference not allowed in bracket expression", PRL_COMPILE_ERROR);
		*current_node = parse_backslash(r); // updates regex_offset
		if ((*current_node)->backslash.narrow)
		{
			r->regex_offset = p;
			error(r, "narrow literals are not allowed in bracket expressions", PRL_COMPILE_ERROR);
		}

		current_node = &((*current_node)->next);;
	}
	else
	{
		if (c == (CHAR) '^')
		{
			/*LINTED*/
			SET_FLAGS(rval->bracket.flags, PRL_NEGATED);
			r->regex_offset++;
			c = *r->regex_offset;
		}

		if ((c == (CHAR) '-') || (c == (CHAR) ']'))
		{
			add_char_to_set(r, c, charsets);
			r->regex_offset++;
		}
	}

	for(;;)
	{
		c = *r->regex_offset;
		p = r->regex_offset;
		if (CHARISNULL(c)) error(r, "missing closing bracket", PRL_COMPILE_ERROR);
		ahead1 = *(r->regex_offset+1);

		if ((c == '[') && (ahead1 == ':'))
		{
			*current_node = parse_posix_class(r); // updates regex offset
			current_node = &((*current_node)->next);;
			continue;
		}

		if (c == (CHAR) '\\')
		{
			if (isdigit(ahead1))
				error(r, "backreferences are not allowed in bracket expressions", PRL_COMPILE_ERROR);
			*current_node = parse_backslash(r); // updates regex_offset
			if ((*current_node)->backslash.narrow)
			{
				r->regex_offset = p;
				error(r, "narrow literals are not allowed in bracket expressions", PRL_COMPILE_ERROR);
			}

			current_node = &((*current_node)->next);;
			continue;
		}

		ahead2 = (CHAR) '\0';
		if (!CHARISNULL(ahead1)) ahead2 = *(r->regex_offset+2);

		if (ahead1 == (CHAR) '-')
		{
			// a few possibilities here
			if (c == ahead2) // range of 1 trumps all else
			{
				add_char_to_set(r, c, charsets);
				r->regex_offset += 3;
			}
			else if (ahead2 == (CHAR) ']')
			{
				add_char_to_set(r, c, charsets);
				add_char_to_set(r, ahead1, charsets);
				r->regex_offset += 3;
				break;
			}
			else // normal range
			{
				*current_node = parse_range(r);		// updates regex_offset
				current_node = &((*current_node)->next);;
			}
			continue;
		}

		if (c == (CHAR) ']')
		{
			r->regex_offset++;
			break;
		}

		add_char_to_set(r, c, charsets);
		r->regex_offset++;
	}

	*current_node = charsets;
	r->container = my_container;
	return(rval);
}

static
mybool_t
match_bracket(register prl_t r, register node_t node)
{
	register mybool_t	rval;
	register node_t		tmp;

	if (ATSTRINGEND) return(FALSE);
	tmp = node->bracket.tail;

	rval = FALSE;
	while (tmp != NULL)
	{
		rval = tmp->match(r, tmp);
		if (rval) break;
		tmp = tmp->next;
	}

	if (NEGATED(node->bracket.flags))
	{
		if (rval) r->string_offset--;
		else r->string_offset++;
		rval = (mybool_t) !rval;
	}

	return(rval);
}

static
node_t
parse_branch(register prl_t r)
{
	register node_t		rval;
	register node_t		my_container;

	r->regex_offset++;
	rval = new_node(r, N_BRANCH, match_branch, NULL);
	rval->branch.left = r->piece.start;
	r->piece.start = r->piece.end = NULL;
	update_container(r, rval, rval->branch.left);
	my_container = rval->container;
	r->container = rval;
	rval->branch.right = parse_regex(r);
	ZERO_PIECE(r);
	r->container = my_container;
	return(rval);
}

static
mybool_t
match_branch(register prl_t r, register node_t node)
{
	register const CHAR *	start;
	register const CHAR *	left_end_short;
	register const CHAR *	left_end_long;
	register const CHAR *	right_end_short;
	register const CHAR *	right_end_long;
	register mybool_t	left_match;
	register mybool_t	right_match;
	register mybool_t	left_done;
	register mybool_t	right_done;
	string_t *		left_captures;	// address taken
	string_t *		save_captures;	// address taken
	register int64_t	sizeof_captures;
	jmp_buf			save_jmpbuf;
	register mybool_t	rval;

	left_captures = save_captures = NULL;
	COPY_JMPBUF(save_jmpbuf, r->jmpbuf);
	if (setjmp(r->jmpbuf) != 0)
	{
		FREE(left_captures);
		FREE(save_captures);
		COPY_JMPBUF(r->jmpbuf, save_jmpbuf);
		longjmp(r->jmpbuf, r->exit_status);
	}

	left_captures = MALLOC(r->size_captures);
	save_captures = MALLOC(r->size_captures);

	left_done = right_done = FALSE;
	start = r->string_offset;
	left_end_short = left_end_long = start;
	right_end_short = right_end_long = start;
	/*LINTED*/
	sizeof_captures = r->num_subexpr * (int64_t) sizeof(string_t);

	safe_memmove((void *) save_captures, (const void *) r->captures, sizeof_captures);
	left_match = match_regex(r, node->branch.left);

	if (left_match)
	{
		if (FLAGS_ARE_SET(r->flags, PRL_ATOMIC)) FINALIZE(TRUE)
		left_end_short = r->string_offset;
		if (match_to_end(r, node)) left_end_long = r->string_offset;
		if (r->done && (r->string_offset > start)) FINALIZE(TRUE)
		left_done = r->done;
		r->done = FALSE;
		safe_memmove((void *) left_captures, (const void *) r->captures, sizeof_captures);
	}

	r->string_offset = start;
	safe_memmove((void *) r->captures, (const void *) save_captures, sizeof_captures);
	right_match = match_regex(r, node->branch.right);

	if (right_match)
	{
		if (FLAGS_ARE_SET(r->flags, PRL_ATOMIC)) FINALIZE(TRUE)
		right_end_short = r->string_offset;
		if (match_to_end(r, node)) right_end_long = r->string_offset;
		right_done = r->done;
		r->done = FALSE;
	}

	r->string_offset = start;

	if (left_match)
	{
		if (!right_match)
		{
			safe_memmove((void *) r->captures, (const void *) left_captures, sizeof_captures);
			r->string_offset = left_end_short;
			if (left_done)
			{
				r->done = TRUE;
				r->string_offset = left_end_long;
			}
			FINALIZE(TRUE)
		}

		if (left_done)
		{
			r->done = TRUE;
			if (!right_done || (left_end_long >= right_end_long))
			{
				safe_memmove((void *) r->captures, (const void *) left_captures, sizeof_captures);
				r->string_offset = left_end_long;
				FINALIZE(TRUE)
			}

			r->string_offset = right_end_long;
			FINALIZE(TRUE)
		}

		if (right_done)
		{
			r->done = TRUE;
			r->string_offset = right_end_long;
			FINALIZE(TRUE)
		}


		if (left_end_short >= right_end_short)
		{
			safe_memmove((void *) r->captures, (const void *) left_captures, sizeof_captures);
			r->string_offset = left_end_short;
			FINALIZE(TRUE)
		}

		r->string_offset = right_end_short;
		FINALIZE(TRUE)
	}

	if (right_match)
	{
		r->string_offset = right_end_short;
		FINALIZE(TRUE)
	}

	r->string_offset = start;
	safe_memmove((void *) r->captures, (const void *) save_captures, sizeof_captures);
	rval = FALSE;

finalize:
	FREE(left_captures);
	FREE(save_captures);
	COPY_JMPBUF(r->jmpbuf, save_jmpbuf);
	return(rval);
}

static
void
free_captures(register prl_t r)
{
	if (r->captures == NULL) return;
	FREE(r->captures);
	r->captures = NULL;
	return;
}

const
char *
prl_get_error(register prl_t r)
{
	if (r == NULL) return("internal error");
	check_prl(r);
	if (r->errmsg == NULL) r->errmsg = "no error";
	return(r->errmsg);
}

void
prl_free(prl_t r) // address taken
{
	if (r == NULL) return;
	check_prl(r);
	free_captures(r);
	FREE(r->regex_base);
	free_slablist(r, &(r->slablist));
	/*LINTED*/
	safe_memset(r, 0, (int64_t) sizeof(*r));
	FREE(r);
	return;
}

static
void
parse_paren(register prl_t r, register int64_t * min, register int64_t * max)
{
	register CHAR	c;

	c = *r->regex_offset;
	if (c != (CHAR) '{') INTERNAL_ERROR;
	r->regex_offset++;
	c = *r->regex_offset;

	*min = 0;
	*max = 0;

	while(isdigit(c))
	{
		*min = (*min * 10) + (c - (CHAR) '0');
		r->regex_offset++;
		c = *r->regex_offset;
	}

	if (c == (CHAR) '}')
	{
		*max = *min;
		return;
	}

	if (c != (CHAR) ',') error(r, "illegal repeat range", PRL_COMPILE_ERROR);

	r->regex_offset++;
	c = *r->regex_offset;

	if (c == (CHAR) '}')
	{
		*max = INFINITY;
		return;
	}

	if (!isdigit(c)) error(r, "illegal repeat range", PRL_COMPILE_ERROR);

	while(isdigit(c))
	{
		*max = (*max * 10) + (c - (CHAR) '0');
		r->regex_offset++;
		c = *r->regex_offset;
	}

	if (c != (CHAR) '}') error(r, "illegal repeat range", PRL_COMPILE_ERROR);
	if (*max < *min) error(r, "illegal repeat range", PRL_COMPILE_ERROR);
	return;
}

static
CHAR
hex(register prl_t r)
{
	register CHAR		rval;
	register int64_t	i;
	register CHAR		c;

	c = *r->regex_offset;
	if (c != (CHAR) 'x') INTERNAL_ERROR;
	r->regex_offset++;

	rval = 0;
	for(i=0;i<2;i++)
	{
		c = *r->regex_offset;
		if (CHARISNULL(c)) error(r, "bad hexadecimal number", PRL_COMPILE_ERROR);
		r->regex_offset++;
		c = lowercase(c);
		rval <<= 4;
		if (isdigit(c))
			/*LINTED*/
			rval |= (CHAR) (c - (CHAR) '0');
		else if (c >= 'a' && c <= 'f')
			/*LINTED*/
			rval |= (c - 'a' + 10);
		else
			error(r, "bad hexadecimal number", PRL_COMPILE_ERROR);
	}
	return(rval);
}

static
const
char *
nodename(register prl_t r, register node_t node)
{
	register int64_t	i;

	for(i=0;i<sizeof(names)/sizeof(struct nodenames);i++)
	{
		if (node->type == names[i].type) return(names[i].name);
	}
	INTERNAL_ERROR;
	/*NOTREACHED*/
	return(NULL); // stupid gcc
}

static
mybool_t
isin(register prl_t r, register CHAR * s, register CHAR c)
{
	if (CHARISNULL(c)) return(FALSE);

	if (ICASE(r->flags))
	{
		c = lowercase((int) c);
		for(;;)
		{
			if (CHARISNULL(*s)) return(FALSE);
			if (c == lowercase(*s)) return(TRUE);
			s++;
		}
	}
	else
	{
		for(;;)
		{
			if (CHARISNULL(*s)) return(FALSE);
			if (c == *s) return(TRUE);
			s++;
		}
	}

	/*NOTREACHED*/
}

static
CHAR *
stringtype_to_string(register string_t * capture)
{
	register CHAR *		rval;
	register int64_t	len;

	if (capture == NULL) return(NULL);
	len = capture->len;
	if (len < 0) len = 0;
	/*LINTED*/
	rval = malloc((size_t) len + 1);
	if (rval == NULL) out_of_memory();
	safe_memmove((void *) rval, (const void *) capture->start, len);
	rval[len] = (CHAR) '\0';
	return(rval);
}

static
string_t *
get_capture(register prl_t r, register int64_t i, register string_t * name)
{
	register string_t *	capture;
	register node_t		node;

	if (name != NULL)
	{
		node = find_named_node(r, name, 0, r->named_nodes);
		if (node == NULL) return(NULL);
		i = node->subexpr.capture_id;
	}

	if ((i < 0) || (i >= r->num_subexpr)) return(NULL);
	capture = &(r->captures[i]);

	return(capture);
}


static
char *
get_capture_name(register prl_t r, register int64_t i)
{
	register char *	rval;
	register node_t	node;

	node = find_named_node(r, NULL, i, r->named_nodes);
	if (node == NULL) return(NULL);
	/*LINTED*/
	rval = malloc((size_t) node->subexpr.name->len + 1);
	if (rval == NULL) out_of_memory();
	// strlcpy is not in posix
	/*LINTED*/
	safe_strncpy((CHAR *) rval, (CHAR *) node->subexpr.name->start, (int) node->subexpr.name->len);
	rval[node->subexpr.name->len] = '\0';
	return(rval);
}


CHAR *
prl_capture_string(register prl_t r, register int64_t i, register const char * name)
{
	string_t	str;

	check_prl(r);
	if (name != NULL)
	{
		/*LINTED*/
		str.start = (CHAR *) name;
		/*LINTED*/
		str.len = (int64_t) strlen(name);
		return(stringtype_to_string(get_capture(r, i, &str)));
	}
	return(stringtype_to_string(get_capture(r, i, NULL)));
}

void
prl_capture(register prl_t r, register int64_t i, register const char * name,
		register const unsigned char ** start,
		register int64_t * len)
{
	register string_t *	capture;
	string_t		str;

	check_prl(r);
	if ((start == NULL) || (len == NULL)) error(r, "bad arguments", PRL_USAGE_ERROR);
	*start = NULL;
	*len = 0;
	if (name == NULL)
	{
		capture = get_capture(r, i, NULL);
	}
	else
	{
		/*LINTED*/
		str.start = (CHAR *) name;
		/*LINTED*/
		str.len = (int64_t) strlen(name);
		capture = get_capture(r, i, &str);
	}

	if (capture == NULL) return;
	*start = capture->start;
	*len = capture->len;
	return;
}

int64_t
prl_capture_count(register prl_t r)
{
	check_prl(r);
	return(r->num_subexpr);
}

static
void
prc(register int64_t count, register char c)
{
	while(count > 0)
	{
		count--;
		(void) putchar(c);
	}
	return;
}

static
void
prl_compile_error(register prl_t r)
{
	register int64_t	offset;

	if (r->exit_status != PRL_COMPILE_ERROR)
	{
		(void) printf("No compile time error.\n");
		return;
	}

	(void) printf("Compile time error - error message: %s\n", r->errmsg);
	(void) printf("\nApproimate location of detected error is shown below.\n\n");
	(void) printf("Regex:             %s\n",r->regex_base);
	offset = pdiff(r->regex_base, r->regex_offset) + 1;
	(void) printf("Location of error:");
	prc(offset, ' ');
	(void) printf("^\n\n");
	return;
}

void
prl_status(register prl_t r)
{
	register int64_t	i;
	CHAR *			p; // address taken
	register char *		name;

	check_prl(r);
	(void) printf("\nPRL internal status\n\nRegex = \"%s\"\n", (char *) r->regex_base);
	if (r->string_base != NULL) (void) printf("String = \"%s\"\n", (char *) r->string_base);
	if (r->exit_status != PRL_OK)
	{
		if (r->exit_status == PRL_COMPILE_ERROR)
		{
			prl_compile_error(r);
		}
		else
		{
			(void) printf("Exit status: %lld\n", (long long) r->exit_status);
			if (r->errmsg != NULL)(void) printf("Errmsg = \"%s\"\n", (char *) r->errmsg);
		}
	}
	else
	{
		(void) printf("No errors detected.\n");
	}


	if (!r->used) return;
	(void) printf("Match result = %s\n",
		      r->exit_status == PRL_MATCH ? "True" : "False");
	(void) printf("Captures = %lld\n", (long long) r->num_subexpr);
	for(i=0; i<r->num_subexpr;i++)
	{
		name = get_capture_name(r, i);
		p = prl_capture_string(r, i, NULL);
		(void) printf("\tCapture %lld(%s): \"%s\"\n",
			      (long long) i, (name == NULL) ? "" : name,
			      (p == NULL) ? "NULL" : (char *) p);
		(void) free(p); // prl_capture_string uses real malloc
		if (name != NULL) free(name);
	}


	(void) printf("\n");
	return;
}

static
void
zero_captures(register prl_t r)
{
	if (r->captures != NULL) safe_memset(r->captures, 0, r->size_captures);
	return;
}

static
void
zero(register prl_t r)
{
	zero_captures(r);
	r->string_base = NULL;
	r->string_offset = NULL;
	r->atom = NULL;
	ZERO_PIECE(r);
	r->flags = 0;
	r->passed_flags = 0;
	r->parse_depth = 0;
	r->exit_status = 0;
	r->used = TRUE;
	r->recursion_depth = 0;
	return;
}

static
mybool_t
isrepeatchar(register prl_t r, register CHAR c, register CHAR ahead1)
{
	if (isin(r, REPEATCHARS, c)) return(TRUE);
	if ((c == (CHAR) '{') && (isdigit(ahead1))) return(TRUE);
	return(FALSE);
}

static
mybool_t
match_to_end(register prl_t r, register node_t node)
{
	register const CHAR *	start;
	register mybool_t	rval;

	if (node == NULL) INTERNAL_ERROR;
	rval = FALSE;
	start = r->string_offset;

	for(;;)
	{
		if (node->type == N_SUBEXPR)
		{
			if (NARROW(node->subexpr.flags) || DEADEND(node->subexpr.flags))
			{
				r->done = TRUE;
				return(TRUE);
			}
		}

		if (node->next != NULL)
		{
			if (node->type == N_SUBEXPR) end_capture(r, node, r->string_offset);
			rval = match_regex(r, node->next);
			if (r->done) return(TRUE);

			if (!rval)
			{
				if (node->type == N_SUBEXPR) zero_capture(r, node);
				break;
			}
		}

		if (node->id == 0)
		{
			end_capture(r, node, r->string_offset);
			node = NULL;
		}
		else
		{
			node = node->container;
		}

		if (node == NULL)
		{
			rval = TRUE;
			break;
		}
	}

	if (!rval) r->string_offset = start;
	else r->done = TRUE;
	return(rval);
}


static
gp_stack_t
new_stack(register prl_t r, register int64_t item_size) /*ARGSUSED*/
{
	gp_stack_t	rval;

	rval = MALLOC(sizeof(*rval));
	rval->item_size = item_size;
	rval->max_items = 0;
	rval->num_items = 0;
	rval->items = NULL;
	rval->bytes = 0;
	return(rval);
}


static
void
destroy_stack(register prl_t r, gp_stack_t stack) /*ARGSUSED*/
{
	if (stack == NULL) return;
	FREE(stack->items);
	FREE(stack);
	return;
}

static
void
push(register gp_stack_t stack, register void * item)
{
	void *			old_items;
	register int64_t	old_bytes;
	register CHAR *		loc;

	if (stack->num_items >= stack->max_items)
	{
		old_bytes = stack->bytes;
		stack->max_items += STACK_INC;
		stack->bytes = stack->max_items * stack->item_size;
		old_items = stack->items;
		stack->items = MALLOC(stack->bytes);
		// safe, NULL checked in safe_memmove
		safe_memmove((CHAR *) stack->items, (CHAR *) old_items, old_bytes);
		// safe, NULL checked in FREE
		FREE(old_items);
	}

	loc = stack->items + (stack->num_items * stack->item_size);
	safe_memmove((void *) loc, (void *) item, stack->item_size);
	stack->num_items++;
	return;
}

static
mybool_t
pop(register gp_stack_t stack, register void * item)
{
	register CHAR *	loc;

	if (stack->num_items <= 0) return(FALSE);
	stack->num_items--;
	loc = stack->items + (stack->num_items * stack->item_size);
	safe_memmove((CHAR *) item, (CHAR *) loc, stack->item_size);
	return(TRUE);
}


static
void
update_container(register prl_t r, register node_t container, register node_t node) /*ARGSUSED*/
{
	while (node != NULL)
	{
		node->container = container;
		node = node->next;
	}
	return;
}

static
void
append_piece(register prl_t r, register node_t node)
{
	if (r->piece.start == NULL)
	{
		r->piece.start = r->piece.end = node;
	}
	else
	{
		r->piece.end->next = node;
		r->piece.end = node;
	}
	return;
}

static
void
prstr(register char * preamble, register string_t * str, register char * postscript)
{
	register const CHAR *	p;
	register int64_t	len;

	if (preamble != NULL) (void) printf("%s", preamble);
	p = str->start;
	len = str->len;
	while(len-- > 0) (void) fputc((int) *p++, stdout);
	if (postscript != NULL) (void) printf("%s", postscript);
	return;
}

static
mybool_t
cmp_string(register string_t * s1, register string_t * s2, register mybool_t icase)
{
	register const CHAR *	p1;
	register const CHAR *	p2;
	register CHAR		c1;
	register CHAR		c2;
	register int64_t	len;

	if (s1->len != s2->len) return(FALSE);
	p1 = s1->start;
	p2 = s2->start;
	len = s1->len;
	while(len > 0)
	{
		c1 = *p1; p1++;
		c2 = *p2; p2++;
		len--;

		if (icase)
		{
			c1 = lowercase(c1);
			c2 = lowercase(c2);
		}

		if (c1 != c2) return(FALSE);
		if (CHARISNULL(c1)) return(TRUE);

	}

	return(TRUE);
}

static
CHAR
lowercase(register CHAR c)
{
	if ((c >= (CHAR) 'A') && (c <= (CHAR) 'Z'))
		/*LINTED*/
		return((CHAR) (c - (CHAR) 'A' + (CHAR) 'a'));
	return(c);
}

static
void
prl_print_node_list(register prl_t r, register char * msg, register node_t node)
{
	register node_t		t;

	check_prl(r);
top:
	if (node == NULL)
	{
		(void) printf("\n");
		return;
	}



	(void) printf("\nStart Node List: %s\n", msg == NULL ? "" : (char *) msg);
	(void) printf("\nNode: %lld, Type: %s, Container: %lld\n", (long long) node->id,
		      nodename(r, node),
		      (long long) (node->container == NULL ? 0 : node->container->id));
	if (node->next != NULL) (void) printf("Next Node: %lld\n", (long long) node->next->id);
	else (void) printf("Next Node: NULL\n");
	switch(node->type)
	{
		case N_NOOP:		break;

		case N_BACKSLASH:	(void) printf("Backslash: simple: \"%c\", character class: \"%c\", backref: %lld, narrow: %s\n",
						      /*LINTED*/
						      (char) node->backslash.simple,
						      /*LINTED*/
						      (char) node->backslash.charclass,
						      (long long) node->backslash.backref,
						      node->backslash.narrow ? "True" : "False");
					break;

		case N_STRING:		prstr("String: string \"", &node->string, "\"\n");
					break;

		case N_SUBEXPR:		(void) printf("Subexpr Node: %lld, Narrow: %s, Negated: %s, "
						      "Flags: %lld, Capture_id: %lld\n",
						      (long long) node->subexpr.tail->id,
						      NARROW(node->subexpr.flags) ? "True" : "False",
						      NEGATED(node->subexpr.flags) ? "True" : "False",
						      (long long) node->subexpr.flags,
						      (long long) node->subexpr.capture_id);

					if (node->subexpr.backref != NULL)
						(void) printf("Backreference node: %lld\n",
							      (long long) node->subexpr.backref->id);

					(void) printf("Subexpression name: ");
					if (node->subexpr.name == NULL) (void) printf("None");
					else prstr(NULL, node->subexpr.name, "\n");
					if (node->subexpr.tail != NULL)
						(void) printf("Tail head: %lld\n", (long long) node->subexpr.tail->id);
					else
						(void) printf("Tail head: None\n");
					prl_print_node_list(r, "Subexpression list", node->subexpr.tail);
					break;

		case N_DOT:		break;

		case N_RANGE:		(void) printf("Range: %c - %c (%d - %d)\n",
						      /*LINTED*/
						      (char) (isprint(node->range.start) ? node->range.start : (CHAR) '?'),
						      /*LINTED*/
						      (char) (isprint(node->range.end) ? node->range.end : (CHAR) '?'),
						      (int) node->range.start, (int) node->range.end);
					break;

		case N_CHARSET:		(void) printf("Charset: ");
					for(t = node->charset.tail; t != NULL; t = t->next)
					{
						(void) printf("\tSubcharset: %s", t->subcharset.chars);
					}
					(void) printf("\n");
					break;

		case N_BRACKET:		(void) printf("Tail: %lld, Negated: %s\n",
						      (long long) (node->bracket.tail == NULL ?
								   -1 : node->bracket.tail->id),
						      NEGATED(node->bracket.flags) ? "True" : "False");
					prl_print_node_list(r, "Bracket tail list", node->bracket.tail);
					(void) printf("\n");
					break;

		case N_BRANCH:		(void) printf("Left: %lld, Right %lld\n",
						      (long long) (node->branch.left != NULL ? node->branch.left->id : -1),
						      (long long) (node->branch.right != NULL ? node->branch.right->id : -1));
					prl_print_node_list(r, "Branch List Left", node->branch.left);
					prl_print_node_list(r, "Branch List Right", node->branch.right);
					break;

		case N_REPEAT_GREEDY:
		case N_DOTSTAR:
		case N_REPEAT_NON_GREEDY:
					(void) printf("Min: %lld, Max: %lld, Tail: %lld\n",
						      (long long) node->repeat.min_repeat,
						      (long long) node->repeat.max_repeat,
						      (long long) node->repeat.tail->id);
					prl_print_node_list(r, "Repeat List", node->repeat.tail);
					break;

		case N_BOS:
		case N_EOS:		break;

		default:		/*LINTED*/
					(void) fprintf(stderr, "Unknown node type %lld\n", (long long) node->type);
					INTERNAL_ERROR;
	}

	node = node->next;
	goto top; // yeah I know
	/*NOTREACHED*/
}

void
prl_set_parameter(register prl_t r, register int64_t parameter, register int64_t value)
{
	check_prl(r);

	switch(parameter)
	{
		case PRL_MAX_RECURSION_DEPTH:	if (value < MINIMUM_RECURSION_DEPTH)
							value = MINIMUM_RECURSION_DEPTH;
						r->max_recursion_depth = value;
						break;
		case PRL_MAX_LOOKBEHIND:	if (value < MINIMUM_LOOKBEHIND)
							value = MINIMUM_LOOKBEHIND;
						r->max_lookbehind = value;
						break;
		default:			(void) fprintf(stderr, "WARNING: unknown parameter.\n");
						break;
	}

	return;
}

static
void
safe_memmove(register void * dst, register const void * src, register int64_t len)
{
	if ((len == 0) || (src == NULL) || (dst == NULL)) return;
	/*LINTED*/
	(void) memmove(dst, src, (size_t) len); // safe
	return;
}

static
void
safe_memset(register void * dst, register int c, register int64_t len)
{
	if ((len == 0) || (dst == NULL)) return;
	/*LINTED*/
	(void) memset(dst, c, (size_t) len); // safe
	return;
}



static
void
safe_strncpy(register void * dst, register const void * src, register int64_t len)
{
	if ((len == 0) || (src == NULL) || (dst == NULL)) return;
	/*LINTED*/
	(void) strncpy(dst, src, (size_t) len); // safe
	return;
}

static
void
out_of_memory(void)
{
	(void) fprintf(stderr, "Out of memory.\n");
	exit(1);
}
