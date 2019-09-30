

PRL is a relatively small, relatively simple, portable regex matching library
written in stardard C. It requires no libraries other than the standard C library
to work.

It is not fully compatible with POSIX regex standards but does
implement pretty much all the useful bits and quite a few
extensions found in very complete regex libraries such as PCRE.

In size and feature set tradeoffs it sits somewhere between a tiny regex library
like SLRE, and a fully featured but much larger and more complex library
such as PCRE.

PRL is primarily designed to work in embedded applications.

Some interesting/unusual features of PRL are:

- there are no practical restrictions on the size or
	number of anything until you run out of
	virtual memory.

- all subexpressions create a capture. No exceptions.
	The number of captures in the regex is
	therefore the number of unquoted "("
	characters.

- there are no regex compile time flags. Any flags are passed in
	at the time the regex is matched. For example, you do not have
	to decide if you are doing case invarient matching
	before the regex is compiled.

If you find this code useful or even if not, or you find a bug
or want to make a comment, email me.

Tested on solaris 11 and linux.

Peter D. Gray
metadalek@gmail.com
