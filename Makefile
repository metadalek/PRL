
# The default is 64 bit. Comment this out to
# compile 32 bit or if your compiler does not
# support this flag. PRL is designed to work best
# on 64 bit machines but will work 32 bit.

M64 = -m64

# If you OS does not support getrlimit(2) or you simply
# do not want it comment this out. If present, PRL tries to detect
# small stack sizes and limit recursion appropriately.

RLIMIT = -DHAVE_RLIMIT

# Optimize

OPT = -O

# If you compiler supports this flag, print all warnings.
# NOTE: THERE SHOULD NOT BE ANY.

#WARN = -Wall

# Compiler

CC = cc


#################################################################################################
# Should be no need to modify below here
#################################################################################################

CFLAGS = $(RLIMIT) $(OPT) $(M64) $(WARN)
LDFLAGS = $(M64)


all: clean prl.o try test prl_grep txt

txt:
	@if test -x /usr/bin/nroff; then echo 'nroff prl.3 > prl.3.txt'; nroff -man prl.3 > prl.3.txt; fi

prl.o:	prl.c
	$(CC) $(CFLAGS) -c -o prl.o prl.c

try:	prl.o try.o
	$(CC) $(M64) -o try try.o  prl.o
	strip try

test:	try
	@echo "Running test script."
	@chmod 755 ./test.sh
	@./test.sh

clean:
	rm -f *.o try prl_grep

prl_grep:	prl_grep.c
		cc $(M64) -o prl_grep prl_grep.c prl.o
		strip prl_grep
