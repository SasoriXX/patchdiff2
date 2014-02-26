# Usage: make IDASDK=/path/to/IDA/sdk
NAME = patchdiff2

# TODO: Make it build 32 and 64-bit binaries
# TODO: Fix compilation of both libraries on one command

# By default assume we're not compiling on Windows with Makefiles
SOURCES = $(filter-out win_fct.cpp,$(notdir $(wildcard *.cpp *.cc *.c)))

COMMON_FLAGS = -D__IDP__ -D__PLUGIN__ -D__MAC__ "-I$(IDAINC)" -arch i386 $(EA64)
CFLAGS = $(COMMON_FLAGS)
CXXFLAGS = $(COMMON_FLAGS) -std=c++11
# It had --shared, --no-undefined and -Wl
LDFLAGS = "-L$(IDALIB)" -l$(LIBIDA) -arch i386 -dynamiclib
LD = $(CXX)

IDASDK ?= $(HOME)/Software/ida/sdk+utilities/idasdk65
IDAINC  = $(IDASDK)/include
IDAAPP ?= /Applications/IDA Pro 6.5/idaq.app
IDALIB  = $(IDAAPP)/Contents/MacOS
IDAPLUGINS = $(IDALIB)/plugins

BaseNameSources := $(sort $(basename $(SOURCES)))
Objects32  := $(BaseNameSources:%=%.32.o)
Objects64  := $(BaseNameSources:%=%.64.o)

.PHONY: all install uninstall clean

OUTPUTS = $(NAME).pmc $(NAME).pmc64
all: $(OUTPUTS)

$(NAME).pmc: LIBIDA=ida
$(NAME).pmc: $(Objects32)
	$(LD) $(LDFLAGS) -o $@ $+

$(NAME).pmc64: EA64=-D__EA64__
$(NAME).pmc64: LIBIDA=ida64
$(NAME).pmc64: $(Objects64)
	$(LD) $(LDFLAGS) -o $@ $+

%.32.o %.64.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $^

install: $(OUTPUTS)
	cp $(OUTPUTS) "$(IDAPLUGINS)"

uninstall:
	rm "$(IDAPLUGINS)/$(OUTPUTS)"

clean:
	rm -f $(Objects32) $(Objects64) $(OUTPUTS)

# Debug targets, to print the vars
debug_%:
	@echo $($*)
