VSN          := 0.1
ERL          ?= erl
EBIN_DIRS    := $(wildcard lib/*/ebin)
APP          := enet
OS	     := $(shell uname -s)

ifeq (Darwin, $(OS))
	CC           ?= /Developer/usr/llvm-gcc-4.2/bin/llvm-gcc-4.2
	CFLAGS       ?= -march=core2 -mmmx -msse3 -w -pipe -mmacosx-version-min=10.6 -I /Users/nem/usr/include
	LDFLAGS      ?= -L/Users/nem/usr/lib
endif

TAP_DRIVER := priv/bin/enet_tap

all: erl $(TAP_DRIVER)

erl: ebin lib
	@$(ERL) -pa $(EBIN_DIRS) -pa ebin -noinput +B \
	  -eval 'case make:all() of up_to_date -> halt(0); error -> halt(1) end.'

docs:
	@erl -noshell -run edoc_run application '$(APP)' '"."' '[]'

clean: 
	@echo "removing:"
	@rm -fv ebin/*.beam

ebin:
	@mkdir ebin

lib:
	@mkdir lib

dialyzer: erl
	@dialyzer -c ebin



priv/bin:
	@mkdir -p priv/bin
$(TAP_DRIVER): priv/bin

$(TAP_DRIVER): c_src/enet_tap.c
	$(CC) $(CFLAGS) $(LDFLAGS) -Wall $< -levent -o $@
