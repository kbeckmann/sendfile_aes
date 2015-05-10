.PHONY: all

all: setup verify bench

setup: clean
	@$(BASH) ./setup.sh

verify:
	@$(BASH) ./verify.sh

bench:
	@$(BASH) ./bench.sh

clean:
	@$(BASH) ./clean.sh
