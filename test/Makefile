.PHONY: all setup verify bench clean
CORES=12

all: clean verify

setup:
	@$(BASH) ./setup.sh

verify: setup
	@echo Starting verification
	$(MAKE) -s -j$(CORES) -f Makefile.verify

bench:
	$(MAKE) -s -f Makefile.bench

clean:
	@$(BASH) ./clean.sh
