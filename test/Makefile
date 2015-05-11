.PHONY: all setup verify bench clean
CORES=12

all: clean setup verify

setup:
	@$(BASH) ./setup.sh

verify:
	@echo Starting verification
	$(MAKE) -s -j$(CORES) -f Makefile.verify

bench:
	$(MAKE) -s -f Makefile.bench

clean:
	@$(BASH) ./clean.sh
