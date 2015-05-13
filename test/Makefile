.PHONY: all setup verify bench clean
CORES=$(shell grep -c ^processor /proc/cpuinfo)

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
	@echo Cleaned test
