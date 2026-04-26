.PHONY: all clean spectre-rsb spectre_v2

all: spectre-rsb spectre_v2

spectre-rsb:
	$(MAKE) -C spectre-rsb

spectre_v2:
	$(MAKE) -C spectre_v2

clean:
	$(MAKE) -C spectre-rsb clean
	$(MAKE) -C spectre_v2 clean
