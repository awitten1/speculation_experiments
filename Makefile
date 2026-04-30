.PHONY: all clean spectre-rsb spectre_v1 spectre_v2

all: spectre-rsb spectre_v1 spectre_v2

spectre-rsb:
	$(MAKE) -C spectre-rsb

spectre_v1:
	$(MAKE) -C spectre_v1

spectre_v2:
	$(MAKE) -C spectre_v2

clean:
	$(MAKE) -C spectre-rsb clean
	$(MAKE) -C spectre_v1 clean
	$(MAKE) -C spectre_v2 clean
