UDEV_RULES = castle.rules

.PHONY: all
all:

.PHONY: build
build:

.PHONY: install
install: $(UDEV_RULES)
	set -e; for rule in $(UDEV_RULES); do \
		install $$rule /etc/udev/rules.d; \
	done

.PHONY: clean
clean:
