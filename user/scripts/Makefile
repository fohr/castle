SCRIPTS  = udev-watch

.PHONY: all
all:

.PHONY: build
build:

.PHONY: install
install: $(SCRIPTS)
	mkdir -p /etc/castle
	set -e; for rule in $(SCRIPTS); do \
		install $$rule /etc/castle; \
	done

.PHONY: clean
clean:
