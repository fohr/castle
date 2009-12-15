UDEV_RULES  = udev-watch
SBIN_SCRIPTS = create-dm.sh remove-all-dms.sh

.PHONY: all
all:

.PHONY: build
build:

.PHONY: install
install: $(UDEV_RULES) $()
	mkdir -p /etc/castle
	set -e; for rule in $(UDEV_RULES); do \
		install $$rule /etc/castle; \
	done
	set -e; for script in $(SBIN_SCRIPTS); do \
		install $$script /usr/sbin; \
	done

.PHONY: clean
clean:
