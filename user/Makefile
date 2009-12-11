include Rules.mk

SUBDIRS-y := utils
SUBDIRS-y += scripts
SUBDIRS-y += udev

.PHONY: all clean install
all clean install: %: subdirs-%
