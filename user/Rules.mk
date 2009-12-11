subdirs-all subdirs-clean subdirs-install:
	@set -e; for subdir in $(SUBDIRS) $(SUBDIRS-y); do \
		$(MAKE) subdir-$(patsubst subdirs-%,%,$@)-$$subdir; \
	done

subdir-all-% subdir-clean-% subdir-install-%:
	$(MAKE) -C $* $(patsubst subdir-%-$*,%,$@)
