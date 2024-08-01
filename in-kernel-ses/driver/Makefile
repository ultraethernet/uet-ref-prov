
SUBDIRS = uet_core uet_crypto uet_nic uet_utils

all:
	for dir in $(SUBDIRS) ; do \
		make -C $$dir all ; \
	done

clean:
	for dir in $(SUBDIRS) ; do \
		make -C $$dir clean ; \
	done

