include ../Makefile.inc

noinst_LTLIBRARIES = libtestcomp.la
libtestcomp_la_SOURCES = comp.c \
			 odp_comp_test_inp.c \
			 comp_ofs_test.c

test_PROGRAMS = comp_main$(EXEEXT)
dist_comp_main_SOURCES = comp_main.c
comp_main_LDADD = libtestcomp.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = comp.h odp_comp_test_inp.h test_vectors.h
