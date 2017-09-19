include ../Makefile.inc

noinst_LTLIBRARIES = libtestcomp.la
libtestcomp_la_SOURCES = comp.c \
			 odp_comp_test.c \
			 comp_ofs_test.c

test_PROGRAMS = comp_main$(EXEEXT) comp_demo$(EXEEXT)
dist_comp_main_SOURCES = comp_main.c
comp_main_LDADD = libtestcomp.la $(LIBCUNIT_COMMON) $(LIBODP)
dist_comp_demo_SOURCES = odp_comp_demo.c

EXTRA_DIST = comp.h odp_comp_test.h test_vectors.h
