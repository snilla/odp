include ../Makefile.inc

test_PROGRAMS = comp_main$(EXEEXT)

comp_main_SOURCES = comp_main.c \
		      comp.c \
		      comp.h \
		      odp_comp_test.c \
		      odp_comp_test.h \
			 comp_ofs_test.c \
		      test_vectors.h 

comp_main_LDADD = $(LIBCUNIT_COMMON) $(LIBODP)
