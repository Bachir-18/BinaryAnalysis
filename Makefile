# to edit
SRC_FILES := isos_inject.c
vpath %.c ./src
build_dependencies: $(SRC_FILES:.c=.dep)
	@cat $^ > make.test
	@rm $^

%.dep: %.c
	@gcc -MM -MF $@ $<
# New target to run the Makefile in the src directory
src:
	$(MAKE) -C src all

# New clean target to clean the src directory
clean:
	$(MAKE) -C src clean

.PHONY: src clean

