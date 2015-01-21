.PHONY: lint

SRCS := $(wildcard *.py)
SRCS := $(SRCS) $(wildcard ../*.py)

lint:
	pylint --rcfile pylintrc -E $(SRCS)

