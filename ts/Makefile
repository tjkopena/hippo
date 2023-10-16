SOURCEDIR = src
BUILDDIR = build

SOURCES := $(shell find $(SOURCEDIR) -regex '.*\.tsx?')
TARGETS = $(patsubst $(SOURCEDIR)%.ts,$(BUILDDIR)%.js,$(patsubst %.tsx,%.ts,$(SOURCES)))

$(info SOURCES=$(SOURCES))

all: build hippo.bundle.js hippo.bundle.d.ts

build: $(TARGETS)

$(TARGETS) &: $(SOURCES)
	tsc

hippo.bundle.js hippo.bundle.d.ts @: $(SOURCES)
	rollup -c
	sed -i 's/declare //' hippo.bundle.d.ts
	sed -i '1ideclare module "hippo" {' hippo.bundle.d.ts
	sed -i '$$a}' hippo.bundle.d.ts

.PHONY: all build
