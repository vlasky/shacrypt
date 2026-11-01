all: build

node_modules: package.json
	npm install

build: node_modules
	npm run build

test: build
	node --test test/tests.js test/esm.mjs

clean:
	rm -rf build prebuilds

distclean: clean
	rm -rf node_modules

.PHONY: all build test clean distclean
