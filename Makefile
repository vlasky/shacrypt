all: build

node_modules: package.json
	npm install

build: node_modules
	npm run build

lint: node_modules
	npm run lint

test: build
	node --test test/tests.js test/esm.mjs

clean:
	rm -rf build prebuilds

distclean: clean
	rm -rf node_modules

.PHONY: all build lint test clean distclean
