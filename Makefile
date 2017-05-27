all:
	rm -rf dist node_modules 2> /dev/null
	mkdir dist node_modules

	npm install

	cp supersphincs.js dist/supersphincs.module.js
	webpack --output-library-target var --output-library superSphincs supersphincs.js dist/supersphincs.js
	uglifyjs dist/supersphincs.js -o dist/supersphincs.js

	rm -rf node_modules

clean:
	rm -rf dist node_modules
