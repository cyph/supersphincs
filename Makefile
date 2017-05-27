all:
	rm -rf dist node_modules 2> /dev/null
	mkdir dist node_modules

	npm install

	cp supersphincs.js dist/
	webpack --output-library-target var --output-library superSphincs supersphincs.js dist/supersphincs.global.js
	uglifyjs dist/supersphincs.global.js -o dist/supersphincs.global.js

	rm -rf node_modules

clean:
	rm -rf dist node_modules
