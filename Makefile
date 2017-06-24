all:
	rm -rf dist node_modules 2> /dev/null
	mkdir dist node_modules

	npm install

	webpack --output-library-target var --output-library superSphincs supersphincs.js dist/supersphincs.js
	echo " \
		if (typeof module !== 'undefined' && module.exports) { \
			module.exports		= superSphincs; \
		} \
		else { \
			self.superSphincs	= superSphincs; \
		} \
	" >> dist/supersphincs.js
	uglifyjs dist/supersphincs.js -cmo dist/supersphincs.js

	rm -rf node_modules

clean:
	rm -rf dist node_modules
