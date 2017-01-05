all:
	rm -rf dist sphincs.js sodiumutil js-sha512 promise-polyfill 2> /dev/null
	mkdir dist

	git clone https://github.com/cyph/sphincs.js.git

	git clone https://github.com/cyph/sodiumutil.git

	git clone https://github.com/emn178/js-sha512.git
	git clone https://github.com/taylorhakes/promise-polyfill.git
	for f in js-sha512/build/sha512.min.js promise-polyfill/promise.min.js ; do sed -i 's|typeof module|"undefined"|' $$f ; done

	cp pre.js dist/supersphincs.debug.js
	echo >> dist/supersphincs.debug.js
	echo 'BALLS();' >> dist/supersphincs.debug.js
	echo >> dist/supersphincs.debug.js
	cat js-sha512/build/sha512.min.js >> dist/supersphincs.debug.js
	echo >> dist/supersphincs.debug.js
	cat promise-polyfill/promise.min.js >> dist/supersphincs.debug.js
	echo >> dist/supersphincs.debug.js
	cat sodiumutil/dist/sodiumutil.js | perl -pe 's/if\(typeof module!=="undefined".*//g' >> dist/supersphincs.debug.js
	echo >> dist/supersphincs.debug.js
	cat post.js >> dist/supersphincs.debug.js

	uglifyjs dist/supersphincs.debug.js -o dist/supersphincs.js

	node -e " \
		var fs = require('fs'); \
		for (var file of ['dist/supersphincs.js', 'dist/supersphincs.debug.js']) { \
			fs.writeFileSync( \
				file, \
				fs.readFileSync(file). \
					toString(). \
					replace( \
						'BALLS()', \
						fs.readFileSync( \
							'sphincs.js/' + file.replace('super', '') \
						).toString().trim() \
					) \
			); \
		}; \
	"

	sed -i 's|require(|eval("require")(|g' dist/supersphincs.js

	rm -rf sphincs.js sodiumutil js-sha512 promise-polyfill

clean:
	rm -rf dist sphincs.js sodiumutil js-sha512 promise-polyfill
