all:
	rm -rf dist sphincs.js codecs.js js-sha512 promise-polyfill 2> /dev/null
	mkdir dist

	git clone git@github.com:cyph/sphincs.js.git

	curl -s https://raw.githubusercontent.com/jedisct1/libsodium.js/9a8b4f9/wrapper/wrap-template.js | \
		tr '\n' '☁' | perl -pe 's/.*Codecs(.*?)Memory management.*/\1/g' | tr '☁' '\n' > codecs.js

	git clone https://github.com/emn178/js-sha512.git
	git clone https://github.com/taylorhakes/promise-polyfill.git
	for f in js-sha512/build/sha512.min.js promise-polyfill/promise.min.js ; do sed -i 's|typeof module|"undefined"|' $$f ; done

	cp pre.js dist/supersphincs.debug.js
	echo 'BALLS();' >> dist/supersphincs.debug.js
	cat js-sha512/build/sha512.min.js >> dist/supersphincs.debug.js
	cat promise-polyfill/promise.min.js>> dist/supersphincs.debug.js
	cat codecs.js >> dist/supersphincs.debug.js
	cat post.js >> dist/supersphincs.debug.js

	uglifyjs dist/supersphincs.debug.js > dist/supersphincs.js

	node -e ' \
		var fs = require("fs"); \
		for (var file of ["dist/supersphincs.js", "dist/supersphincs.debug.js"]) { \
			fs.writeFileSync( \
				file, \
				fs.readFileSync(file). \
					toString(). \
					replace( \
						"BALLS()", \
						fs.readFileSync( \
							"sphincs.js/" + file.replace("super", "") \
						).toString().trim() \
					) \
			); \
		}; \
	'

	rm -rf sphincs.js codecs.js js-sha512 promise-polyfill

clean:
	rm -rf dist sphincs.js codecs.js js-sha512 promise-polyfill
