all:
	rm -rf dist sphincs.js sodiumhelpers js-sha512 promise-polyfill 2> /dev/null
	mkdir dist

	git clone git@github.com:cyph/sphincs.js.git

	mkdir sodiumhelpers
	wget https://raw.githubusercontent.com/jedisct1/libsodium.js/9a8b4f9/wrapper/wrap-template.js -O sodiumhelpers/main.js
	cat sodiumhelpers/main.js | tr '\n' '☁' | perl -pe 's/.*Codecs(.*?)Memory management.*/\1/g' | tr '☁' '\n' > sodiumhelpers/codecs.js
	cat sodiumhelpers/main.js | tr '\n' ' ' | perl -pe 's/\s+/ /g' | perl -pe 's/.*(function memzero.*?)\s+function.*/\1/g' > sodiumhelpers/memzero.js

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
	cat sodiumhelpers/codecs.js >> dist/supersphincs.debug.js
	echo >> dist/supersphincs.debug.js
	cat sodiumhelpers/memzero.js >> dist/supersphincs.debug.js
	echo >> dist/supersphincs.debug.js
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

	rm -rf sphincs.js sodiumhelpers js-sha512 promise-polyfill

clean:
	rm -rf dist sphincs.js sodiumhelpers js-sha512 promise-polyfill
