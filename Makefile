all:
	rm -rf dist sphincs.js codecs.js js-sha512 2> /dev/null
	mkdir dist

	git clone git@github.com:cyph/sphincs.js.git

	curl -s https://raw.githubusercontent.com/jedisct1/libsodium.js/9a8b4f9/wrapper/wrap-template.js | \
		tr '\n' '☁' | perl -pe 's/.*Codecs(.*?)Memory management.*/\1/g' | tr '☁' '\n' > codecs.js

	git clone https://github.com/emn178/js-sha512.git
	sed -i 's|typeof module|"undefined"|' js-sha512/build/sha512.min.js

	cp pre.js dist/supersphincs.debug.js
	echo 'BALLS();' >> dist/supersphincs.debug.js
	cat js-sha512/build/sha512.min.js >> dist/supersphincs.debug.js
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

	rm -rf sphincs.js codecs.js js-sha512

clean:
	rm -rf dist sphincs.js codecs.js js-sha512
