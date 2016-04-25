all:
	rm -rf dist sphincs.js codecs.js 2> /dev/null
	mkdir dist

	git clone git@github.com:cyph/sphincs.js.git

	curl -s https://raw.githubusercontent.com/jedisct1/libsodium.js/9a8b4f9/wrapper/wrap-template.js | \
		tr '\n' '☁' | perl -pe 's/.*Codecs(.*?)Memory management.*/\1/g' | tr '☁' '\n' > codecs.js

	cp pre.js dist/supersphincs.debug.js
	cat sphincs.js/dist/sphincs.debug.js >> dist/supersphincs.debug.js
	cat codecs.js >> dist/supersphincs.debug.js
	cat post.js >> dist/supersphincs.debug.js

	echo "$$(cat pre.js)BALLS();$$(cat codecs.js)$$(cat post.js)" | uglifyjs > dist/supersphincs.js
	node -e ' \
		var fs = require("fs"); \
		fs.writeFileSync( \
			"dist/supersphincs.js", \
			fs.readFileSync("dist/supersphincs.js"). \
				toString(). \
				replace( \
					"BALLS()", \
					fs.readFileSync("sphincs.js/dist/sphincs.js").toString().trim() \
				) \
		); \
	'

	rm -rf sphincs.js codecs.js

clean:
	rm -rf dist sphincs.js codecs.js
