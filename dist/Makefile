all:
	if [ -e didaozhan.app ] ; then mv -f didaozhan.app .didaozhan.app; fi
	cp ../ebin/* .
	cp ../deps/*/priv/* ../priv/
	cp ../deps/*/ebin/* .
	if [ -e .didaozhan.app ] ; then mv -f .didaozhan.app didaozhan.app; fi

