VERSION=0.1

# Comment out these two lines if openssl is not available:
SSL_LIB=`pkg-config openssl --libs`
USE_SSL=-DHAVE_SSL


PNG_TGZ=libpng-1.6.26.tar.gz
PNG_DIR=libpng-1.6.26
PNG_LIB=$(PNG_DIR)/.libs/libpng16.a

JPG_TGZ=jpegsrc.v6b.tar.gz
JPG_DIR=jpeg-6b
JPG_LIB=$(JPG_DIR)/libjpeg.a


all: $(PNG_LIB) $(JPG_LIB) sg-game

sg-game: $(PNG_LIB) $(JPG_LIB) sg-game.c
	gcc -O2 -g -Wall -I$(PNG_DIR) -I$(JPG_DIR) $(USE_SSL) sg-game.c -o $@ -lm -lz $(PNG_LIB) $(JPG_LIB) $(SSL_LIB)

$(PNG_LIB): $(PNG_TGZ)
	tar xzf $(PNG_TGZ) && cd $(PNG_DIR) && ./configure && make 

$(JPG_LIB): $(JPG_TGZ)
	tar xzf $(JPG_TGZ) && cd $(JPG_DIR) && ./configure && make 

clean:
	rm -rf $(PNG_DIR) $(JPG_DIR) sg-game

distro:
	mkdir -p sg-game.$(VERSION) && cp $(PNG_TGZ) $(JPG_TGZ) sg-game.c README Makefile sg-game.$(VERSION)/ \
	    && tar czf sg-game.$(VERSION).tgz sg-game.$(VERSION)/ && rm -rf sg-game.$(VERSION)

