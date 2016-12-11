Compilation
-----------
Type `make`. If openssl is not installed on your system and you don't need
AES encryption, edit Makefile and comment out the lines SSL_LIB and USE_SSL.


Test
----

./sg-game -d test.png


Usage
-----

    About: Encode plain text or an arbitrary file into an image
    Usage: sg-game [OPTIONS]

    Options:
       -e, --encode <file>          PNG/JPG container
       -d, --decode <file>          decode the embedded text or file
       -o, --output <file|prefix>   output PNG/JPG file (with -e) or output file prefix (with -d)
       -p, --password <text>        protect with password, "-" to read from stdin
       -s, --embed-secret <file>    file to embed in the image

    Example:
       # Embed file, then retrieve
       sg-game -e container.jpg -o encoded.png -s file.dat
       sg-game -d encoded.png -o prefix
    
       # Embed text, then retrieve
       sg-game -e container.jpg -o encoded.jpg
       <type message when prompted>
       sg-game -d encoded.jpg
    
       # Embed and retrieve text, password protected
       sg-game -e container.jpg -o encoded.png -s file.dat -p password
       sg-game -d encoded.png -p password



