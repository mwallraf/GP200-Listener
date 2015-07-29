INSTALL-DIR:=/opt

all:
	echo "Use 'make install' to install the listener"

install:
	cp -R GP200-Listener ${INSTALL-DIR}
	sudo chmod -R 755 ${INSTALL-DIR}

clean:
	rm -rf ${INSTALL-DIR}
	