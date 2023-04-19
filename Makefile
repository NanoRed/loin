appexe:
	# sudo apt-get install -y mingw-w64
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -o app.exe github.com/NanoRed/loin/cmd/client
	mv ./app.exe /mnt/c/Users/radix/Desktop/