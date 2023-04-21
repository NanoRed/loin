client:
	# sudo apt-get install -y mingw-w64
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -o loin.exe github.com/NanoRed/loin/cmd/client
	mv ./loin.exe /mnt/s/loin

server:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o loin github.com/NanoRed/loin/cmd/server
	scp ./loin red@106.52.81.44:~/loin
	rm -f ./loin