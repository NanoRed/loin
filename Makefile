server:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o loinsrv github.com/NanoRed/loin/cmd/server
	scp ./loinsrv red@106.52.81.44:~/loinsrv
	rm -f ./loinsrv

client:
	# sudo apt-get install -y mingw-w64
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -o loincli.exe github.com/NanoRed/loin/cmd/client
	mv ./loincli.exe /mnt/s/mine/loin