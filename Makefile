app:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o app github.com/NanoRed/loin/cmd

appexe:
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -tags windows -o app.exe github.com/NanoRed/loin/cmd

appexe2:
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -tags windows -o app2.exe github.com/NanoRed/loin/cmd