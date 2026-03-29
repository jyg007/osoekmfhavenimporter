all: ekmfimportserver ekmfexport createTKEY rsawrapTKEY createskblob hsmrsawrapTKEY ekmfQ


ekmfimportserver: ekmfimportserver.go
	go build $^

ekmfexport: ekmfexport.go
	go build $^

ekmfQ: ekmfQ.go
	go build $^

createTKEY: createTKEY.go
	go build $^

rsawrapTKEY: rsawrapTKEY.go
	go build $^

hsmrsawrapTKEY: hsmrsawrapTKEY.go
	go build $^

createskblob: createskblob.go
	go build $^

