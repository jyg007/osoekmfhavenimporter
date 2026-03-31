BIN_DIR := ../bin

all: $(BIN_DIR) ekmfimportserver ekmfexport createTKEY rsawrapTKEY createskblob hsmrsawrapTKEY ekmfQ

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

ekmfimportserver: ekmfimportserver.go
	go build -o $(BIN_DIR)/ekmfimportserver $^

ekmfexport: ekmfexport.go
	go build -o $(BIN_DIR)/ekmfexport $^

ekmfQ: ekmfQ.go
	go build -o $(BIN_DIR)/ekmfQ $^

createTKEY: createTKEY.go
	go build -o $(BIN_DIR)/createTKEY $^

rsawrapTKEY: rsawrapTKEY.go
	go build -o $(BIN_DIR)/rsawrapTKEY $^

hsmrsawrapTKEY: hsmrsawrapTKEY.go
	go build -o $(BIN_DIR)/hsmrsawrapTKEY $^

createskblob: createskblob.go
	go build -o $(BIN_DIR)/createskblob $^		
