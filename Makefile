


tidy:
	go fmt ./...
	go mod tidy


module:
	xcaddy list-modules | grep 'events.handlers'
