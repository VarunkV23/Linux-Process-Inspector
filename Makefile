BIN := target/debug/procsnoop
RELEASE_BIN := target/release/procsnoop

.PHONY: build release run clean install uninstall

build:
	cargo build

release:
	cargo build --release

# Usage: make run ARGS="--trace 5"
run: build
	sudo $(BIN) $(ARGS)

# Usage: make rrun ARGS="--trace 5"
rrun: release
	sudo $(RELEASE_BIN) $(ARGS)

install: release
	sudo cp $(RELEASE_BIN) /usr/local/bin/procsnoop
	@echo "Installed → /usr/local/bin/procsnoop"

uninstall:
	sudo rm -f /usr/local/bin/procsnoop
	@echo "Removed /usr/local/bin/procsnoop"

clean:
	cargo clean
