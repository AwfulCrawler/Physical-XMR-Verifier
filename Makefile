all: mainnet

mainnet:
	mkdir -p build
	cd build && cmake .. && $(MAKE)

testnet:
	mkdir -p build
	cd build && cmake -D TESTNET=true .. && $(MAKE)

clean:
	rm -rf build

.PHONY: all mainnet testnet clean
