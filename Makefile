build:
	wasm-pack build --target=web
server:
	python3 -m http.server
test:
	cargo test
