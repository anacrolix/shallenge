windows:
	cargo build -r --target x86_64-pc-windows-gnu
	zip -j anacrolix-shallenge-windows.zip target/x86_64-pc-windows-gnu/release/shallenge.exe
