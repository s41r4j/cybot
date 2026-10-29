module github.com/ffuf/ffuf/v2

go 1.26.0

require (
	github.com/PuerkitoBio/goquery v1.8.0
	github.com/adrg/xdg v0.4.0
	github.com/andybalholm/brotli v1.0.5
	github.com/ffuf/pencode v0.0.0-20230421231718-2cea7e60a693
	github.com/pelletier/go-toml v1.9.5
)

require (
	github.com/ProtonMail/go-crypto v1.4.0 // indirect
	github.com/andybalholm/cascadia v1.3.1 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/klauspost/compress v1.18.7 // indirect
	github.com/yuin/goldmark v1.7.17 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

replace github.com/google/go-github/v30 => ./.cybot-patches/go-github
