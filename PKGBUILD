# Maintainer: Caleb Eastman <eastmancr@gmail.com>
pkgname=netwrap
pkgver=1.0
pkgrel=1
pkgdesc="Run a program in an isolated network namespace with port forwarding"
arch=('x86_64' 'aarch64')
url="https://github.com/eastmancr/netwrap"
license=('Apache-2.0')
depends=('iproute2')
optdepends=('python3: tests')
makedepends=('go')
options=('!strip' '!debug') # Go binaries don't play well with standard strip/debug

source=('main.go' 'go.mod' 'netwrap.1' 'README.md' 'LICENSE')
sha256sums=('8af9e3ecdb34cb589fc031f756804cf0b334ee754eaed4cde78e67ff860cbdbe'
            '36e5716c68b7ce5cd6272a13536ad8f7e40c89f793d9240b038f433e5f5ebcc3'
            'd389699c8e12c1fd11e40f5c61b563f871db86d15664cf5be2911efe7e87f403'
            '2c0a7be7c5cd80fc2de24b43531f1da8dc5724fe26eed78244744074107f5a6d'
            'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30')

build() {
  cd "$srcdir" || return 1
  export CGO_ENABLED=0
  # Use -buildmode=pie for security hardening (PIE/RELRO), supported with CGO=0 on linux/amd64
  go build -trimpath -buildmode=pie -ldflags "-s -w" -o netwrap main.go
}

package() {
  cd "$srcdir" || return 1

  install -Dm755 netwrap "$pkgdir/usr/bin/netwrap"
  install -Dm644 netwrap.1 "$pkgdir/usr/share/man/man1/netwrap.1"
  install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
