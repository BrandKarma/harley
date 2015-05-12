.PHONY: all bench build clean configure haddock hpc install repl run test

all: install configure build haddock test hpc bench

bench:
	cabal bench --jobs

build:
	cabal build --jobs

clean:
	cabal clean
	if test -d .cabal-sandbox; then cabal sandbox delete; fi
	if test -d .hpc; then rm -r .hpc; fi

configure:
	cabal configure --enable-benchmarks --enable-tests

haddock:
	cabal haddock --hyperlink-source

hpc:
	hpc markup --destdir=tmp dist/hpc/tix/tests/tests.tix

install:
	cabal sandbox init
	cabal install --enable-benchmarks --enable-tests --jobs --only-dependencies --reorder-goals

repl:
	cabal repl lib:harley

run:
	cabal run --jobs harley

test:
	cabal test --jobs
	cabal check
