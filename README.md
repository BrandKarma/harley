# harley: Haskell HTTP traffic replay


## Installation

```
cabal sandbox init .
cabal install --only-dependencies
cabal configure --enable-test
cabal build
```

## Usage

### Forwarding the traffic in TCP to the receiver 

```
harley --output “tcp://192.168.1.1:8000”
```

### Forwarding the traffic in HTTP to the receiver

```
harley --output “http://192.168.1.1:8000”
```


## License
BSD-3 Copyright © 2015 BrandKarma (Circos.com)
