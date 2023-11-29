<!-- TOC -->
  * [Pre requirements](#pre-requirements)
  * [Building](#building)
<!-- TOC -->

If you want to compile the source code by yourself, follow these steps.

## Pre requirements

You will need the Go compiler at version 1.19 or later.

See the [download](http://download/) page to find out where to get the source code. You can also clone the repository
using git:

```
git clone https://gitlab.roessner-net.de/croessner/nauthilus.git
```

The "main" branch *should* mostly be stable, as it gets merges from the "features" branch. If you require stable
packages, use the binaries provided with each release or checkout the corresponding git tag!

## Building

```
go build -mod=vendor -ldflags="-s -w" -o nauthilus .
```

If everything went fine, follow the instructions found on the
page "[Using binaries](https://nauthilus.io/docs/using-binaries/)".