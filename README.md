<h1 align="center">
  <img
    alt=""
    src="https://raw.githubusercontent.com/catppuccin/catppuccin/main/assets/misc/transparent.png"
    height="30"
    width="0px"
  />
   rpma
  <img
    alt=""
    src="https://raw.githubusercontent.com/catppuccin/catppuccin/main/assets/misc/transparent.png"
    height="30"
    width="0px"
  />
</h1>

<p align="center">
  <a href="https://github.com/crhowell3/rpma/stargazers">
    <img
      alt="Stargazers"
      src="https://img.shields.io/github/stars/crhowell3/rpma?style=for-the-badge&logo=starship&color=b16286&logoColor=d9e0ee&labelColor=282a36"
    />
  </a>
  <a href="https://github.com/crhowell3/rpma/issues">
    <img
      alt="Issues"
      src="https://img.shields.io/github/issues/crhowell3/rpma?style=for-the-badge&logo=gitbook&color=d79921&logoColor=d9e0ee&labelColor=282a36"
    />
  </a>
  <a href="https://github.com/crhowell3/rpma/contributors">
    <img
      alt="Contributors"
      src="https://img.shields.io/github/contributors/crhowell3/rpma?style=for-the-badge&logo=opensourceinitiative&color=689d6a&logoColor=d9e0ee&labelColor=282a36"
    />
  </a>
  <a href="#">
    <img
      alt="Maintained"
      src="https://img.shields.io/maintenance/yes/2025?style=for-the-badge&color=98971a&labelColor=282a36"
    />
  </a>
</p>

&nbsp;

## 💭 About

rpma is a simple peer-to-peer (p2p) networking application written in Rust.

> [!IMPORTANT]
> This is a networking application, so it is possible that Windows Defender or
> other antivirus software may block it from running or communicating over the
> network.

## 🔰 Getting Started

### Prerequisites

If you are building from source, at minimum you need the following tools:

- [git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
- [rustc](https://www.rust-lang.org/tools/install)

### Installation

If you have rustc installed, you can manually build and install rpma from the
command line:

```shell
# Clone the repository using git
git clone https://github.com/crhowell3/rpma.git
cd rpma

# Install using cargo
cargo install --path .
````

### Running

rpma is built upon the concept of communication nodes. To demonstrate basic functionality,
you need to spin up at least two network nodes.

1. Create a noninteractive network node:
  ```shell
  ./rpma -l 127.0.0.1:3500
  ```

2. Create an interactive node and connect it to the first node:
  ```shell
  ./rpma -i -l 127.0.0.1:3501 127.0.0.1:3500
  ```

### Interactive TTY Mode

When a node is started with interactive TTY mode enabled, the user can run commands
from the terminal. To view the list of supported commands, run `help` on a node that
was executed with the `-i` flag.

### Termination

To terminate a node, either run `exit` (if it is a node with interactive TTY enabled),
or simply press `CTRL+C` in the terminal.

<p align="center">
  Copyright &copy; 2025-present
  <a href="https://github.com/crhowell3" target="_blank">Cameron Howell</a>
</p>
<p align="center">
  <a href="https://github.com/crhowell3/rpma/blob/main/LICENSE"
    ><img
      alt="MIT License"
      src="https://img.shields.io/static/v1.svg?style=for-the-badge&label=License&message=MIT&logoColor=d9e0ee&colorA=282a36&colorB=b16286"
  /></a>
</p>
