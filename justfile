_:
  @just --list

# publish
publish:
  cargo publish --registry crates-io

# install card-cli
install:
  cargo install --path .

# build without default features
build-simple:
  cargo build --no-default-features

# install without default features
install-simple:
  cargo install --no-default-features --path .

# run --help
help:
  cargo r -- --help

# run pgp-card-list
pgp-list:
  cargo r -- pgp-card-list

# run example: rsa_encrypt
example-rsa-encrypt:
  cargo r --example rsa_encrypt

# run example: ssh_agent
example-ssh-agent:
  cargo r --example ssh_agent

