_:
  @just --list

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

