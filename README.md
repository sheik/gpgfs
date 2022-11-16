# gpgfs - The GPG File System
gpgfs is a FUSE filesystem that will mount a directory of encrypted files
and unencrypt them on the fly.

The current version is read-only.

## Install
    go install github.com/sheik/gpgfs/cmd/gpgfs@latest

## Use
First you need to export your GPG keys:

    gpg --output privkey.pgp -a --export-secret-key
    gpg --output pubkey.pgp -a --export <your-name>

Next you can mount a directory. In this example we have a directory called
**vault** in the current directory that is filled with encrypted files.

    gpgfs -privkey privkey.gpg -pubkey pubkey.gpg /mnt/unencrypted ./vault
