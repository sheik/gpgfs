package main

import (
	"flag"
	"fmt"
	"github.com/sheik/gpgfs/pkg/crypto"
	"github.com/sheik/gpgfs/pkg/gpgfs"
	"os"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"golang.org/x/term"
)

func main() {
	ttl := flag.Duration("ttl", time.Second, "attribute/entry cache TTL.")
	flag.Parse()
	if flag.NArg() < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s MOUNTPOINT VAULT-DIR\n", os.Args[0])
		os.Exit(2)
	}

	passPhrase := os.Getenv("PASSPHRASE")
	if passPhrase == "" {
		fmt.Print("Enter GPG passphrase: ")
		buf, err := term.ReadPassword(syscall.Stdin)
		if err != nil {
			panic(err)
		}
		passPhrase = string(buf)
	}

	pass := crypto.StringToKey([]byte(passPhrase))

	root, err := gpgfs.NewEncryptedFilesystem(flag.Arg(1), pass)
	if err != nil {
		fmt.Fprintf(os.Stderr, "NewGPGFS failed: %v\n", err)
		os.Exit(1)
	}

	opts := &fs.Options{
		AttrTimeout:  ttl,
		EntryTimeout: ttl,
	}
	server, err := fs.Mount(flag.Arg(0), root, opts)
	if err != nil {
		fmt.Printf("Mount fail: %v\n", err)
		os.Exit(1)
	}
	server.Wait()
}
