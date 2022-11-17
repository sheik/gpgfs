// Copyright 2016 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This is main program driver for github.com/hanwen/go-fuse/zipfs, a
// filesystem for mounting read-only archives.
package main

import (
	"flag"
	"fmt"
	"github.com/sheik/gpgfs/pkg/gpgfs"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
)

func main() {
	// Scans the arg list and sets up flags
	debug := flag.Bool("debug", false, "print debugging messages.")
	profile := flag.String("profile", "", "record cpu profile.")
	mem_profile := flag.String("mem-profile", "", "record memory profile.")
	command := flag.String("run", "", "run this command after mounting.")
	ttl := flag.Duration("ttl", time.Second, "attribute/entry cache TTL.")
	pubKey := flag.String("pubkey", "", "path to public gpg key")
	privKey := flag.String("privkey", "", "path to private gpg key")
	flag.Parse()
	if flag.NArg() < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s MOUNTPOINT ZIP-FILE\n", os.Args[0])
		os.Exit(2)
	}

	var profFile, memProfFile io.Writer
	var err error
	if *profile != "" {
		profFile, err = os.Create(*profile)
		if err != nil {
			log.Fatalf("os.Create: %v", err)
		}
	}
	if *mem_profile != "" {
		memProfFile, err = os.Create(*mem_profile)
		if err != nil {
			log.Fatalf("os.Create: %v", err)
		}
	}
	/*
		fmt.Print("Enter GPG passphrase: ")
		passPhrase, err := term.ReadPassword(syscall.Stdin)
		if err != nil {
			panic(err)
		}
	*/
	passPhrase := []byte("Test1234Abc123")

	root, err := gpgfs.NewGPGFileSystem(flag.Arg(1), *pubKey, *privKey, string(passPhrase))
	if err != nil {
		fmt.Fprintf(os.Stderr, "NewArchiveFileSystem failed: %v\n", err)
		os.Exit(1)
	}

	opts := &fs.Options{
		AttrTimeout:  ttl,
		EntryTimeout: ttl,
	}
	opts.Debug = *debug
	server, err := fs.Mount(flag.Arg(0), root, opts)
	if err != nil {
		fmt.Printf("Mount fail: %v\n", err)
		os.Exit(1)
	}

	runtime.GC()
	if profFile != nil {
		pprof.StartCPUProfile(profFile)
		defer pprof.StopCPUProfile()
	}

	if *command != "" {
		args := strings.Split(*command, " ")
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Start()
	}

	server.Wait()
	if memProfFile != nil {
		pprof.WriteHeapProfile(memProfFile)
	}
}
