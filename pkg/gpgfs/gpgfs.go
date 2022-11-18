package gpgfs

import (
	"context"
	"fmt"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"log"
	"os"
	"path/filepath"
	"syscall"
)

type GPGFS struct {
	fs.Inode
	vault    string
	pubkey   string
	privkey  string
	password string
}

func (G *GPGFS) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	node := G.GetChild(name)
	G.RmChild(name)
	if node.IsDir() {
		G.AddDir(ctx, filepath.Join(G.vault, newName))
	} else {
		G.AddFile(ctx, filepath.Join(G.vault, newName))
	}
	return syscall.F_OK
}

func NewGPGFS(vault, pubkey, privkey, password string) (*GPGFS, error) {
	if privkey == "" || pubkey == "" || password == "" {
		return nil, fmt.Errorf("private key, public key, and password are required")
	}
	return &GPGFS{vault: vault, pubkey: pubkey, privkey: privkey, password: password}, nil
}

func (G *GPGFS) OnAdd(ctx context.Context) {
	nodes, err := os.ReadDir(G.vault)
	if err != nil {
		panic(err)
	}
	for _, node := range nodes {
		path := filepath.Join(G.vault, node.Name())
		if node.IsDir() {
			G.AddDir(ctx, path)
		} else {
			G.AddFile(ctx, path)
		}
	}
}

func (G *GPGFS) AddDir(ctx context.Context, path string) {
	log.Println("AddDir called, path:", path)
	dir, _ := NewGPGFS(path, G.pubkey, G.privkey, G.password)
	ch := G.NewPersistentInode(ctx, dir, fs.StableAttr{Mode: fuse.S_IFDIR})
	ok := G.AddChild(filepath.Base(path), ch, true)
	if !ok {
		panic("could not add child")
	}
}

func (G *GPGFS) AddFile(ctx context.Context, path string) {
	log.Println("AddFile called, path:", path)
	file := NewGPGFile(path)
	ch := G.NewPersistentInode(ctx, file, fs.StableAttr{})
	ok := G.AddChild(filepath.Base(path), ch, true)
	if !ok {
		panic("could not add child")
	}
}

type GPGFile struct {
	fs.Inode
	dataFile string
}

func NewGPGFile(path string) *GPGFile {
	return &GPGFile{dataFile: path}
}
