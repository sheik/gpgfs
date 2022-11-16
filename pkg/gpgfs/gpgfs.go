package gpgfs

import (
	"context"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"os"
	"sync"
	"syscall"
	"time"
)

var _ = (fs.NodeOnAdder)((*GPGRoot)(nil))

type GPGRoot struct {
	fs.Inode
	root string

	pubKey     []byte
	privKey    []byte
	passPhrase []byte
}

func (r *GPGRoot) OnAdd(ctx context.Context) {
	c, err := os.ReadDir(r.root)
	if err != nil {
		panic(err)
	}
	p := &r.Inode

	for _, f := range c {
		if f.IsDir() {
			continue
		}
		ch := p.NewPersistentInode(ctx, &gpgFile{root: r, file: r.root + "/" + f.Name()}, fs.StableAttr{})
		p.AddChild(f.Name(), ch, true)
	}
}

func NewGPGTree(name, pubKey, privKey, passPhrase string) (fs.InodeEmbedder, error) {
	pubKeyBytes, err := os.ReadFile(pubKey)
	if err != nil {
		panic(err)
	}
	privKeyBytes, err := os.ReadFile(privKey)
	if err != nil {
		panic(err)
	}
	return &GPGRoot{root: name, pubKey: pubKeyBytes, privKey: privKeyBytes, passPhrase: []byte(passPhrase)}, nil
}

type gpgFile struct {
	fs.Inode
	file string
	mu   sync.Mutex
	data []byte
	root *GPGRoot
}

// Getattr sets the minimum, which is the size. A more full-featured
// FS would also set timestamps and permissions.
func (file *gpgFile) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = 0644
	out.Nlink = 1
	out.Mtime = uint64(time.Now().Unix())
	out.Atime = out.Mtime
	out.Ctime = out.Mtime
	out.Size = 20000
	const bs = 512
	out.Blksize = bs
	out.Blocks = (out.Size + bs - 1) / bs
	return 0
}

// Open lazily unpacks zip data
func (file *gpgFile) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.data == nil {
		unencrypted, err := os.ReadFile(file.file)
		if err != nil {
			panic(err)
			return nil, 0, syscall.EIO
		}
		// decrypt armored encrypted message using the private key and obtain plain text
		decrypted, err := helper.DecryptMessageArmored(string(file.root.privKey), file.root.passPhrase, string(unencrypted))
		file.data = []byte(decrypted)
	}

	// We don't return a filehandle since we don't really need
	// one.  The file content is immutable, so hint the kernel to
	// cache the data.
	return nil, fuse.FOPEN_KEEP_CACHE, 0
}

// Read simply returns the data that was already unpacked in the Open call
func (file *gpgFile) Read(ctx context.Context, f fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	end := int(off) + len(dest)
	if end > len(file.data) {
		end = len(file.data)
	}
	return fuse.ReadResultData(file.data[off:end]), 0
}

func NewGPGFileSystem(name string, pubKey string, privKey string, passPhrase string) (root fs.InodeEmbedder, err error) {
	root, err = NewGPGTree(name, pubKey, privKey, passPhrase)

	if err != nil {
		return nil, err
	}

	return root, nil
}
