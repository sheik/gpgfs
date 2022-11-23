package gpgfs

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/sheik/gpgfs/pkg/crypto"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const SALT = "7861492h18ncdskjhfnb132riunfn21n3unf9284env92183nf9283nkjnwdfsjnvk231"

var (
	VAULT = ""
)

type GPGFS struct {
	fs.Inode
	vault    string
	password []byte

	nodes map[string]*GPGFile
	dirs  map[string]*GPGFS
}

func (G *GPGFS) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	p := G.vault
	fsa, ok := f.(fs.FileSetattrer)
	if ok && fsa != nil {
		fsa.Setattr(ctx, in, out)
	} else {
		if m, ok := in.GetMode(); ok {
			if err := syscall.Chmod(p, m); err != nil {
				return fs.ToErrno(err)
			}
		}

		uid, uok := in.GetUID()
		gid, gok := in.GetGID()
		if uok || gok {
			suid := -1
			sgid := -1
			if uok {
				suid = int(uid)
			}
			if gok {
				sgid = int(gid)
			}
			if err := syscall.Chown(p, suid, sgid); err != nil {
				return fs.ToErrno(err)
			}
		}

		mtime, mok := in.GetMTime()
		atime, aok := in.GetATime()

		if mok || aok {

			ap := &atime
			mp := &mtime
			if !aok {
				ap = nil
			}
			if !mok {
				mp = nil
			}
			var ts [2]syscall.Timespec
			ts[0] = fuse.UtimeToTimespec(ap)
			ts[1] = fuse.UtimeToTimespec(mp)

			if err := syscall.UtimesNano(p, ts[:]); err != nil {
				return fs.ToErrno(err)
			}
		}

		if sz, ok := in.GetSize(); ok {
			if err := syscall.Truncate(p, int64(sz)); err != nil {
				return fs.ToErrno(err)
			}
		}
	}

	fga, ok := f.(fs.FileGetattrer)
	if ok && fga != nil {
		fga.Getattr(ctx, out)
	} else {
		st := syscall.Stat_t{}
		err := syscall.Lstat(p, &st)
		if err != nil {
			return fs.ToErrno(err)
		}
		out.FromStat(&st)
	}
	return fuse.F_OK
}

func (G *GPGFS) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	id := G.SaveName(name)
	path := filepath.Join(G.vault, name)
	dataPath := filepath.Join(G.vault, id)
	os.Mkdir(dataPath, 0755)
	G.AddDir(ctx, path)
	node := G.GetChild(name)
	return node, fuse.F_OK
}

func (G *GPGFS) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (node *fs.Inode, errno syscall.Errno) {
	ch := G.AddSymlink(ctx, target, name)
	return ch, fuse.F_OK
}

func (G *GPGFS) GetID(name string) string {
	sum := sha256.Sum256([]byte(G.vault + name + SALT))
	return fmt.Sprintf("%x", sum)
}

func (G *GPGFS) SaveName(name string) string {
	id := G.GetID(name)
	filenameFile := filepath.Join(VAULT, ".db", id)

	fp, err := os.OpenFile(filenameFile, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		panic(err)
	}
	defer fp.Close()

	enc, err := crypto.NewStreamEncrypter(G.password, G.password, strings.NewReader(name))
	if err != nil {
		panic(err)
	}
	encrypted, err := io.ReadAll(enc)
	if err != nil {
		panic(err)
	}

	fp.Write(encrypted)

	err = G.SaveMeta(filenameFile+".meta", enc.Meta())
	if err != nil {
		panic(err)
	}

	return id
}

func (G *GPGFS) SaveMeta(filename string, meta crypto.StreamMeta) error {
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	err := enc.Encode(meta)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(G.password)
	if err != nil {
		return err
	}
	cipherText := make([]byte, block.BlockSize()+buffer.Len())
	iv := cipherText[:block.BlockSize()]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[block.BlockSize():], buffer.Bytes())

	err = os.WriteFile(filename, cipherText, 0600)
	if err != nil {
		return err
	}
	return nil
}

func (G *GPGFS) GetMeta(id string) crypto.StreamMeta {
	filenameFile := filepath.Join(VAULT, ".db", id+".meta")
	buf, err := os.ReadFile(filenameFile)
	if err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(G.password)
	if err != nil {
		panic(err)
	}

	iv := buf[:block.BlockSize()]
	buf = buf[block.BlockSize():]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(buf, buf)

	dec := gob.NewDecoder(bytes.NewReader(buf))
	var meta crypto.StreamMeta
	dec.Decode(&meta)
	return meta
}

func (G *GPGFS) GetName(id string) string {
	filenameFile := filepath.Join(VAULT, ".db", id)
	buf, err := os.ReadFile(filenameFile)
	if err != nil {
		panic(err)
	}

	meta := G.GetMeta(id)

	dec, err := crypto.NewStreamDecrypter(G.password, G.password, meta, bytes.NewReader(buf))
	if err != nil {
		panic(err)
	}
	unencrypted, err := io.ReadAll(dec)
	if err != nil {
		panic(err)
	}
	return string(unencrypted)
}

func (G *GPGFS) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (node *fs.Inode, fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	errno = fuse.F_OK

	id := G.SaveName(name)
	path := filepath.Join(G.vault, name)
	dataPath := filepath.Join(G.vault, id)

	G.AddFile(ctx, path, nil)

	fp, err := os.OpenFile(dataPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		log.Println(err)
		err = fs.ToErrno(err)
		return
	}
	fp.Close()

	node = G.GetChild(name)
	fh = nil
	return
}

func (G *GPGFS) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	fileStat, err := os.Stat(G.vault)
	if err != nil {
		return fs.ToErrno(err)
	}

	stat := fileStat.Sys().(*syscall.Stat_t)

	out.Mode = stat.Mode
	out.Nlink = 1
	out.Mtime = uint64(fileStat.ModTime().Unix())
	out.Atime = out.Mtime
	out.Ctime = out.Mtime
	out.Owner = struct {
		Uid uint32
		Gid uint32
	}{Uid: stat.Uid, Gid: stat.Gid}
	out.Size = 4096
	const bs = 512
	out.Blksize = bs
	out.Blocks = (out.Size + bs - 1) / bs

	return fuse.F_OK
}

func (G *GPGFS) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	nameID := G.GetID(name)
	newNameID := G.GetID(newName)
	G.SaveName(newName)

	oldPath := filepath.Join(G.vault, nameID)
	newPath := filepath.Join(G.vault, newNameID)

	// rename data file
	err := os.Rename(oldPath, newPath)
	if err != nil {
		return fs.ToErrno(err)
	}

	err = os.Rename(oldPath+".meta", newPath+".meta")
	if err != nil {
		return fs.ToErrno(err)
	}

	if G.GetChild(name).IsDir() {
		G.dirs[name].vault = newPath
		G.dirs[newName] = G.dirs[name]
		delete(G.dirs, name)
	} else {
		// reorg the filesystem
		G.nodes[name].dataFile = newPath
		G.nodes[newName] = G.nodes[name]
		delete(G.nodes, nameID)
	}

	return syscall.F_OK
}

func NewEncryptedFilesystem(vault string, password []byte) (*GPGFS, error) {
	VAULT = vault
	path := filepath.Join(VAULT, ".db")
	os.Mkdir(path, 0700)
	return NewGPGFS(vault, password)
}

func NewGPGFS(vault string, password []byte) (*GPGFS, error) {
	if len(password) != crypto.DefaultKeySize {
		return nil, fmt.Errorf("password of length %d required", crypto.DefaultKeySize)
	}
	return &GPGFS{vault: vault, password: password, nodes: make(map[string]*GPGFile), dirs: make(map[string]*GPGFS)}, nil
}

func (G *GPGFS) OnAdd(ctx context.Context) {
	nodes, err := os.ReadDir(G.vault)
	if err != nil {
		panic(err)
	}
	for _, node := range nodes {
		if node.Name() == ".db" {
			continue
		}
		if filepath.Ext(node.Name()) == ".meta" {
			continue
		}
		name := G.GetName(node.Name())
		path := filepath.Join(G.vault, name)
		if node.IsDir() {
			G.AddDir(ctx, path)
		} else {
			G.AddFile(ctx, path, nil)
		}
	}
}

func (G *GPGFS) AddDir(ctx context.Context, path string) *GPGFS {
	name := filepath.Base(path)
	id := G.SaveName(name)
	dir, _ := NewGPGFS(filepath.Join(G.vault, id), G.password)
	G.dirs[filepath.Base(path)] = dir
	ch := G.NewPersistentInode(ctx, dir, fs.StableAttr{Mode: fuse.S_IFDIR | 0755})
	ok := G.AddChild(name, ch, true)
	if !ok {
		panic("could not add child")
	}
	return dir
}

func (G *GPGFS) AddFile(ctx context.Context, path string, node *fs.Inode) {
	name := filepath.Base(path)
	id := G.SaveName(name)
	file := NewGPGFile(filepath.Join(G.vault, id), G)
	if node != nil {
		file.Inode = *node
	}
	G.nodes[filepath.Base(path)] = file
	ch := G.NewPersistentInode(ctx, file, fs.StableAttr{})
	ok := G.AddChild(name, ch, true)
	if !ok {
		panic("could not add child")
	}
}

func (file *GPGFile) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	return []byte(file.link), fuse.F_OK
}

func (G *GPGFS) AddSymlink(ctx context.Context, target string, name string) *fs.Inode {
	path := filepath.Join(G.vault, target)
	gpgfile := NewGPGFile(path, G)
	gpgfile.link = target
	ch := G.NewPersistentInode(ctx, gpgfile, fs.StableAttr{Mode: fuse.S_IFLNK | 0777})
	return ch
}

func (G *GPGFS) Unlink(ctx context.Context, name string) syscall.Errno {
	id := G.GetID(name)
	path := filepath.Join(G.vault, id)
	err := syscall.Unlink(path)
	if err != nil {
		log.Println(err)
	}
	return fuse.F_OK
}
