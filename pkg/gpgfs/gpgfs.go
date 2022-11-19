package gpgfs

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const SALT = "7861492h18ncdskjhfnb132riunfn21n3unf9284env92183nf9283nkjnwdfsjnvk231"

var (
	VAULT = ""
)

type GPGFS struct {
	fs.Inode
	vault    string
	pubkey   string
	privkey  string
	password string

	nodes map[string]*GPGFile
	dirs  map[string]*GPGFS
}

func (G *GPGFS) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	log.Println("GPGFS.Mkdir called:", name)
	id := G.SaveName(name)
	path := filepath.Join(G.vault, name)
	dataPath := filepath.Join(G.vault, id)
	os.Mkdir(dataPath, 0755)
	G.AddDir(ctx, path)
	node := G.GetChild(name)
	return node, fuse.F_OK
}

func (G *GPGFS) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (node *fs.Inode, errno syscall.Errno) {
	fmt.Println("SYMLINK CALLED:", target, name)
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

	encrypted, err := helper.EncryptMessageArmored(G.pubkey, string(name))
	if err != nil {
		panic(err)
	}

	fp.WriteString(encrypted)

	return id
}

func (G *GPGFS) GetName(id string) string {
	filenameFile := filepath.Join(VAULT, ".db", id)
	buf, err := os.ReadFile(filenameFile)
	if err != nil {
		panic(err)
	}
	unencrypted, err := helper.DecryptMessageArmored(G.privkey, []byte(G.password), string(buf))
	if err != nil {
		panic(err)
	}
	return unencrypted
}

func (G *GPGFS) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (node *fs.Inode, fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	errno = fuse.F_OK
	log.Println("GPGFS.Create called:", name)

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
	log.Println("Rename called:", name, newName)

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

func NewEncryptedFilesystem(vault, pubkey, privkey, password string) (*GPGFS, error) {
	VAULT = vault
	return NewGPGFS(vault, pubkey, privkey, password)
}

func NewGPGFS(vault, pubkey, privkey, password string) (*GPGFS, error) {
	if privkey == "" || pubkey == "" || password == "" {
		return nil, fmt.Errorf("private key, public key, and password are required")
	}
	return &GPGFS{vault: vault, pubkey: pubkey, privkey: privkey, password: password, nodes: make(map[string]*GPGFile), dirs: make(map[string]*GPGFS)}, nil
}

func (G *GPGFS) OnAdd(ctx context.Context) {
	log.Println("OnAdd called:", G.vault)
	nodes, err := os.ReadDir(G.vault)
	if err != nil {
		panic(err)
	}
	for _, node := range nodes {
		if node.Name() == ".db" {
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
	log.Println("AddDir called, path:", path)
	name := filepath.Base(path)
	id := G.SaveName(name)
	dir, _ := NewGPGFS(filepath.Join(G.vault, id), G.pubkey, G.privkey, G.password)
	G.dirs[filepath.Base(path)] = dir
	ch := G.NewPersistentInode(ctx, dir, fs.StableAttr{Mode: fuse.S_IFDIR})
	ok := G.AddChild(name, ch, true)
	if !ok {
		panic("could not add child")
	}
	return dir
}

func (G *GPGFS) AddFile(ctx context.Context, path string, node *fs.Inode) {
	log.Println("AddFile called, path:", path)
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
	log.Println("READLINK CALLED:", file.link)
	return []byte(file.link), fuse.F_OK
}

func (G *GPGFS) AddSymlink(ctx context.Context, target string, name string) *fs.Inode {
	path := filepath.Join(G.vault, target)
	gpgfile := NewGPGFile(path, G)
	gpgfile.link = target
	ch := G.NewPersistentInode(ctx, gpgfile, fs.StableAttr{Mode: fuse.S_IFLNK | 0777})
	return ch
}

type GPGFile struct {
	fs.Inode
	root *GPGFS

	dataFile string
	link     string
	data     []byte
	size     int
	modTime  int64
}

func (file *GPGFile) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	p := file.dataFile
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

func (file *GPGFile) Fsync(ctx context.Context, f fs.FileHandle, flags uint32) syscall.Errno {
	log.Println("GPGFile.Fsync:", file.dataFile)
	err := file.SaveData()
	return fs.ToErrno(err)
}

func (file *GPGFile) Flush(ctx context.Context, f fs.FileHandle) syscall.Errno {
	log.Println("GPGFile.Flush called:", file.dataFile)
	return fuse.F_OK
}

func (file *GPGFile) Write(ctx context.Context, f fs.FileHandle, data []byte, off int64) (written uint32, errno syscall.Errno) {
	log.Println("Write: ", file.dataFile, string(data), off)

	file.data = file.data[:off]

	//	file.data = append(file.data, data...)
	file.data = append(file.data, data...)
	file.size = len(file.data)
	file.modTime = time.Now().UnixNano()

	file.Fsync(ctx, nil, 0)
	return uint32(len(data)), fuse.F_OK
}

func (file *GPGFile) Open(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	log.Printf("GPGFile.Open: %s %x", file.dataFile, fuseFlags)
	return nil, fuse.FOPEN_KEEP_CACHE, fuse.F_OK
}

// Read simply returns the data that was already unpacked in the Open call
func (file *GPGFile) Read(ctx context.Context, f fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if file.data == nil {
		file.LoadData()
	}

	end := int(off) + len(dest)
	if end > len(file.data) {
		end = len(file.data)
	}

	return fuse.ReadResultData(file.data[off:end]), fuse.F_OK
}

func NewGPGFile(path string, root *GPGFS) *GPGFile {
	return &GPGFile{dataFile: path, root: root}
}

func (file *GPGFile) SaveData() error {
	fileStat, err := os.Stat(file.dataFile)
	if err != nil {
		return fs.ToErrno(err)
	}
	stat := fileStat.Sys().(*syscall.Stat_t)

	encrypted, err := helper.EncryptMessageArmored(file.root.pubkey, string(file.data))
	if err != nil {
		return err
	}
	err = os.WriteFile(file.dataFile, []byte(encrypted), os.FileMode(stat.Mode))
	if err != nil {
		return err
	}
	return nil
}

func (file *GPGFile) LoadData() error {
	fileStat, err := os.Stat(file.dataFile)
	if err != nil {
		return err
	}
	modTime := fileStat.ModTime().UnixNano()

	// do not reload data if it is already loaded
	//if file.data != nil && modTime == file.modTime {
	//	return nil
	//}

	// read encrypted data
	encrypted, err := os.ReadFile(file.dataFile)
	if err != nil {
		return err
	}

	unencrypted := ""
	if string(encrypted) != "" {
		// decrypt
		unencrypted, err = helper.DecryptMessageArmored(file.root.privkey, []byte(file.root.password), string(encrypted))
		if err != nil {
			return err
		}
	}

	// save attrs to GPGFile node
	file.data = []byte(unencrypted)
	file.size = len(file.data)
	file.modTime = modTime

	return nil
}

// Getattr sets the minimum, which is the size. A more full-featured
// FS would also set timestamps and permissions.
func (file *GPGFile) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	log.Println("Getattr called:", file.dataFile)
	fileStat, err := os.Stat(file.dataFile)
	if err != nil {
		return fs.ToErrno(err)
	}

	if file.data == nil {
		err = file.LoadData()
		if err != nil {
			log.Println("LoadData failed: ", err)
		}
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
	out.Size = uint64(file.size)
	const bs = 512
	out.Blksize = bs
	out.Blocks = (out.Size + bs - 1) / bs

	return fuse.F_OK
}

func (G *GPGFS) Unlink(ctx context.Context, name string) syscall.Errno {
	id := G.GetID(name)
	path := filepath.Join(G.vault, id)
	fmt.Println("GPGFile.Unlink called:", name, path)
	err := syscall.Unlink(path)
	if err != nil {
		log.Println(err)
	}
	return fuse.F_OK
}
