package gpgfs

import (
	"context"
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"os"
	"sync"
	"syscall"
	"time"
)

var _ = (fs.NodeOnAdder)((*GPGRoot)(nil))
var _ = (fs.NodeFsyncer)((*GPGFile)(nil))
var _ = (fs.NodeWriter)((*GPGFile)(nil))
var _ = (fs.NodeCreater)((*GPGRoot)(nil))
var _ = (fs.NodeUnlinker)((*GPGFile)(nil))
var _ = (fs.NodeRenamer)((*GPGFile)(nil))

type GPGRoot struct {
	fs.Inode
	root string

	pubKey     []byte
	privKey    []byte
	passPhrase []byte
}

func (r *GPGRoot) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	fmt.Println("READLINK CALLED")
	return nil, fuse.F_OK
}

func (r *GPGRoot) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	fmt.Println("setattr called:", *in, *out)
	return fuse.F_OK
}

func (r *GPGRoot) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	p := newParent.(*GPGRoot)

	ch := r.EmbeddedInode().GetChild(name)
	gpgfile := &GPGFile{
		Inode: *ch,
		file:  newName,
		name:  newName,
		root:  p,
		info:  fuse.Attr{},
	}
	node := r.NewInode(ctx, gpgfile, fs.StableAttr{})
	p.EmbeddedInode().AddChild(newName, node, true)
	//	r.RmChild(name)
	/*
		ch := r.EmbeddedInode().GetChild(name)
		if ch == nil {
			fmt.Println("OH NO ITS NIL")
		}

		fmt.Println(r.Inode.RmChild(name))

		fmt.Println(p.Inode.AddChild(newName, node, true))
		gpgfile.Flush(ctx, gpgfile.file)
	*/

	fmt.Println("GPGRoot.Rename called:", name, newName)
	err := os.Rename(r.GetPath()+"/"+name, r.GetPath()+"/"+newName)
	if err != nil {
		fmt.Println("error renaming:", err)
	}

	return fs.ToErrno(err)
}

func (r *GPGRoot) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (node *fs.Inode, errno syscall.Errno) {
	fmt.Println("SYMLINK CALLED:", target, name)
	ch := r.NewPersistentInode(ctx, NewGPGFile(), fs.StableAttr{Mode: fuse.S_IFLNK | 0777})
	r.AddChild(name, ch, true)
	return ch, fuse.F_OK
}

func (r *GPGRoot) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	fmt.Println("GPGRoot.Mkdir called:", name, mode)
	path := r.GetPath()
	err := os.Mkdir(path+name, 0755)
	if err != nil {
		fmt.Println("error creating directory:", err)
	}
	node := r.NewInode(ctx, &GPGRoot{
		Inode:      fs.Inode{},
		root:       r.GetPath() + name,
		pubKey:     r.pubKey,
		privKey:    r.privKey,
		passPhrase: r.passPhrase,
	}, fs.StableAttr{Mode: fuse.S_IFDIR})
	r.AddChild(name, node, true)

	return node, fs.ToErrno(err)
}

func (r *GPGRoot) GetPath() string {
	var name string
	root := &r.Inode
	path := ""
	for root != nil {
		name, root = root.Parent()
		path = name + "/" + path
	}
	path = "./vault/" + path
	return path
}

func (r *GPGRoot) Unlink(ctx context.Context, filename string) syscall.Errno {
	fmt.Println("GPGRoot.Unlink:", filename)
	path := r.GetPath()
	fmt.Println("UNLINK: ", path+"/"+filename)
	err := os.Remove(path + "/" + filename)
	if err != nil {
		fmt.Println(err)
	}
	r.RmChild(filename)
	return fs.ToErrno(err)
}

func (r *GPGRoot) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (node *fs.Inode, fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	errno = fuse.F_OK
	fmt.Println("Create:", r.GetPath()+"/"+name)
	fp, err := os.OpenFile(r.GetPath()+"/"+name, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}
	node = r.NewInode(ctx, &GPGFile{file: name, root: r, name: name}, fs.StableAttr{})
	r.AddChild(name, node, true)
	fh = fp
	return
}

func (r *GPGRoot) Fsync(ctx context.Context, f fs.FileHandle, flags uint32) syscall.Errno {
	fmt.Println("GPGRoot.Fsync was called", f)
	return syscall.F_OK
}

func (r *GPGRoot) OnAdd(ctx context.Context) {
	fmt.Println("GPGRoot.OnAdd was called")
	c, err := os.ReadDir(r.root)
	if err != nil {
		panic(err)
	}
	p := &r.Inode

	for _, f := range c {
		if f.IsDir() {
			continue
		}
		gpgfile := &GPGFile{root: r, file: r.GetPath() + "/" + f.Name(), name: f.Name()}
		ch := p.NewPersistentInode(ctx, gpgfile, fs.StableAttr{})
		r.Inode.AddChild(f.Name(), ch, true)
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

type GPGFile struct {
	fs.Inode
	file string
	name string
	mu   sync.Mutex
	data []byte
	root *GPGRoot
	link string
	info fuse.Attr
}

func (file *GPGFile) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (node *fs.Inode, errno syscall.Errno) {
	fmt.Println("LINK CALLED:", name)
	return nil, fuse.F_OK
}

func (file *GPGFile) CopyFileRange(ctx context.Context, fhIn fs.FileHandle, offIn uint64, out *fs.Inode, fhOut fs.FileHandle, offOut uint64, len uint64, flags uint64) (uint32, syscall.Errno) {
	fmt.Println("COPY CALLED!")
	return 0, 0
}

func (file *GPGFile) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	fmt.Println("GPGFile.setattr called:", *in, *out)
	return fuse.F_OK
}

func (file *GPGFile) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	fmt.Println("RENAME:", name, newName)
	err := os.Rename(name, newName)
	return fs.ToErrno(err)
}

func NewGPGFile() *GPGFile {
	gpgfile := &GPGFile{Inode: fs.Inode{}}
	gpgfile.Parents = fs.InodeParents{
		Newest: nil,
		Other:  make(map[fs.ParentData]struct{}),
	}
	return gpgfile
}

func (file *GPGFile) Flush(ctx context.Context, f fs.FileHandle) syscall.Errno {
	fmt.Println("GPGFile.Flush called")
	encrypted, err := helper.EncryptMessageArmored(string(file.root.pubKey), string(file.data))
	if err != nil {
		fmt.Println("error writing file:", err)
		return fs.ToErrno(err)
	}
	err = os.WriteFile(file.GetStorageLocation(), []byte(encrypted), 0644)
	if err != nil {
		fmt.Println("error writing file:", err)
		return fs.ToErrno(err)
	}
	return fuse.F_OK
}

func (file *GPGFile) GetStorageLocation() string {
	return file.root.GetPath() + "/" + file.name
}

func (file *GPGFile) Unlink(ctx context.Context, name string) syscall.Errno {
	fmt.Println("GPGFile.Unlink called:", name)
	return fuse.F_OK
}

func (file *GPGFile) Write(ctx context.Context, f fs.FileHandle, data []byte, off int64) (written uint32, errno syscall.Errno) {
	fmt.Println("GPGFile.Write was called:", file.file)
	file.data = append(file.data, data...)
	encrypted, err := helper.EncryptMessageArmored(string(file.root.pubKey), string(file.data))
	if err != nil {
		fmt.Println("error writing file:", err)
		return 0, fs.ToErrno(err)
	}
	err = os.WriteFile(file.GetStorageLocation(), []byte(encrypted), 0644)
	if err != nil {
		fmt.Println("error writing file:", err)
		return 0, fs.ToErrno(err)
	}
	return uint32(len(data)), syscall.F_OK
}

func (file *GPGFile) Fsync(ctx context.Context, f fs.FileHandle, flags uint32) syscall.Errno {
	fmt.Println("GPGRoot.Fsync was called", f)
	encrypted, err := helper.EncryptMessageArmored(string(file.root.pubKey), string(file.data))
	if err != nil {
		fmt.Println("error writing file:", err)
		return fs.ToErrno(err)
	}
	err = os.WriteFile(file.GetStorageLocation(), []byte(encrypted), 0644)
	if err != nil {
		fmt.Println("error writing file:", err)
		return fs.ToErrno(err)
	}
	return fuse.F_OK
}

// Getattr sets the minimum, which is the size. A more full-featured
// FS would also set timestamps and permissions.
func (file *GPGFile) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	path := file.root.GetPath() + "/" + file.file
	if file.link != "" {
		path = file.root.GetPath() + "/" + file.link
	}
	fileStat, err := os.Stat(path)
	if err != nil {
		out.Mode = 0644
		out.Nlink = 1
		out.Mtime = uint64(time.Now().Unix())
		out.Atime = out.Mtime
		out.Ctime = out.Mtime
		out.Owner = struct {
			Uid uint32
			Gid uint32
		}{Uid: 1000, Gid: 1000}
		out.Size = 0
		const bs = 512
		out.Blksize = bs
		out.Blocks = (out.Size + bs - 1) / bs
		return 0
	}
	out.Mode = 0644
	out.Nlink = 1
	out.Mtime = uint64(fileStat.ModTime().Unix())
	out.Atime = out.Mtime
	out.Ctime = out.Mtime
	out.Owner = struct {
		Uid uint32
		Gid uint32
	}{Uid: 1000, Gid: 1000}
	out.Size = file.GetSize()
	const bs = 512
	out.Blksize = bs
	out.Blocks = (out.Size + bs - 1) / bs
	return 0
}

// Open lazily unpacks zip data
func (file *GPGFile) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	fmt.Println("GPGFile.Open was called:", file.file)
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

func (file *GPGFile) GetSize() uint64 {
	if file.data != nil {
		return uint64(len(file.data))
	}
	unencrypted, err := os.ReadFile(file.file)
	if err != nil {
		fmt.Println("unable to get size:", err, file.file)
		return 0
	}
	decrypted, err := helper.DecryptMessageArmored(string(file.root.privKey), file.root.passPhrase, string(unencrypted))
	if err != nil {
		fmt.Println("unable to get size:", err, file.file)
		return 0
	}
	file.data = []byte(decrypted)
	return uint64(len([]byte(decrypted)))
}

// Read simply returns the data that was already unpacked in the Open call
func (file *GPGFile) Read(ctx context.Context, f fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	fmt.Println("GPGFile.Read was called")
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
