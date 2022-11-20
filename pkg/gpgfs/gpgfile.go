package gpgfs

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/sheik/gpgfs/pkg/crypto"
	"io"
	"log"
	"os"
	"syscall"
	"time"
)

type GPGFile struct {
	fs.Inode
	root *GPGFS
	enc  *crypto.StreamEncrypter
	dec  *crypto.StreamDecrypter

	dataFile string
	link     string
	data     []byte
	size     int
	modTime  int64
}

func NewGPGFile(path string, root *GPGFS) *GPGFile {
	return &GPGFile{dataFile: path, root: root}
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
	log.Println("Write: ", file.dataFile, off)

	file.data = file.data[:off]

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

func (file *GPGFile) SaveData() error {
	fileStat, err := os.Stat(file.dataFile)
	if err != nil {
		return fs.ToErrno(err)
	}
	stat := fileStat.Sys().(*syscall.Stat_t)

	src := bytes.NewReader(file.data)
	file.enc, err = crypto.NewStreamEncrypter(file.root.password, file.root.password, src)
	if err != nil {
		panic(err)
	}

	encrypted, err := io.ReadAll(file.enc)
	fmt.Printf("encrypted: %x\n", encrypted)

	err = file.SaveMeta()
	if err != nil {
		return err
	}
	/*
		encrypted, err := helper.EncryptMessageArmored(file.root.pubkey, string(file.data))
		if err != nil {
			return err
		}
	*/
	err = os.WriteFile(file.dataFile, encrypted, os.FileMode(stat.Mode))
	if err != nil {
		return err
	}
	return nil
}

func (file *GPGFile) SaveMeta() error {
	meta := file.enc.Meta()
	fmt.Printf("meta: %+v\n", meta)
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	err := enc.Encode(meta)
	if err != nil {
		return err
	}
	err = os.WriteFile(file.dataFile+".meta", buffer.Bytes(), 0600)
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

	// read encrypted data
	encrypted, err := os.ReadFile(file.dataFile)
	if err != nil {
		return err
	}

	var unencrypted []byte
	if string(encrypted) != "" {
		meta := file.GetMeta()
		if meta != nil {
			file.dec, err = crypto.NewStreamDecrypter(file.root.password, file.root.password, *meta, bytes.NewReader(encrypted))
			if err != nil {
				return err
			}
			// decrypt
			unencrypted, err = io.ReadAll(file.dec)
			if err != nil {
				return err
			}
		}
	}

	// save attrs to GPGFile node
	file.data = unencrypted
	file.size = len(file.data)
	file.modTime = modTime

	return nil
}

func (file *GPGFile) GetMeta() *crypto.StreamMeta {
	filenameFile := file.dataFile + ".meta"
	buf, err := os.ReadFile(filenameFile)
	if err != nil {
		return nil
	}
	dec := gob.NewDecoder(bytes.NewReader(buf))
	var meta crypto.StreamMeta
	dec.Decode(&meta)
	return &meta
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
