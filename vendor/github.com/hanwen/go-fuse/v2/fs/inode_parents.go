// Copyright 2021 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fs

// InodeParents stores zero or more Parents of an Inode,
// remembering which one is the most recent.
//
// No internal locking: the caller is responsible for preventing
// concurrent access.
type InodeParents struct {
	// Newest is the most-recently add()'ed parent.
	// nil when we don't have any Parents.
	Newest *ParentData
	// Other are Parents in addition to the Newest.
	// nil or empty when we have <= 1 Parents.
	Other map[ParentData]struct{}
}

// add adds a parent to the store.
func (p *InodeParents) add(n ParentData) {
	// one and only parent
	if p.Newest == nil {
		p.Newest = &n
	}
	// already known as `Newest`
	if *p.Newest == n {
		return
	}
	// old `Newest` gets displaced into `Other`
	if p.Other == nil {
		p.Other = make(map[ParentData]struct{})
	}
	p.Other[*p.Newest] = struct{}{}
	// new parent becomes `Newest` (possibly moving up from `Other`)
	delete(p.Other, n)
	p.Newest = &n
}

// get returns the most recent parent
// or nil if there is no parent at all.
func (p *InodeParents) get() *ParentData {
	return p.Newest
}

// all returns all known Parents
// or nil if there is no parent at all.
func (p *InodeParents) all() []ParentData {
	count := p.count()
	if count == 0 {
		return nil
	}
	out := make([]ParentData, 0, count)
	out = append(out, *p.Newest)
	for i := range p.Other {
		out = append(out, i)
	}
	return out
}

func (p *InodeParents) delete(n ParentData) {
	// We have zero Parents, so we can't delete any.
	if p.Newest == nil {
		return
	}
	// If it's not the `Newest` it must be in `Other` (or nowhere).
	if *p.Newest != n {
		delete(p.Other, n)
		return
	}
	// We want to delete `Newest`, but there is no Other to replace it.
	if len(p.Other) == 0 {
		p.Newest = nil
		return
	}
	// Move random entry from `Other` over `Newest`.
	var i ParentData
	for i = range p.Other {
		p.Newest = &i
		break
	}
	delete(p.Other, i)
}

func (p *InodeParents) clear() {
	p.Newest = nil
	p.Other = nil
}

func (p *InodeParents) count() int {
	if p.Newest == nil {
		return 0
	}
	return 1 + len(p.Other)
}

type ParentData struct {
	name   string
	parent *Inode
}
