package main

import (
	"math/rand"
	"sort"

	"github.com/blinsay/sandpaper/internal/protocol"
)

// drop tags from a response
func dropTags(drop []uint32) func(map[uint32][]byte) ([]byte, error) {
	return func(tags map[uint32][]byte) ([]byte, error) {
		for _, tag := range drop {
			delete(tags, tag)
		}
		return protocol.Encode(tags)
	}
}

// add extra tags to a response
//
// tag values are not checked to see if they're the proper size
func addTags(add map[uint32][]byte) func(map[uint32][]byte) ([]byte, error) {
	return func(tags map[uint32][]byte) ([]byte, error) {
		for tag, payload := range add {
			tags[tag] = payload
		}
		return protocol.EncodeUnsafe(tags, sort.Sort, false)
	}
}

// modify the target tag with the given function
func modifyTag(target uint32, mod func([]byte) []byte) func(map[uint32][]byte) ([]byte, error) {
	return func(tags map[uint32][]byte) ([]byte, error) {
		if val, hasTag := tags[target]; hasTag {
			cpy := make([]byte, len(val))
			copy(cpy, val)
			tags[target] = mod(cpy)
		}
		return protocol.Encode(tags)
	}
}

func scramble(bs []byte) []byte {
	rand.Shuffle(len(bs), func(i, j int) {
		bs[i], bs[j] = bs[j], bs[i]
	})
	return bs
}

// return reversed tags. requires copying protocol.Encode and changing the
// sort order deep in the guts.
func reverseTags(tags map[uint32][]byte) ([]byte, error) {
	return protocol.EncodeUnsafe(tags, func(xs sort.Interface) {
		sort.Sort(sort.Reverse(xs))
	}, true)
}
