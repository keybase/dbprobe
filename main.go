package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	humanize "github.com/dustin/go-humanize"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
)

type ObjType byte

var dbNameMap = map[ObjType]string{
	0x00: "DBUser",
	0x0f: "DBSig",
	0x10: "DBTeamChain",
	0x19: "DBUserPlusAllKeysV1",
	0xbe: "DBOfflineRPC",
	0xbf: "DBChatCollapses",
	0xca: "DBMerkleAudit",
	0xcb: "DBUnfurler",
	0xcc: "DBStellarDisclaimer",
	0xcd: "DBFTLStorage",
	0xce: "DBTeamAuditor",
	0xcf: "DBAttachmentUploader",
	0xd0: "DBHasRandomPW",
	0xda: "DBDiskLRUEntries",
	0xdb: "DBDiskLRUIndex",
	0xdc: "DBImplicitTeamConflictInfo",
	0xdd: "DBUidToFullName",
	0xde: "DBUidToUsername",
	0xdf: "DBUserPlusKeysVersioned",
	0xe0: "DBLink",
	0xe1: "DBLocalTrack",
	0xe3: "DBPGPKey",
	0xe4: "DBSigHints",
	0xe5: "DBProofCheck",
	0xe6: "DBUserSecretKeys",
	0xe7: "DBSigChainTailPublic",
	0xe8: "DBSigChainTailSemiprivate",
	0xe9: "DBSigChainTailEncrypted",
	0xea: "DBChatActive",
	0xeb: "DBUserEKBox",
	0xec: "DBTeamEKBox",
	0xed: "DBChatIndex",
	0xf0: "DBMerkleRoot",
	0xf1: "DBTrackers",
	0xf2: "DBGregor",
	0xf3: "DBTrackers2",
	0xf4: "DBTrackers2Reverse",
	0xf5: "DBNotificationDismiss",
	0xf6: "DBChatBlockIndex",
	0xf7: "DBChatBlocks",
	0xf8: "DBChatOutbox",
	0xf9: "DBChatInbox",
	0xfa: "DBIdentify",
	0xfb: "DBResolveUsernameToUID",
	0xfc: "DBChatBodyHashIndex",
	0xfd: "DBMerkleStore",
	0xfe: "DBChatConvFailures",
	0xff: "DBTeamList",
}

const (
	// large sample db
	sampleDBFile = "/tmp/keybase.leveldb"
)

// find key dist
// get most frequent key(s)
// avg Get/Put/Size on disk for keys (compact all at the end for size

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		fmt.Printf("usage main.go <path/to/db.leveldb> \n")
		os.Exit(3)
	}
	calculateFreqs(args[0])
}

func calculateFreqs(path string) {
	db, err := leveldb.OpenFile(path, &opt.Options{
		ErrorIfMissing: true,
	})
	if err != nil {
		panic(err)
	}
	defer db.Close()

	freqMap, err := getKeyFreqs(db)
	if err != nil {
		panic(err)
	}
	fmt.Printf("found %d key types in db\n", len(freqMap))

	type dbFreq struct {
		k    ObjType
		size int64
		v    int
	}

	freqs := []dbFreq{}
	for k, v := range freqMap {
		sizes, err := db.SizeOf([]util.Range{keyRange(k)})
		if err != nil {
			fmt.Printf("unable to get size for:%s %v", dbNameMap[k], err)
			continue
		}
		freq := dbFreq{
			k:    k,
			v:    v,
			size: sizes.Sum(),
		}
		freqs = append(freqs, freq)
	}
	sort.Slice(freqs, func(i, j int) bool { return freqs[i].size > freqs[j].size })
	for _, p := range freqs {
		name, ok := dbNameMap[p.k]
		if !ok {
			continue
		}
		fmt.Printf("%s: count: %d, size: %v\n", name, p.v, humanize.Bytes(uint64(p.size)))
	}
}

func getKeyFreqs(db *leveldb.DB) (freqs map[ObjType]int, err error) {
	iter := db.NewIterator(nil, nil)
	defer iter.Release()
	freqs = make(map[ObjType]int)
	for i := 0; iter.Next(); i++ {
		ldbKey := iter.Key()
		oKey, err := DbKeyParseTyp(string(ldbKey))
		if err != nil {
			s := strings.Split(string(ldbKey), ":")
			fmt.Printf("unable to parse key %q, %s, %v\n", ldbKey, s, err)
			continue
		}
		freqs[oKey]++
		if i > 0 && i%100000 == 0 {
			fmt.Printf("found %d keys so far\n", i)
		}
	}
	return freqs, iter.Error()
}

func keyRange(objTyp ObjType) util.Range {
	prefix := func(o ObjType) []byte {
		return []byte(fmt.Sprintf("kv:%02x:", o))
	}

	return util.Range{
		Start: prefix(objTyp),
		Limit: prefix(objTyp + 1),
	}
}

var fieldExp = regexp.MustCompile(`[a-f0-9]{2}`)

// derived from libkb's DbKeyParse
func DbKeyParseTyp(s string) (ObjType, error) {
	v := strings.Split(s, ":")
	if len(v) < 3 {
		return 0, fmt.Errorf("expected 3 colon-separated fields, found %d", len(v))
	}

	if !fieldExp.MatchString(v[1]) {
		return 0, fmt.Errorf("2nd field should be a 1-byte hex string")
	}

	b, err := strconv.ParseUint(v[1], 16, 8)
	if err != nil {
		return 0, err
	}
	return ObjType(b), nil
}
