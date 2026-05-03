package fim

import (
	"encoding/json"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

var snapBucket = []byte("snapshots")

type store struct {
	db *bolt.DB
}

type snapRecord struct {
	Hash string `json:"hash"`
	Size int64  `json:"size"`
	Mode uint32 `json:"mode"`
}

func openStore(path string) (*store, error) {
	if path == "" {
		path = defaultStatePath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, err
	}
	s := &store{db: db}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(snapBucket)
		return err
	}); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func (s *store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *store) LoadAll() map[string]snap {
	out := map[string]snap{}
	if s == nil || s.db == nil {
		return out
	}
	_ = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(snapBucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var rec snapRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return nil
			}
			out[string(k)] = snap{
				hash: rec.Hash,
				size: rec.Size,
				mode: os.FileMode(rec.Mode),
			}
			return nil
		})
	})
	return out
}

func (s *store) Put(path string, sn snap) error {
	if s == nil || s.db == nil {
		return nil
	}
	rec := snapRecord{Hash: sn.hash, Size: sn.size, Mode: uint32(sn.mode)}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(snapBucket)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(path), b)
	})
}

func (s *store) Delete(path string) error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(snapBucket)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(path))
	})
}
