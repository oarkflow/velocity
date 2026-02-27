package velocity

import (
	"fmt"
	"os"
	"time"
)

func Example_putGet() {
	db, _ := NewWithConfig(Config{Path: "./tmpdb_example"})
	defer db.Close()

	_ = db.Put([]byte("foo"), []byte("bar"))
	val, _ := db.Get([]byte("foo"))
	fmt.Println(string(val))
	// Output: bar
}

func Example_putWithTTL() {
	db, _ := NewWithConfig(Config{Path: "./tmpdb_example2"})
	defer db.Close()

	_ = db.PutWithTTL([]byte("temp"), []byte("value"), 2*time.Second)
	ttl, _ := db.TTL([]byte("temp"))
	if ttl > 0 {
		fmt.Println("ttl>0")
	}
	// Wait until expired
	time.Sleep(3 * time.Second)
	_, err := db.Get([]byte("temp"))
	fmt.Println(err != nil)
	// Output:
	// ttl>0
	// true
}

func Example_keys() {
	db, _ := NewWithConfig(Config{Path: "./tmpdb_example3"})
	defer db.Close()

	_ = db.Put([]byte("a:1"), []byte("1"))
	_ = db.Put([]byte("a:2"), []byte("2"))
	_ = db.Put([]byte("b:1"), []byte("3"))

	keys, _ := db.Keys("a:*")
	for _, k := range keys {
		fmt.Println(k)
	}
	// Output:
	// a:1
	// a:2
}

func Example_incrDecr() {
	db, _ := NewWithConfig(Config{Path: "./tmpdb_example4"})
	defer db.Close()

	_ = db.Put([]byte("counter"), []byte("0"))
	v, _ := db.Incr([]byte("counter"), 5)
	fmt.Println(v)
	v2, _ := db.Decr([]byte("counter"), 2)
	fmt.Println(v2)
	// Output:
	// 5
	// 3
}

func Example_keysPage() {
	tmpdir, _ := os.MkdirTemp("", "velocity_example_")
	defer os.RemoveAll(tmpdir)

	db, _ := NewWithConfig(Config{Path: tmpdir})
	defer db.Close()

	for i := 0; i < 10; i++ {
		_ = db.Put([]byte(fmt.Sprintf("k%02d", i)), []byte("x"))
	}
	keys, total := db.KeysPage(2, 3)
	fmt.Println(total, len(keys))
	// Output: 16 3
}
