package benchmarks

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
)

func BenchmarkSQLInsert(b *testing.B) {
	eng, cleanup := bootSQL(b)
	defer cleanup()
	ctx := context.Background()
	if _, err := eng.Exec(ctx, `CREATE TABLE bench (id INT PRIMARY KEY, name VARCHAR(255), age INT)`); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q := fmt.Sprintf(`INSERT INTO bench (id, name, age) VALUES (%d, 'user-%d', %d)`, i, i, i%100)
		if _, err := eng.Exec(ctx, q); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSQLSelectByPK(b *testing.B) {
	eng, cleanup := bootSQL(b)
	defer cleanup()
	ctx := context.Background()
	if _, err := eng.Exec(ctx, `CREATE TABLE bench (id INT PRIMARY KEY, name VARCHAR(255), age INT)`); err != nil {
		b.Fatal(err)
	}
	const n = 10000
	for i := 0; i < n; i++ {
		q := fmt.Sprintf(`INSERT INTO bench (id, name, age) VALUES (%d, 'user-%d', %d)`, i, i, i%100)
		if _, err := eng.Exec(ctx, q); err != nil {
			b.Fatal(err)
		}
	}
	r := rand.New(rand.NewSource(1))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := r.Intn(n)
		q := fmt.Sprintf(`SELECT * FROM bench WHERE id = %d`, id)
		if _, err := eng.Query(ctx, q); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSQLSelectWhereScan(b *testing.B) {
	eng, cleanup := bootSQL(b)
	defer cleanup()
	ctx := context.Background()
	if _, err := eng.Exec(ctx, `CREATE TABLE bench (id INT PRIMARY KEY, name VARCHAR(255), age INT)`); err != nil {
		b.Fatal(err)
	}
	const n = 10000
	for i := 0; i < n; i++ {
		q := fmt.Sprintf(`INSERT INTO bench (id, name, age) VALUES (%d, 'user-%d', %d)`, i, i, i%100)
		if _, err := eng.Exec(ctx, q); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := eng.Query(ctx, `SELECT * FROM bench WHERE age > 50`); err != nil {
			b.Fatal(err)
		}
	}
}
