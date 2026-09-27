package benchmarks

import (
	"bytes"
	"context"
	"testing"
)

func benchEncrypt(b *testing.B, pluginName string, size int) {
	prov, cleanup := bootCrypto(b, pluginName)
	defer cleanup()
	ctx := context.Background()
	payload := bytes.Repeat([]byte("x"), size)

	b.ReportAllocs()
	b.ResetTimer()
	b.SetBytes(int64(size))
	for i := 0; i < b.N; i++ {
		if _, err := prov.Encrypt(ctx, payload, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func benchDecrypt(b *testing.B, pluginName string, size int) {
	prov, cleanup := bootCrypto(b, pluginName)
	defer cleanup()
	ctx := context.Background()
	payload := bytes.Repeat([]byte("x"), size)
	ct, err := prov.Encrypt(ctx, payload, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.SetBytes(int64(size))
	for i := 0; i < b.N; i++ {
		if _, err := prov.Decrypt(ctx, ct, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncrypt_XChaCha20_1KB(b *testing.B) { benchEncrypt(b, "crypto-xchacha", 1<<10) }
func BenchmarkEncrypt_XChaCha20_1MB(b *testing.B) { benchEncrypt(b, "crypto-xchacha", 1<<20) }
func BenchmarkDecrypt_XChaCha20_1KB(b *testing.B) { benchDecrypt(b, "crypto-xchacha", 1<<10) }
func BenchmarkDecrypt_XChaCha20_1MB(b *testing.B) { benchDecrypt(b, "crypto-xchacha", 1<<20) }

func BenchmarkEncrypt_FIPS_1KB(b *testing.B) { benchEncrypt(b, "crypto-fips", 1<<10) }
func BenchmarkEncrypt_FIPS_1MB(b *testing.B) { benchEncrypt(b, "crypto-fips", 1<<20) }
func BenchmarkDecrypt_FIPS_1KB(b *testing.B) { benchDecrypt(b, "crypto-fips", 1<<10) }
func BenchmarkDecrypt_FIPS_1MB(b *testing.B) { benchDecrypt(b, "crypto-fips", 1<<20) }
