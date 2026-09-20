// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package armor_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// armorEncrypt encrypts plaintext to id and returns the PEM-armored form.
func armorEncrypt(t *testing.T, plaintext []byte, id *age.X25519Identity) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := armor.NewWriter(&buf)
	enc, err := age.Encrypt(w, id.Recipient())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := enc.Write(plaintext); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("Encrypt Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("armor Close: %v", err)
	}
	return buf.Bytes()
}

func armorDecrypt(t *testing.T, armored []byte, id *age.X25519Identity) []byte {
	t.Helper()
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(armored)), id)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("decrypt read: %v", err)
	}
	return out
}

// TestCIArmorRoundTrip checks armored encryption/decryption across base64 line
// boundary shapes: the WrappedBase64 encoder emits a 64-column (48-byte)
// grid, so payloads must be exercised at multiples and off-by offsets of that
// stride, up to a multi-hundred-KiB size.
func TestCIArmorRoundTrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	// Plaintext sizes chosen to hit every interesting alignment of the 48
	// bytes-per-armor-line grid after the (larger) age header is encoded.
	sizes := []int{0, 1, 47, 48, 49, 64 * 1024, 256*1024 + 48, 600*1024 + 7}
	for _, size := range sizes {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			pt := make([]byte, size)
			if size > 0 {
				if _, err := rand.Read(pt); err != nil {
					t.Fatal(err)
				}
			}
			a := armorEncrypt(t, pt, id)

			if !bytes.HasPrefix(a, []byte(armor.Header+"\n")) {
				t.Error("armored output missing BEGIN header")
			}
			if !bytes.HasSuffix(a, []byte(armor.Footer+"\n")) {
				t.Error("armored output missing END footer")
			}
			// Output must be text: no NUL bytes, no over-long lines.
			for i, line := range bytes.Split(a, []byte("\n")) {
				if bytes.ContainsRune(line, 0) {
					t.Fatalf("NUL byte in armored output at line %d", i)
				}
				if len(line) > 64 && !bytes.HasPrefix(line, []byte("-----")) {
					t.Fatalf("line %d exceeds 64 columns: %d", i, len(line))
				}
			}

			if got := armorDecrypt(t, a, id); !bytes.Equal(got, pt) {
				t.Fatalf("armored round-trip mismatch: %d vs %d bytes", len(got), size)
			}
		})
	}
}

// TestCIArmorMatchesBinary verifies that armoring is a transport-only layer:
// decoding an armored file reproduces the exact binary age ciphertext, which
// then decrypts through the ordinary binary path.
func TestCIArmorMatchesBinary(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	pt := make([]byte, 400*1024+333)
	if _, err := rand.Read(pt); err != nil {
		t.Fatal(err)
	}

	var binary bytes.Buffer
	enc, err := age.Encrypt(&binary, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Write(pt); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}

	var armored bytes.Buffer
	w := armor.NewWriter(&armored)
	if _, err := w.Write(binary.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	decoded, err := io.ReadAll(armor.NewReader(bytes.NewReader(armored.Bytes())))
	if err != nil {
		t.Fatalf("armor decode: %v", err)
	}
	if !bytes.Equal(decoded, binary.Bytes()) {
		t.Fatalf("armor decode did not reproduce binary: %d vs %d bytes", len(decoded), binary.Len())
	}

	// And an age file encrypted straight into the armor writer must decode to
	// the same shape and decrypt successfully.
	direct := armorEncrypt(t, pt, id)
	raw, err := io.ReadAll(armor.NewReader(bytes.NewReader(direct)))
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.Decrypt(bytes.NewReader(raw), id)
	if err != nil {
		t.Fatalf("binary Decrypt of armor-decoded file: %v", err)
	}
	if got, _ := io.ReadAll(r); !bytes.Equal(got, pt) {
		t.Fatal("binary path over armor-decoded bytes mismatch")
	}
}

// TestCIArmorErrors asserts stable, matchable failures for the malformed armor
// inputs that real pipelines can encounter: bad headers, bad base64, truncated
// bodies, and trailing garbage. All reader errors must wrap *armor.Error.
func TestCIArmorErrors(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	good := armorEncrypt(t, bytes.Repeat([]byte("armor-ci-"), 20000), id)

	checkArmorError := func(t *testing.T, name string, data []byte, wantSub string) {
		t.Helper()
		out, err := io.ReadAll(armor.NewReader(bytes.NewReader(data)))
		if err == nil {
			t.Fatalf("%s: expected error, got %d bytes", name, len(out))
		}
		var ae *armor.Error
		if !errors.As(err, &ae) {
			t.Fatalf("%s: error %v (%T) is not *armor.Error", name, err, err)
		}
		if wantSub != "" && !strings.Contains(err.Error(), wantSub) {
			t.Fatalf("%s: error %q does not contain %q", name, err, wantSub)
		}
	}

	t.Run("wrong begin header", func(t *testing.T) {
		bad := bytes.ReplaceAll(good, []byte("BEGIN AGE ENCRYPTED FILE"), []byte("BEGIN AGE ENCRYPTED FILX"))
		checkArmorError(t, "wrong header", bad, "invalid first line")
	})

	t.Run("missing begin header", func(t *testing.T) {
		checkArmorError(t, "missing header", []byte("AAAA\n"+armor.Footer+"\n"), "invalid first line")
	})

	t.Run("bad base64 body", func(t *testing.T) {
		bad := append([]byte(armor.Header+"\n"), good[len(armor.Header)+1:]...)
		// Replace the first body line's content with invalid base64.
		lines := bytes.Split(bad, []byte("\n"))
		lines[1] = []byte("!!!!not base64!!!!")
		checkArmorError(t, "bad base64", bytes.Join(lines, []byte("\n")), "invalid armor")
	})

	t.Run("column limit exceeded", func(t *testing.T) {
		long := append([]byte(armor.Header+"\n"), bytes.Repeat([]byte("A"), 65)...)
		long = append(long, '\n')
		long = append(long, []byte(armor.Footer+"\n")...)
		checkArmorError(t, "long line", long, "column limit exceeded")
	})

	t.Run("truncated before footer", func(t *testing.T) {
		cut := bytes.LastIndex(good, []byte(armor.Footer))
		checkArmorError(t, "truncated", good[:cut], "invalid armor")
	})

	t.Run("garbage closing line", func(t *testing.T) {
		bad := bytes.ReplaceAll(good, []byte(armor.Footer), []byte("-----END AGE ENCRYPTED FILX-----"))
		checkArmorError(t, "bad footer", bad, "invalid closing line")
	})

	t.Run("trailing garbage", func(t *testing.T) {
		bad := append(bytes.Clone(good), []byte("unexpected trailing bytes\n")...)
		checkArmorError(t, "trailing", bad, "trailing data")
	})
}

// TestCIArmorWriteCloseContract checks the writer's idempotence/order errors.
func TestCIArmorWriteCloseContract(t *testing.T) {
	var buf bytes.Buffer
	w := armor.NewWriter(&buf)
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err == nil || !strings.Contains(err.Error(), "already closed") {
		t.Fatalf("want already-closed error, got %v", err)
	}
	if _, err := w.Write([]byte("y")); err == nil || !strings.Contains(err.Error(), "already closed") {
		t.Fatalf("want write-after-close error, got %v", err)
	}
}
