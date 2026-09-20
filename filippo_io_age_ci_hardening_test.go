// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
)

// encryptTo is a small helper: it encrypts plaintext to the recipient and
// returns the resulting ciphertext.
func encryptTo(t *testing.T, plaintext []byte, r age.Recipient) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("encrypted Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("encrypted Close: %v", err)
	}
	return buf.Bytes()
}

// decryptWith is a small helper: it decrypts ciphertext with the given
// identities and returns the plaintext.
func decryptWith(t *testing.T, ciphertext []byte, ids ...age.Identity) []byte {
	t.Helper()
	r, err := age.Decrypt(bytes.NewReader(ciphertext), ids...)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("decrypted Read: %v", err)
	}
	return out
}

// TestCIX25519RoundTrip exercises the core Encrypt/Decrypt path over the
// plaintext shapes that historically only had happy-path coverage: empty
// input, high-entropy binary data, and a payload several chunks larger than
// the 64 KiB stream chunk size.
func TestCIX25519RoundTrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}

	sizes := []int{
		0,
		1,
		64,
		64 * 1024,      // exactly one stream chunk
		64*1024 + 1,    // straddles a chunk boundary
		512 * 1024,     // several hundred KiB, many chunks
		700*1024 + 123, // unaligned multi-chunk size
	}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			plaintext := make([]byte, size)
			if size > 0 {
				if _, err := rand.Read(plaintext); err != nil {
					t.Fatalf("rand.Read: %v", err)
				}
			}

			ciphertext := encryptTo(t, plaintext, id.Recipient())
			if size > 0 && bytes.Equal(ciphertext, plaintext) {
				t.Fatal("ciphertext is identical to plaintext")
			}

			got := decryptWith(t, ciphertext, id)
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(plaintext))
			}

			// Encryption must be randomized: two encryptions of the same
			// plaintext must not share a wire representation.
			again := encryptTo(t, plaintext, id.Recipient())
			if bytes.Equal(again, ciphertext) {
				t.Fatal("two encryptions of the same plaintext are byte-identical")
			}
		})
	}
}

// TestCIRoundTripStreamingWrites makes sure plaintext fed in many small writes
// decrypts identically to a single-shot write, including writes that never
// align to the chunk size.
func TestCIRoundTripStreamingWrites(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := make([]byte, 300*1024+777)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	for off := 0; off < len(plaintext); {
		n := 1000 + off%4096 // deliberately irregular write sizes
		if off+n > len(plaintext) {
			n = len(plaintext) - off
		}
		if _, err := w.Write(plaintext[off : off+n]); err != nil {
			t.Fatalf("Write at %d: %v", off, err)
		}
		off += n
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if got := decryptWith(t, buf.Bytes(), id); !bytes.Equal(got, plaintext) {
		t.Fatalf("streamed round-trip mismatch: %d vs %d bytes", len(got), len(plaintext))
	}
}

// TestCIBadRecipient pins down the error surface for recipient strings that
// users actually type wrong in CI configs.
func TestCIBadRecipient(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantSub string
	}{
		{"garbage", "not-a-key", "malformed recipient"},
		{"wrong bech32 hrp", "age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "malformed recipient"},
		{"secret key as recipient", "AGE-SECRET-KEY-1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "malformed recipient"},
		{"truncated", "age1qq", "malformed recipient"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := age.ParseX25519Recipient(tc.input)
			if err == nil {
				t.Fatal("ParseX25519Recipient unexpectedly succeeded")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err, tc.wantSub)
			}
		})
	}

	// ParseRecipients reports a stable, line-indexed error, without echoing
	// the (possibly sensitive) line contents for unknown types.
	_, err := age.ParseRecipients(strings.NewReader("# comment\n\nbogus-line\n"))
	if err == nil || !strings.Contains(err.Error(), "error at line 3") {
		t.Fatalf("want line-3 error, got %v", err)
	}
	if strings.Contains(err.Error(), "bogus-line") {
		t.Fatalf("error leaks raw recipient line: %v", err)
	}

	if _, err := age.ParseRecipients(strings.NewReader("# only a comment\n")); err == nil ||
		!strings.Contains(err.Error(), "no recipients found") {
		t.Fatalf("want no recipients found error, got %v", err)
	}
}

// TestCIBadIdentity pins down identity parsing errors, including the fact that
// unknown-type errors must not echo the secret back at the caller.
func TestCIBadIdentity(t *testing.T) {
	const fakeSecret = "AGE-SECRET-KEY-1SUPERSECRETDONOTECHOSUPERSECRETDONOTECHOSUPERSECRETDONOTECHO"

	if _, err := age.ParseX25519Identity("AGE-SECRET-KEY-1qq"); err == nil ||
		!strings.Contains(err.Error(), "malformed secret key") {
		t.Fatalf("want malformed secret key error, got %v", err)
	}

	if _, err := age.ParseIdentities(strings.NewReader("AGE-PLUGIN-SECRET-KEY-1QQ\n")); err == nil ||
		!strings.Contains(err.Error(), "unknown identity type") {
		t.Fatalf("want unknown identity type error, got %v", err)
	}

	_, err := age.ParseIdentities(strings.NewReader(fakeSecret + "\n"))
	if err == nil {
		t.Fatal("ParseIdentities unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "error at line 1") {
		t.Fatalf("want line-1 error, got %v", err)
	}
	if strings.Contains(err.Error(), "SUPERSECRET") {
		t.Fatalf("error leaks secret material: %v", err)
	}

	if _, err := age.ParseIdentities(strings.NewReader("")); err == nil ||
		!strings.Contains(err.Error(), "no identities found") {
		t.Fatalf("want no identities found error, got %v", err)
	}
}

// TestCIDecryptErrors checks stable failures for wrong-key and corrupted /
// truncated ciphertext, which are the operational failures CI needs to detect
// programmatically rather than logging an opaque error.
func TestCIDecryptErrors(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := bytes.Repeat([]byte("age-ci-"), 40000) // multi-chunk payload
	ciphertext := encryptTo(t, plaintext, id.Recipient())

	t.Run("no identities", func(t *testing.T) {
		_, err := age.Decrypt(bytes.NewReader(ciphertext))
		if err == nil || !strings.Contains(err.Error(), "no identities specified") {
			t.Fatalf("want no identities specified error, got %v", err)
		}
	})

	t.Run("wrong identity", func(t *testing.T) {
		_, err := age.Decrypt(bytes.NewReader(ciphertext), other)
		var nme *age.NoIdentityMatchError
		if !errors.As(err, &nme) {
			t.Fatalf("want *NoIdentityMatchError, got %T: %v", err, err)
		}
	})

	t.Run("truncated header", func(t *testing.T) {
		_, err := age.Decrypt(bytes.NewReader(ciphertext[:20]), id)
		if err == nil || !strings.Contains(err.Error(), "failed to read header") {
			t.Fatalf("want header parse error, got %v", err)
		}
	})

	t.Run("truncated payload mid stream", func(t *testing.T) {
		// Drop the tail inside the final chunk. A partial chunk is parsed as
		// the last chunk but fails authentication.
		cut := len(ciphertext) - 100
		r, err := age.Decrypt(bytes.NewReader(ciphertext[:cut]), id)
		if err != nil {
			t.Fatalf("Decrypt setup failed: %v", err)
		}
		_, err = io.ReadAll(r)
		if err == nil || !strings.Contains(err.Error(), "failed to decrypt and authenticate") {
			t.Fatalf("want authentication error for partial final chunk, got %v", err)
		}
	})

	t.Run("truncated final chunk removed", func(t *testing.T) {
		// Plaintext is exactly four full chunks, so the ciphertext ends with
		// a full-length, last-flagged chunk (ChunkSize + 16 AEAD bytes).
		aligned := make([]byte, 4*64*1024)
		ct := encryptTo(t, aligned, id.Recipient())
		const encryptedChunkSize = 64*1024 + 16
		r, err := age.Decrypt(bytes.NewReader(ct[:len(ct)-encryptedChunkSize]), id)
		if err != nil {
			t.Fatalf("Decrypt setup failed: %v", err)
		}
		if _, err := io.ReadAll(r); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("want io.ErrUnexpectedEOF when the final chunk is gone, got %v", err)
		}
	})

	t.Run("flipped ciphertext byte", func(t *testing.T) {
		tampered := bytes.Clone(ciphertext)
		tampered[len(tampered)-50] ^= 0xFF
		r, err := age.Decrypt(bytes.NewReader(tampered), id)
		if err != nil {
			t.Fatalf("Decrypt setup failed: %v", err)
		}
		_, err = io.Copy(io.Discard, r)
		if err == nil ||
			(!strings.Contains(err.Error(), "failed to decrypt and authenticate") &&
				!errors.Is(err, io.ErrUnexpectedEOF)) {
			t.Fatalf("want authentication failure on tampered payload, got %v", err)
		}
	})

	t.Run("flipped header byte", func(t *testing.T) {
		tampered := bytes.Clone(ciphertext)
		tampered[5] ^= 0xFF
		_, err := age.Decrypt(bytes.NewReader(tampered), id)
		if err == nil {
			t.Fatal("tampered header unexpectedly decrypted")
		}
	})
}

// TestCIConcurrentEncryptDecrypt hammers Encrypt/Decrypt from many goroutines
// with distinct plaintexts and distinct keys, asserting no cross-talk. The
// streaming API documents no global state, so concurrent use must be safe.
func TestCIConcurrentEncryptDecrypt(t *testing.T) {
	const workers = 32
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		w := w
		go func() {
			defer wg.Done()
			id, err := age.GenerateX25519Identity()
			if err != nil {
				errCh <- err
				return
			}
			// Distinct, worker-specific content and size.
			pt := bytes.Repeat([]byte{byte('A' + w%26), byte(w), byte(0xFF - byte(w))}, 50000+w*137)
			ct := encryptTo(t, pt, id.Recipient())
			got := decryptWith(t, ct, id)
			if !bytes.Equal(got, pt) {
				errCh <- fmt.Errorf("worker %d: plaintext mismatch (%d vs %d bytes)", w, len(got), len(pt))
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}
