// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// deterministicBytes returns size bytes of pseudo-random-looking but
// deterministic data, so tests don't depend on the system RNG for the
// plaintext contents.
func deterministicBytes(size int) []byte {
	out := make([]byte, size)
	// Fill with a simple xorshift pattern so binary content (including NUL
	// bytes) is well represented.
	x := uint32(0x9e3779b9)
	for i := range out {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		out[i] = byte(x)
	}
	return out
}

func encryptTo(t *testing.T, recipient age.Recipient, plaintext []byte) []byte {
	t.Helper()
	out := &bytes.Buffer{}
	w, err := age.Encrypt(out, recipient)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return out.Bytes()
}

func decryptWith(t *testing.T, identity age.Identity, ciphertext []byte) ([]byte, error) {
	t.Helper()
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestRoundTripX25519(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}

	binary := make([]byte, 256)
	for i := range binary {
		binary[i] = byte(i)
	}

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"Empty", []byte{}},
		{"Short", []byte("hello, age")},
		{"BinaryAllBytes", binary},
		{"BinaryWithNULs", append(append([]byte{0, 0, 0}, []byte("abc")...), 0, 0)},
		{"ChunkBoundary", deterministicBytes(64 * 1024)},       // exactly one STREAM chunk
		{"Large512KiB", deterministicBytes(512 * 1024)},        // multiple chunks
		{"LargeNonAligned", deterministicBytes(512*1024 + 13)}, // short final chunk
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext := encryptTo(t, identity.Recipient(), tt.plaintext)
			if len(tt.plaintext) > 0 && bytes.Contains(ciphertext, tt.plaintext) {
				t.Errorf("ciphertext contains plaintext")
			}
			got, err := decryptWith(t, identity, ciphertext)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(got, tt.plaintext) {
				t.Errorf("round-trip mismatch: got %d bytes, want %d", len(got), len(tt.plaintext))
			}
		})
	}
}

func flipChar(c byte) byte {
	if c == 'a' {
		return 'b'
	}
	return 'a'
}

func TestParseMalformedRecipient(t *testing.T) {
	valid, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	validKey := valid.Recipient().String()

	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"Empty", "", "malformed recipient"},
		{"Garbage", "not-a-key", "malformed recipient"},
		{"SecretKeyAsRecipient", valid.String(), "malformed recipient"},
		{"Truncated", validKey[:len(validKey)-5], "malformed recipient"},
		{"BitFlipped", validKey[:len(validKey)-1] + string(flipChar(validKey[len(validKey)-1])), "malformed recipient"},
		{"SSHKey", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqfdhR2RVEjVEQnzcKJyRvQn0qEjhMGJkFjPkVvZqH", "malformed recipient"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := age.ParseX25519Recipient(tt.input)
			if err == nil {
				t.Fatalf("ParseX25519Recipient(%q) succeeded, want error", tt.input)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseMalformedIdentity(t *testing.T) {
	valid, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	validKey := valid.String()

	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"Empty", "", "malformed secret key"},
		{"Garbage", "hunter2", "malformed secret key"},
		{"RecipientAsIdentity", valid.Recipient().String(), "malformed secret key"},
		{"Truncated", validKey[:len(validKey)-5], "malformed secret key"},
		{"LowercasePrefix", strings.ToLower(validKey), "malformed secret key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := age.ParseX25519Identity(tt.input)
			if err == nil {
				t.Fatalf("ParseX25519Identity(%q) succeeded, want error", tt.input)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestDecryptWithWrongIdentity(t *testing.T) {
	alice, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	mallory, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := encryptTo(t, alice.Recipient(), []byte("for alice's eyes only"))

	_, err = decryptWith(t, mallory, ciphertext)
	var noMatch *age.NoIdentityMatchError
	if !errors.As(err, &noMatch) {
		t.Fatalf("Decrypt with wrong identity: got %T (%v), want *age.NoIdentityMatchError", err, err)
	}
	if got := err.Error(); got != "identity did not match any of the recipients: incorrect identity for recipient block" {
		t.Errorf("unexpected error message: %q", got)
	}
}

func TestDecryptTruncatedCiphertext(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := deterministicBytes(200 * 1024) // multiple STREAM chunks
	ciphertext := encryptTo(t, identity.Recipient(), plaintext)

	tests := []struct {
		name string
		// cut is where to truncate the ciphertext.
		cut     int
		wantErr func(err error) bool
	}{
		{"EmptyFile", 0, func(err error) bool {
			return strings.Contains(err.Error(), "failed to read header")
		}},
		{"TruncatedHeader", 50, func(err error) bool {
			return strings.Contains(err.Error(), "failed to read header")
		}},
		// Truncating mid-chunk makes the short final chunk fail authentication.
		{"TruncatedPayload", len(ciphertext) / 2, func(err error) bool {
			return strings.Contains(err.Error(), "failed to decrypt and authenticate payload chunk")
		}},
		// Truncating exactly at a STREAM chunk boundary leaves no final chunk
		// at all, which is reported as an unexpected EOF.
		{"TruncatedAtChunkBoundary", len(ciphertext) - (200*1024%65536 + 16), func(err error) bool {
			return errors.Is(err, io.ErrUnexpectedEOF)
		}},
		{"MissingLastByte", len(ciphertext) - 1, func(err error) bool {
			// The final chunk fails authentication or is short.
			return err != nil && !errors.Is(err, io.EOF)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			truncated := ciphertext[:tt.cut]
			r, err := age.Decrypt(bytes.NewReader(truncated), identity)
			if err == nil {
				_, err = io.ReadAll(r)
			}
			if err == nil {
				t.Fatalf("Decrypt of truncated ciphertext (%d/%d bytes) succeeded",
					tt.cut, len(ciphertext))
			}
			if !tt.wantErr(err) {
				t.Errorf("unexpected error for truncation at %d: %v", tt.cut, err)
			}
		})
	}
}

func TestDecryptCorruptedCiphertext(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := encryptTo(t, identity.Recipient(), []byte("authenticated plaintext"))

	// Flip a bit in the last byte of the payload.
	corrupted := bytes.Clone(ciphertext)
	corrupted[len(corrupted)-1] ^= 0x01

	r, err := age.Decrypt(bytes.NewReader(corrupted), identity)
	if err == nil {
		_, err = io.ReadAll(r)
	}
	if err == nil {
		t.Fatal("Decrypt of corrupted ciphertext succeeded")
	}
	if !strings.Contains(err.Error(), "failed to decrypt and authenticate payload chunk") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestArmorRoundTripConsistency(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := deterministicBytes(300 * 1024) // large enough to wrap many armor lines

	// Encrypt to binary.
	binaryCiphertext := encryptTo(t, identity.Recipient(), plaintext)

	// Encrypt the same plaintext through the armor writer.
	armoredBuf := &bytes.Buffer{}
	aw := armor.NewWriter(armoredBuf)
	w, err := age.Encrypt(aw, identity.Recipient())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close encrypt writer: %v", err)
	}
	if err := aw.Close(); err != nil {
		t.Fatalf("Close armor writer: %v", err)
	}
	armored := armoredBuf.String()

	if !strings.HasPrefix(armored, armor.Header+"\n") {
		t.Errorf("armored output missing header")
	}
	if !strings.HasSuffix(armored, armor.Footer+"\n") {
		t.Errorf("armored output missing footer")
	}

	// The armored ciphertext must decode to a valid age file that decrypts to
	// the same plaintext as the binary path.
	decoded := mustReadAll(t, armor.NewReader(strings.NewReader(armored)))
	got, err := decryptWith(t, identity, decoded)
	if err != nil {
		t.Fatalf("Decrypt armored: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("armored round-trip mismatch: got %d bytes, want %d", len(got), len(plaintext))
	}

	got, err = decryptWith(t, identity, binaryCiphertext)
	if err != nil {
		t.Fatalf("Decrypt binary: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("binary round-trip mismatch: got %d bytes, want %d", len(got), len(plaintext))
	}
}

func mustReadAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return b
}

func TestArmorInvalidHeader(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"WrongType", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", "invalid first line"},
		{"Garbage", "this is not armored data\n", "invalid first line"},
		{"Empty", "", "unexpected EOF"},
		{"MissingFooter", armor.Header + "\nAAAA\n", "unexpected EOF"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := io.ReadAll(armor.NewReader(strings.NewReader(tt.input)))
			if err == nil {
				t.Fatalf("armor.NewReader(%q) succeeded, want error", tt.input)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestConcurrentEncryptDecrypt exercises Encrypt and Decrypt from many
// goroutines with distinct keys and plaintexts, verifying that no state leaks
// between concurrent operations. Run with -race to catch data races.
func TestConcurrentEncryptDecrypt(t *testing.T) {
	const workers = 16

	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			identity, err := age.GenerateX25519Identity()
			if err != nil {
				errs <- fmt.Errorf("worker %d: %w", i, err)
				return
			}
			// Distinct, recognizable plaintext per worker.
			plaintext := bytes.Repeat([]byte(fmt.Sprintf("worker-%02d|", i)), 4096)
			ciphertext := encryptTo(t, identity.Recipient(), plaintext)
			got, err := decryptWith(t, identity, ciphertext)
			if err != nil {
				errs <- fmt.Errorf("worker %d: %w", i, err)
				return
			}
			if !bytes.Equal(got, plaintext) {
				errs <- fmt.Errorf("worker %d: round-trip mismatch", i)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestConcurrentSharedRecipient verifies that a single Recipient value can be
// used concurrently, as recipients are safe for concurrent use.
func TestConcurrentSharedRecipient(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipient := identity.Recipient()

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			plaintext := []byte(fmt.Sprintf("message from worker %d", i))
			ciphertext := encryptTo(t, recipient, plaintext)
			got, err := decryptWith(t, identity, ciphertext)
			if err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(got, plaintext) {
				errs <- fmt.Errorf("worker %d: got %q, want %q", i, got, plaintext)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
