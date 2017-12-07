package encryptedConfig

import (
	"fmt"
	"strings"
	"testing"
)

type testStruct struct {
	Name        string
	Description string `encrypted:"-"`
	Encrypted   string `encrypted:"true"`
}

type wrongStruct struct {
	NoName           string
	WrongDescription string
	NothingSpecial   int
}

type testReadWriter struct {
	read          string
	written       string
	stringToWrite string
	seeked        int64
	whence        int
}

const EncryptedString = "{\"Name\":\"James Bond\",\"Description\":\"SecretAgent\",\"Encrypted\":\"88FtfVzGcLG0ovDzQQ5vpmyLR45gaX2_Z5s=\"}"
const DecryptedString = "{\"Name\":\"James Bond\",\"Description\":\"SecretAgent\",\"Encrypted\":\"007\"}"
const CompletelyWrongString = "wrongstring No Json"

func (t *testReadWriter) Write(p []byte) (n int, err error) {
	t.written = string(p)
	n = len(t.written)

	return n, nil
}

func (t *testReadWriter) Seek(offset int64, whence int) (int64, error) {
	t.seeked = 0
	t.whence = whence
	return 0, nil
}

func (t *testReadWriter) setStringToWrite(s string) {
	t.stringToWrite = s
}

func (t *testReadWriter) Read(p []byte) (n int, err error) {
	reader := strings.NewReader(t.stringToWrite)
	return reader.Read(p)
}

func TestDoReadDecrypted(t *testing.T) {
	var s testStruct
	trw := testReadWriter{"", "", DecryptedString, 1, 1}
	rw := ConfigReadWriter{&s, &trw, "ASDF"}

	err := rw.DoRead()
	if err != nil {
		fmt.Println(err)
	}
	if s.Name != "James Bond" {
		t.Error("Name could Not Be Load")
	}
	if trw.written == "" {
		t.Error("written should be set!")
	}
	if trw.seeked != 0 {
		t.Error("should be seeked to 0")
	}

}
func TestDoReadEncrypted(t *testing.T) {
	var s testStruct
	trw := testReadWriter{"", "", EncryptedString, 1, 1}
	rw := ConfigReadWriter{&s, &trw, "ASDF"}

	err := rw.DoRead()
	if err != nil {
		fmt.Println(err)
	}
	if s.Name != "James Bond" {
		t.Error("Name could Not Be Load")
	}
	if s.Description != "SecretAgent" {
		t.Error("Description is not read correctly")
	}
	if s.Encrypted != "007" {
		t.Error("Encrypted Field is not read correctly")
	}
	if trw.written != "" {
		t.Error("written should NOT be set!")
	}
	if trw.seeked == 0 {
		t.Error("should not be seeked to 0, because write was not called")
	}
}
func TestDoReadWrongStringToWrongStruct(t *testing.T) {
	var s wrongStruct
	trw := testReadWriter{"", "", CompletelyWrongString, 1, 1}
	rw := ConfigReadWriter{&s, &trw, "ASDF"}

	err := rw.DoRead()
	if err == nil {
		t.Error("Error should be given when no JSON Parsed")
	}
}
func TestDoReadEncryptedToWrongStruct(t *testing.T) {
	var s wrongStruct
	trw := testReadWriter{"", "", EncryptedString, 1, 1}
	rw := ConfigReadWriter{&s, &trw, "ASDF"}

	err := rw.DoRead()
	if err != nil {
		t.Error("Error should be given when no JSON Parsed")
	}
	if s.WrongDescription != "" || s.NothingSpecial != 0 || s.NoName != "" {
		t.Error("no field should be read")
	}
}