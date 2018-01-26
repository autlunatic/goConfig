package encryptedConfig

import (
	"encoding/json"
	"fmt"
	"reflect"
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

type SliceOfWrongstruct struct {
	Sws []wrongStruct
}
type SliceOfTestStruct struct {
	Test string
	Sts  []testStruct
}
type NestedStruct struct {
	NestString string
	NestStruct testStruct
}

type testReadWriter struct {
	read          string
	written       string
	stringToWrite string
	truncated     int64
}

const EncryptedString = "{\"Name\":\"James Bond\",\"Description\":\"SecretAgent\",\"Encrypted\":\"88FtfVzGcLG0ovDzQQ5vpmyLR45gaX2_Z5s=\"}"
const DecryptedString = "{\"Name\":\"James Bond\",\"Description\":\"SecretAgent\",\"Encrypted\":\"007\"}"
const DecryptedString2 = "{\"Name\"     :     \"James Bond\"     ,     \"Description\"     :      \"SecretAgent\"     ,     \"Encrypted\":\"007\"}"
const CompletelyWrongString = "wrongstring No Json"

func (t *testReadWriter) Write(p []byte) (n int, err error) {
	t.written = string(p)
	n = len(t.written)

	return n, nil
}

func (t *testReadWriter) setStringToWrite(s string) {
	t.stringToWrite = s
}
func (t *testReadWriter) Truncate(size int64) error {
	t.truncated = size
	return nil
}
func (t *testReadWriter) Seek(size int64, n int) (int64, error) {
	return 0, nil
}

func (t *testReadWriter) Read(p []byte) (n int, err error) {
	reader := strings.NewReader(t.stringToWrite)
	return reader.Read(p)
}

func TestDoReadDecrypted(t *testing.T) {
	var s testStruct
	trw := testReadWriter{"", "", DecryptedString, 0}
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

	if trw.written == DecryptedString {
		t.Errorf("written should NOT be the same as Decrypted! %s==%s ", trw.written, DecryptedString)
	}
}
func TestDoReadEncrypted(t *testing.T) {
	var s testStruct
	trw := testReadWriter{"", "", EncryptedString, 0}
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
}
func TestDoReadWrongStringToWrongStruct(t *testing.T) {
	var s wrongStruct
	trw := testReadWriter{"", "", CompletelyWrongString, 0}
	rw := ConfigReadWriter{&s, &trw, "ASDF"}

	err := rw.DoRead()
	if err == nil {
		t.Error("Error should be given when no JSON Parsed")
	}
}
func TestDoReadEncryptedToWrongStruct(t *testing.T) {
	var s wrongStruct
	trw := testReadWriter{"", "", EncryptedString, 0}
	rw := ConfigReadWriter{&s, &trw, "ASDF"}

	err := rw.DoRead()
	if err != nil {
		t.Error("Error should be given when no JSON Parsed")
	}

	if s.WrongDescription != "" || s.NothingSpecial != 0 || s.NoName != "" {
		t.Error("no field should be read")
	}
}
func TestDoWriteSliceWrongStruct(t *testing.T) {
	var s SliceOfWrongstruct
	s.Sws = append(s.Sws, wrongStruct{"One", "noOne", 1})
	s.Sws = append(s.Sws, wrongStruct{"Two", "noTwo", 2})
	trw := testReadWriter{"", "", EncryptedString, 0}
	rw := ConfigReadWriter{&s, &trw, "ASDF"}

	rw.DoWrite()

	var result SliceOfWrongstruct
	json.Unmarshal([]byte(trw.written), &result)
	if !reflect.DeepEqual(result, s) {
		t.Errorf("read is not equal to written")
	}
}
func TestDoWriteSliceTestStruct(t *testing.T) {
	var s SliceOfTestStruct
	s.Test = "testText"
	s.Sts = append(s.Sts, testStruct{"One", "noOne", "encr1"})
	s.Sts = append(s.Sts, testStruct{"Two", "noTwo", "encr2"})

	trw := testReadWriter{"", "", EncryptedString, 0}
	rw := ConfigReadWriter{&s, &trw, "ASDF"}

	err := rw.DoWrite()
	if err != nil {
		t.Error("Error DoWrite: ", err)
	}

	var result SliceOfTestStruct
	err = json.Unmarshal([]byte(trw.written), &result)
	if err != nil {
		t.Error("Error Unmarshal: ", err)
	}
	if result.Sts[0].Encrypted == "encr1" {
		t.Errorf("Encrypted field is not encrypted")
	}
	if result.Test != "testText" {
		t.Errorf("unmarshal written doesnt return the correct value for Test \"testText\" <> %s", result.Test)
	}
	if err != nil {
		t.Error("no Error expected, but was ", err)
	}
}

func TestDoWriteSliceNestedStruct(t *testing.T) {
	var s NestedStruct
	s.NestString = "testText"
	s.NestStruct = testStruct{"One", "noOne", "encr1"}

	trw := testReadWriter{"", "", EncryptedString, 0}
	rw := ConfigReadWriter{&s, &trw, "ASDF"}

	err := rw.DoWrite()
	if trw.written == "{\"NestString\":\"testText\",\"NestStruct\":{\"Name\":\"One\",\"Description\":\"noOne\",\"Encrypted\":\"encr1\"}}" {
		t.Error("written should not conatin decrypted string!", trw.written)
	}
	if err != nil {
		t.Error("no Error expected, but was ", err)
	}
}
func TestDoWriteSliceTestStructWithLongerStructBefore(t *testing.T) {
	var s SliceOfTestStruct
	s.Test = "testText"
	s.Sts = append(s.Sts, testStruct{"One", "noOne", "encr1"})
	s.Sts = append(s.Sts, testStruct{"Two", "noTwo", "encr2"})

	trw := testReadWriter{"", "", DecryptedString2, -1}
	rw := ConfigReadWriter{&s, &trw, "ASDF"}

	err := rw.DoWrite()
	if err != nil {
		t.Error("Error DoWrite: ", err)
	}
	fmt.Println(s)
	var result SliceOfTestStruct
	err = json.Unmarshal([]byte(trw.written), &result)
	if err != nil {
		t.Error("Error Unmarshal: ", err)
	}
	if result.Sts[0].Encrypted == "encr1" {
		t.Errorf("Encrypted field is not encrypted")
	}
	if result.Test != "testText" {
		t.Errorf("unmarshal written doesnt return the correct value for Test \"testText\" <> %s", result.Test)
	}
	if trw.truncated == -1 {
		t.Errorf("longer read string than written, should be truncated")
	}
	if err != nil {
		t.Error("no Error expected, but was ", err)
	}
}
