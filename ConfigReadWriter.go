package encryptedConfig

import (
	"encoding/json"
	"github.com/autlunatic/goConfig/encrypting"
	"io"
	"reflect"
)

// ConfigReadWriter takes the necessary infos for the encryption
// please take note that the values are being read to StructToReadWrite
// so you have to pass the pointer of a struct to take effect when reading
type ConfigReadWriter struct {
	StructToReadWrite interface{}
	ReadWriter        io.ReadWriteSeeker
	EncryptKey        string
}

// EncryptedTag shows shows how to tag a value that should be read and written encrypted
// the encrypted tag needs to be set to a value e.g. encrypted:"true"
// no encrypted tag or encrypted:"-" does not encrypt the value
const EncryptedTag = "encrypted"

// DoRead reads the values to the StructToReadWrite
// if it finds an value that is tagged with encrypted:true it automatically writes the Struct encrypted
func (crw *ConfigReadWriter) DoRead() error {

	decoder := json.NewDecoder(crw.ReadWriter)
	err := decoder.Decode(&crw.StructToReadWrite)
	if err != nil {
		return err
	}
	if doCryptingForTaggedFields(crw.StructToReadWrite, crw.EncryptKey, doDecrypting) {
		crw.DoWrite()
	}
	return err
}

// DoWrite encrypts tagged fields and writes it to the writer.
// the ReadWriter is seeked to 0 beause it is optimized to write files and it should not append to the file
func (crw *ConfigReadWriter) DoWrite() error {
	doCryptingForTaggedFields(crw.StructToReadWrite, crw.EncryptKey, doEncrypting)

	bs, err := json.Marshal(crw.StructToReadWrite)
	if err != nil {
		return err
	}

	crw.ReadWriter.Seek(0, io.SeekStart)
	_, err = crw.ReadWriter.Write(bs)
	if err != nil {
		return err
	}

	doCryptingForTaggedFields(crw.StructToReadWrite, crw.EncryptKey, doDecrypting)

	return err
}

func doDecrypting(value reflect.Value, key string) bool {
	if !encrypting.IsEncrypted(value.String(), key) {
		return true
	}
	if value.CanSet() {
		s, err := encrypting.DecryptString(value.String(), key)
		if err != nil {
			return false
		}
		value.SetString(s)
	}
	return false
}
func doEncrypting(value reflect.Value, key string) bool {
	if !encrypting.IsEncrypted(value.String(), key) {
		if value.CanSet() {
			s, err := encrypting.EncryptString(value.String(), key)
			if err != nil {
				return false
			}
			value.SetString(s)
		}
	}
	return false
}

type doCrypting func(reflect.Value, string) bool

func doCryptingForTaggedFields(structToCrypt interface{}, key string, fnCrypt doCrypting) bool {
	unencryptedFieldFound := false
	v := reflect.ValueOf(structToCrypt)
	// if it is a Pointer get the Elem
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() == reflect.Slice {
		for i := 0; i < v.Len(); i++ {
			if doCryptingForTaggedFields(v.Index(i), key, fnCrypt) {
				unencryptedFieldFound = true
			}
		}
	}
	if v.Kind() == reflect.Struct {
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := v.Field(i)
			switch f.Kind() {
			case reflect.Slice:
				if doCryptingForTaggedFields(f.Interface(), key, fnCrypt) {
					unencryptedFieldFound = true
				}
			case reflect.Struct:
				if doCryptingForTaggedFields(f.Addr().Interface(), key, fnCrypt) {
					unencryptedFieldFound = true
				}
			default:
				field := t.Field(i)
				if tagVal, enc := field.Tag.Lookup(EncryptedTag); enc && tagVal != "-" {
					if fnCrypt(f, key) {
						unencryptedFieldFound = true
					}
				}
			}
		}
	}
	return unencryptedFieldFound
}
