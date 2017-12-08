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
	t := reflect.TypeOf(structToCrypt).Elem()
	v := reflect.ValueOf(structToCrypt).Elem()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		f := v.Field(i)

		if f.Kind() == reflect.Slice {
			//r := reflect.ValueOf(f)
			for i := 0; i < f.Len(); i++ {

				if f.Index(i).Kind() == reflect.Struct {
					v := f.Index(i)
					t2 := f.Index(i).Type()
					for i := 0; i < t2.NumField(); i++ {
						field := t2.Field(i)
						f := v.Field(i)
						//Get the field tag value
						if tagVal, enc := field.Tag.Lookup(EncryptedTag); enc && tagVal != "-" {
							unencryptedFieldFound = fnCrypt(f, key)
						}
					}
					//item := f.Index(i).NumField()
					//doCryptingForTaggedFields(&item, key, fnCrypt)
				}
			}
		} else {
			//Get the field tag value
			if tagVal, enc := field.Tag.Lookup(EncryptedTag); enc && tagVal != "-" {
				unencryptedFieldFound = fnCrypt(f, key)
			}
		}
	}

	return unencryptedFieldFound
}
