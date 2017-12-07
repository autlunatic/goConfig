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
	if crw.decryptTaggedFields() {
		crw.DoWrite()
	}
	return err
}

// DoWrite encrypts tagged fields and writes it to the writer.
// the ReadWriter is seeked to 0 beause it is optimized to write files and it should not append to the file
func (crw *ConfigReadWriter) DoWrite() error {
	crw.encryptTaggedFields()

	bs, err := json.Marshal(crw.StructToReadWrite)
	if err != nil {
		return err
	}

	crw.ReadWriter.Seek(0, io.SeekStart)
	_,err = crw.ReadWriter.Write(bs)
	if err != nil {
		return err
	}

	crw.decryptTaggedFields()

	return err
}

func (crw *ConfigReadWriter) encryptTaggedFields() {
	t := reflect.TypeOf(crw.StructToReadWrite).Elem()
	v := reflect.ValueOf(crw.StructToReadWrite).Elem()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		//Get the field tag value
		if tagVal,enc := field.Tag.Lookup(EncryptedTag); enc && tagVal != "-"{
			if !encrypting.IsEncrypted(v.Field(i).String(), crw.EncryptKey) {
				if v.Field(i).CanSet() {
					s, _ := encrypting.EncryptString(v.Field(i).String(), crw.EncryptKey)
					v.Field(i).SetString(s)
				}
			}
		}
	}
}

func (crw *ConfigReadWriter) decryptTaggedFields() bool {
	t := reflect.TypeOf(crw.StructToReadWrite).Elem()
	v := reflect.ValueOf(crw.StructToReadWrite).Elem()
	unencryptedFieldFound := false
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		// Get the field tag value
		if value,enc := field.Tag.Lookup(EncryptedTag); enc && value != "-" {
			if v.Field(i).CanSet() {
				if !encrypting.IsEncrypted(v.Field(i).String(), crw.EncryptKey) {
					unencryptedFieldFound = true
					continue
				}
				s, err := encrypting.DecryptString(v.Field(i).String(), crw.EncryptKey)
				if err != nil {
					unencryptedFieldFound = true
					continue
				}
				v.Field(i).SetString(s)
			}
		}
	}
	return unencryptedFieldFound
}
