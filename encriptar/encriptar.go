package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"
	/*

	   "encoding/pem"
	   "crypto/x509" */)

type Metadato struct {
	Name string
	Size int64
}

type BloqueSeguridad struct {
	Hp, Ksd, Ksm []byte
}

type ArchivoEstructura struct {
	Header  [6]byte
	DpPrima []byte
	MpPrima []byte
	BsPrima []byte
}

func main() {
	archivo := flag.String("file", "", "Archivo de datos a encriptar")
	rutaClavePublica := flag.String("pub", "public.key", "Nombre de archivo con la clave pública del usuario")
	destino := flag.String("dest", "", "Nombre de archivo destino")
	tamanyoClave := flag.Int("size", 32, "Tamaño en bytes de la clave aleatoria AES-CTR")

	flag.Parse()
	if *archivo == "" {
		flag.Usage()
		os.Exit(1)
	}

	EncriptarArchivo(*archivo, *rutaClavePublica, *destino, *tamanyoClave)
}

func EncriptarArchivo(archivo string, rutaClavePublica string, destino string, tamanyoClave int) {

	start := time.Now()

	fmt.Println("Encriptando...")

	// PASO 1: OBTENER DATOS ARCHIVOS
	fileDp, fileInfoMp := AbrirYExtraerMetadatosArchivo(archivo)
	defer fileDp.Close()
	fmt.Printf("Nombre : %s\n", (*fileInfoMp).Name())
	fmt.Printf("Tamaño : %d bytes\n", (*fileInfoMp).Size())
	fmt.Printf("TmpPath: %s\n", os.TempDir())

	// PASO 2: OBTENER HASH DATOS
	hashHp := ObtenerHashSha512(fileDp)
	//fmt.Printf("Hash   : %s\n", base64.StdEncoding.EncodeToString(hashHp))

	// PASO 3 : GENERAR CLAVES AES-CTR PARA DATOS
	bytesKsd := make([]byte, tamanyoClave) // La clave de AES + el IV
	_, err3 := rand.Read(bytesKsd)
	//fmt.Printf("Ksd    : %x\n", bytesKsd)
	chk(err3)

	// PASO 4 : GENERAR CLAVES AES-CTR PARA METADATOS
	bytesKsm := make([]byte, tamanyoClave) // La clave de AES + el IV
	_, err4 := rand.Read(bytesKsm)
	//fmt.Printf("Ksm    : %x\n", bytesKsm)
	chk(err4)

	// PASO 5 : CIFRAR DATOS CON AES-CTR
	fileDpPrima, err5 := ioutil.TempFile("", "dpPrima")
	chk(err5)
	defer os.Remove(fileDpPrima.Name()) // Limpieza
	fileDp.Seek(0, 0)
	_, err6 := io.Copy(GetAESCTRWriter(bytesKsd, fileDpPrima), fileDp)
	chk(err6)

	// PASO 6 : CIFRAR METADATOS CON AES-CTR
	fileMpPrima, err7 := ioutil.TempFile("", "mpPrima")
	chk(err7)
	defer os.Remove(fileMpPrima.Name()) // Limpieza
	encMd := gob.NewEncoder(GetAESCTRWriter(bytesKsm, fileMpPrima))
	err8 := encMd.Encode(GetMetadato(*fileInfoMp))
	chk(err8)

	// PASO 7 : CONSTRUIR BLOQUE DE SEGURIDAD
	BloqueBs, err9 := GetBytes(BloqueSeguridad{hashHp, bytesKsd, bytesKsm})
	chk(err9)

	// PASO 8 : CIFRAR BLOQUE SEGURIDAD MEDIANTE RSA
	label := []byte("seguridad") // Se puede usar para identificar el bloque
	BloqueBsPrima, err10 := rsa.EncryptOAEP(sha256.New(), rand.Reader, AbrirYExtraerClavePublica(rutaClavePublica), BloqueBs, label)
	chk(err10)

	// PASO 9 : CONSTRUIR ARCHIVO CIFRADO https://play.golang.org/p/TSN52PtbzL y la lectura https://play.golang.org/p/mNouNnMOwW
	nombreArchivoFinal := (*fileInfoMp).Name() + ".spcr"
	fileFinal, err11 := os.Create(nombreArchivoFinal)
	chk(err11)
	defer fileFinal.Close()

	fileDpPrima.Seek(0, 0)
	bytesDpPrima, _ := ioutil.ReadAll(fileDpPrima)
	fileMpPrima.Seek(0, 0)
	bytesMpPrima, _ := ioutil.ReadAll(fileMpPrima)

	encFinal := gob.NewEncoder(fileFinal)
	err12 := encFinal.Encode(
		ArchivoEstructura{
			[6]byte{0x53, 0x50, 0x43, 0x49, 0x50, 0x54},
			bytesDpPrima,
			bytesMpPrima,
			BloqueBsPrima})
	chk(err12)

	elapsed := time.Since(start)
	fmt.Printf("Tiempo : %s\n", elapsed.String())
}

// GetAESCTRWriter crea un io.Writer que encapsula el cigrado en flujo AES-CTR
func GetAESCTRWriter(clave []byte, fileWriter io.Writer) io.Writer {

	aesBlock, err := aes.NewCipher(clave) // Con la primera parte de la clave
	chk(err)

	iv := make([]byte, aes.BlockSize) // Tamaño del bloque
	aesCtr := cipher.NewCTR(aesBlock, iv[:])

	return &cipher.StreamWriter{S: aesCtr, W: fileWriter}
}

func AbrirYExtraerMetadatosArchivo(archivo string) (*os.File, *os.FileInfo) {

	fileInfo, errM := os.Stat(archivo)
	chk(errM)

	f, err := os.Open(archivo)
	chk(err)

	return f, &fileInfo
}

func AbrirYExtraerClavePublica(archivoClavePublica string) *rsa.PublicKey {

	bytesArchivo, err := ioutil.ReadFile(archivoClavePublica)
	chk(err)

	bloque, _ := pem.Decode(bytesArchivo)
	if bloque == nil || bloque.Type != "RSA PUBLIC KEY" {
		panic("El formato de clave publica no es adecuado")
	}

	pub, err2 := x509.ParsePKIXPublicKey(bloque.Bytes)
	chk(err2)

	return pub.(*rsa.PublicKey)
}

func ObtenerHashSha512(archivo *os.File) []byte {
	sha512 := sha512.New()

	_, err := io.Copy(sha512, archivo)
	chk(err)

	return sha512.Sum(nil)
}

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

func GetMetadato(info os.FileInfo) Metadato {
	return Metadato{info.Name(), info.Size()}
}

func GetBytes(key interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(key)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
