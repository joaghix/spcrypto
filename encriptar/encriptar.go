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
)

// Metadato almacena los metadatos del archivo original
type Metadato struct {
	Name string
	Size int64
}

// BloqueSeguridad se compone de Hash, Clave Datos y Clave Metadatos
type BloqueSeguridad struct {
	Hp, Ksd, Ksm []byte
}

// ArchivoEstructura se compone de Header (identifica tipo archivo), datos
// cifrados con AES-CTR, Metadatos cifrados con AES-CTR y Bloque de seguridad
// cifrado con la clave pública RSA facilitada.
type ArchivoEstructura struct {
	Header  [6]byte
	DpPrima []byte
	MpPrima []byte
	BsPrima []byte
}

func main() {
	archivo := flag.String("file", "", "Archivo de datos a encriptar. OBLIGATORIO")
	rutaClavePublica := flag.String("pub", "public.key", "Nombre de archivo con la clave pública del usuario. OBLIGATORIO")
	destino := flag.String("dest", "", "Nombre de archivo destino.")
	tamanyoClave := flag.Int("size", 32, "Tamaño en bytes de la clave aleatoria AES-CTR : 16, 24 o 32")

	flag.Parse()
	if *archivo == "" {
		flag.Usage()
		os.Exit(1)
	}

	EncriptarArchivo(*archivo, *rutaClavePublica, *destino, *tamanyoClave)
}

// EncriptarArchivo produce un archivo encriptado a partir de la ruta de un
// archivo plano, la ruta al archivo de clave pública. Opcioninalmente se puede
// indicar el nombre del archivo destino y el tamaño del bloque AES
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
	bytesKsd := make([]byte, tamanyoClave)
	_, err3 := rand.Read(bytesKsd)
	//fmt.Printf("Ksd    : %x\n", bytesKsd)
	chk(err3)

	// PASO 4 : GENERAR CLAVES AES-CTR PARA METADATOS
	bytesKsm := make([]byte, tamanyoClave)
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
	label := []byte("seguridad") // Se puede usar en el futuro para identificar el bloque
	BloqueBsPrima, err10 := rsa.EncryptOAEP(sha256.New(), rand.Reader, AbrirYExtraerClavePublica(rutaClavePublica), BloqueBs, label)
	chk(err10)

	// PASO 9 : CONSTRUIR ARCHIVO CIFRADO
	nombreArchivoFinal := (*fileInfoMp).Name() + ".spcr"
	if destino != "" {
		nombreArchivoFinal = destino
	}
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
// mediante la clave AES proporcionada y el Writer destino (File, buffer...)
func GetAESCTRWriter(clave []byte, fileWriter io.Writer) io.Writer {

	aesBlock, err := aes.NewCipher(clave) // Con la primera parte de la clave
	chk(err)

	iv := make([]byte, aes.BlockSize) // Tamaño del bloque
	aesCtr := cipher.NewCTR(aesBlock, iv[:])

	return &cipher.StreamWriter{S: aesCtr, W: fileWriter}
}

// AbrirYExtraerMetadatosArchivo abre el archivo origen y devuelve su descriptor
// y una estructura FileInfo con los metadatos.
func AbrirYExtraerMetadatosArchivo(archivo string) (*os.File, *os.FileInfo) {

	fileInfo, errM := os.Stat(archivo)
	chk(errM)

	f, err := os.Open(archivo)
	chk(err)

	return f, &fileInfo
}

// AbrirYExtraerClavePublica analiza y extrae la clave pública a partir de la
// ruta a un archivo con formato PEM y bloque X509
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

// ObtenerHashSha512 calcula la suma SHA-512 a partir de los datos de un archivo
func ObtenerHashSha512(archivo *os.File) []byte {
	sha512 := sha512.New()

	_, err := io.Copy(sha512, archivo)
	chk(err)

	return sha512.Sum(nil)
}

// chk comprueba errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// GetMetadato obtiene un objeto Metadato a partir de FileInfo
func GetMetadato(info os.FileInfo) Metadato {
	return Metadato{info.Name(), info.Size()}
}

// GetBytes obtiene un array con los bytes contenidos en cualquier objeto.
func GetBytes(key interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(key)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
