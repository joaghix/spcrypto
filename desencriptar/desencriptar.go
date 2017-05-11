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
	rutaClavePrivada := flag.String("prv", "private.pem", "Nombre de archivo para la clave privada. OBLIGATORIO")
	//tamanyoClave := flag.Int("size", 32, "Tamaño en bytes de la clave aleatoria AES-CTR : 16, 24 o 32")

	flag.Parse()
	if *archivo == "" {
		flag.Usage()
		os.Exit(1)
	}

	DesencriptarArchivo(*archivo, *rutaClavePrivada)
}

// DesencriptarArchivo descompone un archivo encriptado en un archivo plano y metadatos
// a partir de la ruta al archivo de clave privada.
func DesencriptarArchivo(archivo string, rutaClavePrivada string) {

	start := time.Now()
	var objeto ArchivoEstructura

	fmt.Println("Desencriptando...")

	// PASO 1 : DESCOMPONER ARCHIVO CIFRADO EN DATOS CIFRADOS, METADATOS CIFRADOS
	// Y BLOQUE DE SEGURIDAD CIFRADO
	fileCifrado, err1 := os.Open(archivo)
	chk(err1)
	decFichero := gob.NewDecoder(fileCifrado)
	err2 := decFichero.Decode(objeto)
	fileDpPrima := objeto.DpPrima
	fileMpPrima := objeto.MpPrima
	BloqueBsPrima := objeto.BsPrima
	chk(err2)

	// PASO 2 : DESCIFRAR BLOQUE SEGURIDAD
	label := []byte("seguridad") // Se puede usar en el futuro para identificar el bloque
	BloqueBs, err3 := rsa.DecryptOAEP(sha256.New(), rand.Reader, AbrirYExtraerClavePrivada(rutaClavePrivada), BloqueBsPrima, label)
	chk(err3)

	// PASO 3 : DESCOMPONER BLOQUE DE SEGURIDAD
	bSeguridad := GetBloqueSeguridad(BloqueBs)

	// PASO 4 : DESCIFRAR METADATOS
	fileInfoMp, err4 := DecryptAESCTR(bSeguridad.Ksm, fileMpPrima)
	chk(err4)

	// PASO 5 : DESCIFRAR DATOS PLANOS
	fileDp, err5 := DecryptAESCTR(bSeguridad.Ksd, fileDpPrima)
	chk(err5)

	// PASO 6 : OBTENER HASH DATOS Y COMPARACIÓN CON EL HASH DEL BLOQUE DE
	// SEGURIDAD
	hashHp := ObtenerHashSha512(fileDp)

	if esigual := Compare(hashHp, bSeguridad.Hp); esigual == 0 {
		fmt.Printf("Los códigos Hash son idénticos, se mantiene la integridad")
	} else {
		fmt.Printf("Los códigos Hash son diferentes, se han modificado datos")
	}

	// PASO 7 : CONSTRUIR EL ARCHIVO PLANO A PARTIR DEL FICHERO DE DATOS PLANOS
	// Y LOS METADATOS
	// Convertir array de bytes a una string
	archivoPlano := string(fileDp[:])
	metadatos := string(fileInfoMp[:])

	fileDpDestino, fileInfoMpDestino := AbrirYcopiarMetadatosArchivo(archivoPlano, metadatos)

	elapsed := time.Since(start)
	fmt.Printf("Tiempo : %s\n", elapsed.String())
}

// FUNCIONES

// AbrirYExtraerClavePrivada analiza y extrae la clave privada a partir de la
// ruta a un archivo con formato PEM y bloque X509
func AbrirYExtraerClavePrivada(archivoClavePrivada string) *rsa.PrivateKey {

	bytesArchivo, err := ioutil.ReadFile(archivoClavePrivada)
	chk(err)

	bloque, _ := pem.Decode(bytesArchivo)
	if bloque == nil || bloque.Type != "BEGIN PRIVATE KEY" {
		panic("El formato de clave privada no es adecuado")
	}

	prv, err2 := x509.ParsePKCS8PrivateKey(bloque.Bytes)
	chk(err2)

	return prv.(*rsa.PrivateKey)
}

// GetBloqueSeguridad obtiene una estructura tipo BloqueSeguridad que almacenará
// el código Hash y 2 claves aleatorias
func GetBloqueSeguridad(datos []byte) BloqueSeguridad {
	var resultado BloqueSeguridad
	dec := gob.NewDecoder(bytes.NewReader(datos))
	dec.Decode(resultado)

	return resultado
}

// DecryptAESCTR descifra un mensaje cifrado a partir de la clave aleatoria
// que se ha utilizado para cifrarlo
func DecryptAESCTR(clave []byte, mensaje []byte) ([]byte, error) {

	aesBlock, err := aes.NewCipher(clave) // Con la primera parte de la clave
	chk(err)

	iv := make([]byte, aes.BlockSize) // Tamaño del bloque
	aesCtr := cipher.NewCTR(aesBlock, iv)
	resultado := make([]byte, len(mensaje))

	aesCtr.XORKeyStream(resultado, mensaje)

	return resultado, nil
}

// ObtenerHashSha512 calcula la suma SHA-512 a partir de los datos de un archivo
func ObtenerHashSha512(archivo []byte) []byte {
	sha512 := sha512.New()

	/*_, err := io.Copy(sha512, archivo)
	chk(err)*/

	return sha512.Sum(nil)
}

// AbrirYcopiarMetadatos abre el archivo de datos y el archivo metadatos y
// y copia los metadatos en el archivo de datos devolviendo el descriptor
// del archivo de datos y su estructura FileInfo con los metadatos.
func AbrirYcopiarMetadatosArchivo(aDatos string, aMetadatos string) (*os.File, *os.FileInfo) {

	srcFile, err := os.Open(aMetadatos)
	chk(err)
	defer srcFile.Close()

	destFile, err := os.Open(aDatos)
	chk(err)
	defer destFile.Close()

	fileInfo, errM := os.Stat(aDatos)
	chk(errM)

	_, err = io.Copy(destFile, srcFile)
	chk(err)

	err = destFile.Sync()
	chk(err)

	return destFile, &fileInfo
}

// Compare compara si dos arrays de bytes son iguales
func Compare(a, b []byte) int {
	if a == b {
		return 0
	} else {
		return -1
	}
	return +1
}

// chk comprueba errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}
