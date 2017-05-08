package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"flag"
	"fmt"
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
	var objeto ArchivoEstructura
	var bSeguridad BloqueSeguridad

	flag.Parse()
	if *archivo == "" {
		flag.Usage()
		os.Exit(1)
	}

	DesencriptarArchivo(*archivo, *rutaClavePrivada, objeto, bSeguridad)
}

// DesencriptarArchivo descompone un archivo encriptado en un archivo plano y metadatos
// a partir de la ruta al archivo de clave privada.
func DesencriptarArchivo(archivo string, rutaClavePrivada string, objeto ArchivoEstructura, bSeguridad BloqueSeguridad) {

	start := time.Now()

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
	//bSeguridad, err4 := GetBytes(BloqueBs)
	//hashHp := bSeguridad.Hp
	//chk(err4)

	elapsed := time.Since(start)
	fmt.Printf("Tiempo : %s\n", elapsed.String())
}

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

// chk comprueba errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}
