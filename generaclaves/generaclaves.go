package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
)

func main() {
	password := flag.String("pwd", "", "Password para proteger la clave privada. OBLIGATORIO")
	tamanyoClave := flag.Int("size", 4096, "Tamaño en bytes de la clave privada RSA")
	rutaClavePrivada := flag.String("prv", "private.pem", "Nombre de archivo para la clave privada")
	rutaClavePublica := flag.String("pub", "public.key", "Nombre de archivo para la clave pública")

	flag.Parse()
	if *password == "" {
		flag.Usage()
		os.Exit(1)
	}

	GenerarArhvivosClave(*tamanyoClave, *rutaClavePrivada, *rutaClavePublica, *password)
}

func GenerarArhvivosClave(bytes int, nombreClavePrivada string, nombreClavePublica string, passwordPrivada string) {

	// Generamos la clave privada
	privatekey, err := GenerarParClavesRSA(bytes)

	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// Guardamos la clave pública del usuario.
	err = GuardarClavePublica(&privatekey.PublicKey, nombreClavePublica)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// Guardamos la clave privada en un archivo tipo PEM
	err = GuardarPEMClavePrivada(privatekey, nombreClavePrivada, passwordPrivada)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func GuardarPEMClavePrivada(clavePrivada *rsa.PrivateKey, nombreArchivo string, password string) error {

	// Guardamos la clave privada en un archivo tipo PEM
	archivoPem, err := os.Create(nombreArchivo)
	if err != nil {
		return err
	}

	bloque := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(clavePrivada),
	}

	// Si se proporciona contraseña, encriptamos el bloque mediante AES
	if password != "" {
		bloque, err = x509.EncryptPEMBlock(rand.Reader, bloque.Type, bloque.Bytes, []byte(password), x509.PEMCipherAES256)
		if err != nil {
			return err
		}
	}

	err = pem.Encode(archivoPem, bloque)
	if err != nil {
		return err
	}

	archivoPem.Close()
	return nil
}

func GuardarClavePublica(clavePublica *rsa.PublicKey, nombre string) error {

	publickeyfile, err := os.Create(nombre)
	if err != nil {
		return err
	}

	formatoPKIX, err := x509.MarshalPKIXPublicKey(clavePublica)
	if err != nil {
		return err
	}

	bloque := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: formatoPKIX,
	}

	err = pem.Encode(publickeyfile, bloque)
	if err != nil {
		return err
	}

	publickeyfile.Close()
	return nil
}

// Genera un par de claves RSA del tamaño solicitado
func GenerarParClavesRSA(bits int) (*rsa.PrivateKey, error) {

	clave, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return clave, nil

}
