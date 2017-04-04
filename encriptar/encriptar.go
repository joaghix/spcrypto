package main

import (
   "flag"
   "os"
   "fmt"
  /* "crypto/rand"
   "crypto/rsa"
   "encoding/pem"
   "crypto/x509" */
)

 
func main() {
    archivo := flag.String("file", "", "Archivo de datos a encriptar")
    rutaClavePublica := flag.String("pub", "public.key", "Nombre de archivo con la clave pública del usuario")
    destino := flag.String("dest", "", "Nombre de archivo destino")
    tamanyoClave := flag.Int("size", 512, "Tamaño en bytes de la clave aleatoria AES-CTR")

    flag.Parse()
    if *archivo == "" { 
        flag.Usage()
        os.Exit(1)
    }

    EncriptarArchivo(*archivo, *rutaClavePublica, *destino, *tamanyoClave)
}

func EncriptarArchivo(archivo string, rutaClavePublica string, destino string, tamanyoClave int) {

    fmt.Println("Encriptando...")

    // PASO 1: OBTENER DATOS ARCHIVO
    f, fInfo := AbrirYExtraerMetadatosArchivo(archivo)
    
    fmt.Printf("Tamaño : %d bytes\n", (*fInfo).Size)
    if err := f.Close(); err != nil {
	 fmt.Println(err.Error)
	 os.Exit(1)
    }

    // PASO 1: OBTENER DATOS ARCHIVO


}

func AbrirYExtraerMetadatosArchivo(archivo string) (*os.File, *os.FileInfo) {

    fileInfo, errM := os.Stat(archivo)
 	if errM != nil {
	 fmt.Println(errM.Error)
	 os.Exit(1)
	}
    

    f, err := os.OpenFile(archivo, os.O_RDONLY, 0755)
	if err != nil {
	 fmt.Println(err.Error)
	 os.Exit(1)
	}

    return f, &fileInfo
}