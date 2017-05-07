package main

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
