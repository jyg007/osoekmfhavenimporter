package main

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki

#include <stdint.h>
#include <ep11.h>
*/
import "C"
import "fmt"
import "os"
import "encoding/hex"
import "osoekmfhavenimporter/ep11"
import "log"
func main() {

    hsmTarget := os.Getenv("EP11_IBM_TARGET_HSM")

    if hsmTarget == "" {
        log.Fatalf("EP11_IBM_TARGET_HSM not set")
    }

    target := ep11.HsmInit(hsmTarget)

    // AES key passed as hex
    aeskey, err := hex.DecodeString(os.Args[1])
    if err != nil {
        log.Fatalf("Invalid key hex: %v", err)
    }

    // 16-byte zero block (AES block size)
    zeroBlock := make([]byte, 16)

    // Encrypt zero block using AES-ECB
    cipher, err := ep11.EncryptSingle(
        target,
        ep11.Mech(C.CKM_AES_ECB, nil),
        aeskey,
        zeroBlock,
    )
    if err != nil {
        log.Fatalf("Encryption failed: %v", err)
    }

    // CENC-0 = first 3 bytes
    cenc0 := cipher[:3]

    fmt.Printf("CENC-0 (3-byte KCV): %x\n", cenc0)
}

