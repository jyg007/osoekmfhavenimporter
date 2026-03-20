package main

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki
#include <stdint.h>
#include <ep11.h>
*/
import "C"
import "fmt"
import "osoekmfhavenimporter/ep11"
import "log"
import "os"

//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func main() { 
    // Retrieve the HSM target from the environment variable
        hsmTarget := os.Getenv("EP11_IBM_TARGET_HSM")

        // Optional: Fallback if the variable is empty
        if hsmTarget == "" {
            log.Fatalf("EP11_IBM_TARGET_HSM not set, using default: %s", hsmTarget)
                
        }

        target := ep11.HsmInit(hsmTarget)
 
      keyTemplate := ep11.Attributes{
    C.CKA_CLASS:       C.CKO_SECRET_KEY,
    C.CKA_KEY_TYPE:    C.CKK_AES,
   	        C.CKA_VALUE_LEN: 32 ,
		C.CKA_UNWRAP: true,
		C.CKA_WRAP: true,
		C.CKA_DECRYPT: true,
		C.CKA_ENCRYPT: true,
                C.CKA_EXTRACTABLE: true,
      }

	var aeskey ep11.KeyBlob
	var csum []byte

       	aeskey, csum ,_ = ep11.GenerateKey(target,
                	ep11.Mech(C.CKM_AES_KEY_GEN, nil),
	                keyTemplate)

	fmt.Printf("Generated Key: %x\n", aeskey)
	fmt.Printf("Csum: %x\n", csum)
}
