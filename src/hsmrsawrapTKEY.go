/*******************************************************************************
* Copyright 2022 IBM Corp.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

package main


/*
#cgo LDFLAGS: -lep11
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ep11.h>
*/
import "C"
import (
	"osoekmfhavenimporter/ep11"
	"fmt"
	"os"
	"encoding/hex"
	"log"
)


func main() {

	var err error
	rsapk, _  := hex.DecodeString(os.Args[1])
	blob, _  := hex.DecodeString(os.Args[2])

        hsmTarget := os.Getenv("EP11_IBM_TARGET_HSM")

        // Optional: Fallback if the variable is empty
        if hsmTarget == "" {
            log.Fatalf("EP11_IBM_TARGET_HSM not set, using default: %s", hsmTarget)
                
        }

        target := ep11.HsmInit(hsmTarget) 

        blobWrapKey , err  := ep11.WrapKey(target , ep11.Mech(C.CKM_RSA_PKCS_OAEP,ep11.NewOAEPParams(C.CKM_SHA256, C.CKG_MGF1_SHA256,  0, nil )),rsapk,blob)
    
	if err != nil {
		panic(fmt.Errorf("Wrap key error: %s", err))
	}
                
        
	fmt.Printf("%x\n", blobWrapKey)
}
