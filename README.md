#  EKMF Addon for OSO Haven Plugins

## 1. Preparing for import

### 1.1 As EKMF admin, Generate an OSO RSA Public key to prepare EKMF export file

You need to send the request to the addon.  This is expected to be processed asynchronously during the OSO iteration.

Make sure `ekmfimportserver` is running in `frontend` mode and in `backend` mode in two distinct terminal.  No logs are generated during this action.

```
./EKMF_GetRSAPKey.sh
```
```
{"status":"RSA key pair request registered"}
```


### 1.2 As OSO operator, Simulate OSO Empty iteration #1

Iteration is immediately processed in this environemnt.
You can stop and start the OSO frontend plugin to simulate the OSO iteration.

#### Check FrontEnd OSO Plugin:

```
2026-03-20 06:21:26,208 [INFO] Retrieved 1 documents from server.
2026-03-20 06:21:26,211 [INFO] Successfully wrote 1 documents to INPUTBRIGDEOSMSGS
2026-03-20 06:21:26,211 [INFO] Saved document ID=rsa-1774002086208502800, len=17, snippet=EKMFGENRSAKEYPAIR

```

Check mocked internal created OSO documents as used in confirmation queues and bridges:

```
jq -r . INPUTBRIGDEOSMSGS.PREITERATION
```
```
[
    {
        "id": "rsa-1774002086208502800",
        "content": "EKMFGENRSAKEYPAIR",
        "signature": "",
        "metadata": "EKMFIMPORT"
    }
]
```

OSO documents are moved to input bridge and picked up by backend oso plugin when started.

#### Start OSO Iteration

```
./OSO_StartIteration.sh
```

#### Check BackEnd OSO Plugin:


```
2026-03-20 06:25:19,431 [INFO] Loaded 1 documents from INPUTBRIGDEOSMSGS
2026-03-20 06:25:19,431 [INFO] Condition met for ID: rsa-1774002086208502800. Sending POST request...
2026-03-20 06:25:19,581 [INFO] Successfully processed ID: rsa-1774002086208502800
2026-03-20 06:25:19,581 [INFO] Criteria for final Batch process not met (requires both IMPORT types).
```

You can check results to be send in either via OSO logs or via OSO documents

```
jq -r . OUTPUTBRIDGEMSGS
```
```
{
  "content": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0AVMMTfwdSrum1BJC7jK\n/zG6iPCRqG+RwbQR/BhY2Qf2iLhlOUJh1sGfVAB6gJztkpOMp1X45fs/RzADFBzr\nknN3Tpp3o+HeUtMaoSQLKwaRIKGDv+ilpgYteKucD/L5IcCgqaGo+mhvO31KagjR\nbNnz0bR75em+ouDjSrMGVTH2ms/xdI96Y3VBsyjr/7o+dWyaPV//C15wZDGHJtRj\nOrVA+t+ExK89l5ZmRYy1B4AulcyG9faZ5pT/IJbFzWQO+7PRuXZPi1zpATUD52GT\nt+x1ZhEoxLC9pK4Lfk0OsqXmJdk5Iu+YrOZn9sheOUB8NvlUAHNyOUyI+LDuNkdz\n9FiyvzEuohsK/A9N1FDpwaUPiz640wUxr62jNKihiHHPC5JQuqcpY1yfdgGnWsuD\nbfDT2TEz8EQKApC+FnAOnPrK+kp0XjsVHEWfwxFA2kLjPMvQx5OMmma0QMx7I8o8\npQjy1/uYzx5w+YLi+LSPlsIaNzFIY4Un9uXsQUfP1mKnIujNYiIW19opYpaue0Ip\nmqCoyRQDHPmDcOtbPBJAJMJxgRntQryD3nZagY+W9eKH/H+nhGB4OUfaD4jetWLB\nOM4V1zAuYOVf4jO05EkEIrc8DX5Y1KWiTJHFhI5vqlO8dkv1iG7wuEqxaO5rnMjW\njL3/II+FvtGwRLY5qMCynDcCAwEAAQ==\n-----END PUBLIC KEY-----\n",
  "id": "rsa-1774002086208502800",
  "metadata": "EKMFRSAIMPORT",
  "signature": ""
}
```

Save the RSA import public key by issuing the following command:

```
jq -r .content OUTPUTBRIDGEMSGS > public.pem
```

### 2. Importing keys in OSO via OSO EKMF messages

#### 2.1 As EKMF Admin, Send OSO EKMF Message to provide transport key
```
./EKMF_SendTKEY.sh public.pem rsa-1774002086208502800 8c123e3317f57abe25007fda598acba69dfa0bc8d31816e81f1426597fc99f1d
```
```

Uploading to http://localhost:8080/FrontEndUploadTKEY...
Thu Mar 19 03:04:57 PM EDT 2026: ID=rsa-1774002086208502800 - Response:
Response: {"id":"rsa-1774002086208502800","status":"transport key stored"}
```

### 2.2 As EKMF Admin, Send OS0 EKMF Messages to upload assets keys

```
LIST="1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17"
for i in $LIST; do bash ./EKMF_SendKeys.sh $i & done

Uploaded 100000 keys
[1]+  Done                    bash ./EKMF_SendKeys.sh $i
```

Wait that all jobs be completed

### 2.3 As OSO Operator, simulate OSO Iteration #2

#### Check FrontEnd OSO Plugin:

```
2026-03-20 07:34:08,188 [INFO] Retrieved 11 documents from server.
2026-03-20 07:34:08,214 [INFO] Successfully wrote 11 documents to INPUTBRIGDEOSMSGS
2026-03-20 07:34:08,215 [INFO] Saved document ID=e6982e60-86ef-40a4-8cb0-e58d79de641d, len=983036, snippet=H4sIAAAAAAAA/3T8yaqtSw4mCL6Lj+MHNaYuXqVG6gwKqshBkqMk3z35txNx/wt7j/zgd52ztMxMXyPJ...
2026-03-20 07:34:08,215 [INFO] Saved document ID=a0d48ff7-0a7d-488b-a537-8c6e3eb31e8b, len=983092, snippet=H4sIAAAAAAAA/3T8y6oYTe83ht7LO/4adCid/reyR5JKgg0JGYSMQu499Hp487RheWZsL1tdVfodJFX9...
2026-03-20 07:34:08,215 [INFO] Saved document ID=7db3bded-da93-4479-bc83-187034cf3a89, len=983288, snippet=H4sIAAAAAAAA/3T8yY4wuQ4uBr7LWd8AOIjTfZVecRCBBrrhheGV4Xc3Io/tioIzgVoU/ikZkvgNJKX/...
2026-03-20 07:34:08,215 [INFO] Saved document ID=497b9b3c-9c3d-44d0-afa7-d6c6926cb002, len=983012, snippet=H4sIAAAAAAAA/3S8y65dOa8u9i7VPgMQKV73q6TFKxAgQRpBWkHePRjr3+fUMLBcnYLtaS9OifwuFKX/...
2026-03-20 07:34:08,215 [INFO] Saved document ID=3654dfea-b6e0-4534-a168-a7069bfa0b0f, len=983140, snippet=H4sIAAAAAAAA/3T8S65lu+71ifXlX84J8CG+sisukSIJGLDhguGS4b4bc32ZeecFduBUAid27MUliYO/...
2026-03-20 07:34:08,215 [INFO] Saved document ID=bf22ca76-f25e-4b0b-b43b-c0d747a5ecc9, len=983392, snippet=H4sIAAAAAAAA/3S8y4pmva83di/veC+QbB33rWSkIwQSMggZhdx7WPXfH+9qqB52U1WPHlv6HWTZ/9v/...
2026-03-20 07:34:08,215 [INFO] Saved document ID=7f25b83c-040d-4ed2-9780-2b2ad038aca1, len=983244, snippet=H4sIAAAAAAAA/3S8y4p4R68v9i4e7wVS6b5fJSPdCgIJGYSMwnn3w2qf73gZ+j+zceNWV0m/i6Ra/8f/...
2026-03-20 07:34:08,215 [INFO] Saved document ID=3b4da63a-bbaf-44ac-86ad-247c290794bf, len=983144, snippet=H4sIAAAAAAAA/3T8yWpvS9IvCL5LjO8C65v7KjWyxh0KqshBkqMk3z1Zii+IdUCCM9DZe0uyv7vZrzE3...
2026-03-20 07:34:08,215 [INFO] Saved document ID=7cc0f989-55d3-4c97-b7bb-457082dada03, len=983212, snippet=H4sIAAAAAAAA/3T8y4p+Sc8viN3LO94LFAod9614pCMYbDwwHpm+92bl21/XKsis0Z8iMx89EdLvoFDE...
2026-03-20 07:34:08,215 [INFO] Saved document ID=fd284817-c440-4dec-9a4c-23cbef4407bd, len=983156, snippet=H4sIAAAAAAAA/3S8y6pgyc4m9i41/heEpNDtfxWPdAWDjQfGI9Pv3qxdfbpWwU44gwOVmVtbIX0XhWL9...
2026-03-20 07:34:08,215 [INFO] Saved document ID=rsa-1774002086208502800, len=1024, snippet=9cdcb19eec522adb2d06a30f3962fcf1a31a9968fbdb978c76fc4aa2d33b05cd51e8b54c1b7ce366...
```

#### Start OSO Iteration

```
./OSO_StartIteration.sh
```

#### Check BackEnd OSO Plugin:


```
2026-03-20 07:35:07,650 [INFO] Loaded 11 documents from INPUTBRIGDEOSMSGS
2026-03-20 07:35:07,650 [INFO] Uploading document ID=e6982e60-86ef-40a4-8cb0-e58d79de641d, content length=983036, snippet=H4sIAAAAAAAA/3T8yaqtSw4mCL6Lj+MHNaYuXqVG6gwKqshBkqMk3z35txNx/wt7j/zgd52ztMxMXyPJ...
2026-03-20 07:35:07,696 [INFO] Uploaded 10000 keys from document e6982e60-86ef-40a4-8cb0-e58d79de641d
2026-03-20 07:35:07,696 [INFO] Uploading document ID=a0d48ff7-0a7d-488b-a537-8c6e3eb31e8b, content length=983092, snippet=H4sIAAAAAAAA/3T8y6oYTe83ht7LO/4adCid/reyR5JKgg0JGYSMQu499Hp487RheWZsL1tdVfodJFX9...
2026-03-20 07:35:07,740 [INFO] Uploaded 10000 keys from document a0d48ff7-0a7d-488b-a537-8c6e3eb31e8b
2026-03-20 07:35:07,740 [INFO] Uploading document ID=7db3bded-da93-4479-bc83-187034cf3a89, content length=983288, snippet=H4sIAAAAAAAA/3T8yY4wuQ4uBr7LWd8AOIjTfZVecRCBBrrhheGV4Xc3Io/tioIzgVoU/ikZkvgNJKX/...
2026-03-20 07:35:07,785 [INFO] Uploaded 10000 keys from document 7db3bded-da93-4479-bc83-187034cf3a89
2026-03-20 07:35:07,785 [INFO] Uploading document ID=497b9b3c-9c3d-44d0-afa7-d6c6926cb002, content length=983012, snippet=H4sIAAAAAAAA/3S8y65dOa8u9i7VPgMQKV73q6TFKxAgQRpBWkHePRjr3+fUMLBcnYLtaS9OifwuFKX/...
2026-03-20 07:35:07,830 [INFO] Uploaded 10000 keys from document 497b9b3c-9c3d-44d0-afa7-d6c6926cb002
2026-03-20 07:35:07,830 [INFO] Uploading document ID=3654dfea-b6e0-4534-a168-a7069bfa0b0f, content length=983140, snippet=H4sIAAAAAAAA/3T8S65lu+71ifXlX84J8CG+sisukSIJGLDhguGS4b4bc32ZeecFduBUAid27MUliYO/...
2026-03-20 07:35:07,875 [INFO] Uploaded 10000 keys from document 3654dfea-b6e0-4534-a168-a7069bfa0b0f
2026-03-20 07:35:07,875 [INFO] Uploading document ID=bf22ca76-f25e-4b0b-b43b-c0d747a5ecc9, content length=983392, snippet=H4sIAAAAAAAA/3S8y4pmva83di/veC+QbB33rWSkIwQSMggZhdx7WPXfH+9qqB52U1WPHlv6HWTZ/9v/...
2026-03-20 07:35:07,921 [INFO] Uploaded 10000 keys from document bf22ca76-f25e-4b0b-b43b-c0d747a5ecc9
2026-03-20 07:35:07,921 [INFO] Uploading document ID=7f25b83c-040d-4ed2-9780-2b2ad038aca1, content length=983244, snippet=H4sIAAAAAAAA/3S8y4p4R68v9i4e7wVS6b5fJSPdCgIJGYSMwnn3w2qf73gZ+j+zceNWV0m/i6Ra/8f/...
2026-03-20 07:35:07,967 [INFO] Uploaded 10000 keys from document 7f25b83c-040d-4ed2-9780-2b2ad038aca1
2026-03-20 07:35:07,967 [INFO] Uploading document ID=3b4da63a-bbaf-44ac-86ad-247c290794bf, content length=983144, snippet=H4sIAAAAAAAA/3T8yWpvS9IvCL5LjO8C65v7KjWyxh0KqshBkqMk3z1Zii+IdUCCM9DZe0uyv7vZrzE3...
2026-03-20 07:35:08,013 [INFO] Uploaded 10000 keys from document 3b4da63a-bbaf-44ac-86ad-247c290794bf
2026-03-20 07:35:08,013 [INFO] Uploading document ID=7cc0f989-55d3-4c97-b7bb-457082dada03, content length=983212, snippet=H4sIAAAAAAAA/3T8y4p+Sc8viN3LO94LFAod9614pCMYbDwwHpm+92bl21/XKsis0Z8iMx89EdLvoFDE...
2026-03-20 07:35:08,059 [INFO] Uploaded 10000 keys from document 7cc0f989-55d3-4c97-b7bb-457082dada03
2026-03-20 07:35:08,059 [INFO] Uploading document ID=fd284817-c440-4dec-9a4c-23cbef4407bd, content length=983156, snippet=H4sIAAAAAAAA/3S8y6pgyc4m9i41/heEpNDtfxWPdAWDjQfGI9Pv3qxdfbpWwU44gwOVmVtbIX0XhWL9...
2026-03-20 07:35:08,106 [INFO] Uploaded 10000 keys from document fd284817-c440-4dec-9a4c-23cbef4407bd
2026-03-20 07:35:08,106 [INFO] Submitting transport key for ID: rsa-1774002086208502800
2026-03-20 07:35:08,113 [INFO] Transport key successfully uploaded for ID: rsa-1774002086208502800
2026-03-20 07:35:08,113 [INFO] {"content":"{\"checksum\":\"2bba8e00000100\",\"status\":\"ok\"}","id":"rsa-1774002086208502800","metadata":"EKMFIMPORT","signature":""}

2026-03-20 07:35:08,113 [INFO] Both EKMFIMPORT and EKMFKEYSIMPORT detected. Triggering BackendProcess...
2026-03-20 07:35:30,601 [INFO] Batch process triggered successfully: {"content":"{\"success_count\":100000,\"failed_count\":0,\"failed_ids\":null}","id":"20260320-073530","metadata":"EKMFKEYSIMPORT","signature":""}
```

You can check results in `OUTPUTBRIDGEMSGS` file:

```
cat OUTPUTBRIDGEMSGS 
{"content":"{\"checksum\":\"2bba8e00000100\",\"status\":\"ok\"}","id":"rsa-1774002086208502800","metadata":"EKMFIMPORT","signature":""}
{"content":"{\"success_count\":100000,\"failed_count\":0,\"failed_ids\":null}","id":"20260320-073530","metadata":"EKMFKEYSIMPORT","signature":""}
```

# Appendix 

## OSO - Starting EKMF Frontend and EKMF Backend Addons for OSO Haven Plugin


### Starting the EKMF FrontEnd Addon

```
export mode=frontend
./ekmfimportserver 
Frontend server listening on :8080
```


### Starting EKMF Backend Addon

Set HSM using `EP11_IBM_TARGET_HSM` environment variable

```
export EP11_IBM_TARGET_HSM="4.16 3.16"
export mode=backend
./ekmfimportserver 
Initializing adapter 04 and domain 16
Initializing adapter 03 and domain 16
Backend server listening on :9080
```

## Start OSO plugins

### Frontend Plugin

```
python FrontendPlugin.py

2026-03-20 11:08:35,844 [INFO] Starting frontend plugin in infinite loop...

```

### Backend Plugin

```
python BackendPlugin.py

2026-03-20 11:27:19,332 [INFO] OSO backend plugin started. Polling every 5s...

```

## Monitoring Crypto Adapters Performance

Open in a terminal

`watch -n 2 'zcryptstats -i 1 -c 1 -T -a | egrep "COUNTER|Total"'`


## EKMF Mock - Generating keys


### EKMF Mock: Create a transport key

Use openssl command for this.  Alternatively `createTKEY` is provided to protect this key using an HSM.  The key is set extractable so that it could be RSA wrapped.

```
openssl rand -hex 32
8c123e3317f57abe25007fda598acba69dfa0bc8d31816e81f1426597fc99f1d
```

### EMFK Mock: Generation of EKMF seeds using IBM CryptoExpress cards

This procedure uses HSM cards for performance reason.  Alternative is software key generation.


Convert the hexa transkey value into a cryptogram using `createskblob` command:

```
export EP11_IBM_TARGET_HSM="4.16 3.16"
./createskblob 8c123e3317f57abe25007fda598acba69dfa0bc8d31816e81f1426597fc99f1d
Initializing adapter 04 and domain 16
Initializing adapter 03 and domain 16

TransportKey Blob: 00000000000000000000000000000000000000000000000000000000000000002dbfb11e9dc94e5517a4786c0eb7483d00000000000091840000000000000001123431259656d1a8db0ebeac7421d420feab1a92938ca86d5efb947cacf2f9fb36bbfa57e33ee924bb414880fc1d222d4c5b92e7b1c091a8a518c49d8caafca8e2a5b85ba3c753513359e43410dc35ad598d1f187fa230e765edf96f14f9a9592f9c1ff514d687b462f5a92dca14d05b0aecc5555fcc02d316e2938b735feac14a7237379320eb5b52b86ee4d2537db4c99b3f70729d02606202a7616673432f5f94c9c6b1f6a1c09f484a3be187914746a6ab15ea6ab1ee487558f5bb000e7518224f2b4cd032a23c2ed876bd884d16ee470e72bb1245ea9153fa3d0497c9b8eb700d26a1e673b414dd79970a90105b5034a2ce67009942f303ec46b885f87ff3c7dd48b6f11ad978bc09c043bceae89556362ed1b5e3a9897a03e97a63b4c2ce70ce684c586347cdcd4bf96cfd157bc6f18a5d6c77b05b09e3860379284a59266077c0ed188daf155a7b43ba6b9bd78b0ed25e6e18927631b569fa6a63cd40c9a3eeea6daff2c82e334fe84eea293adcfc98c46e381fb8e31b6deed8326212

Csum : 12071000000100
```

For convenience, set the `TKEY` environmnt variable with this cryptogram value.

```
TKEY=00000000000000000000000000000000000000000000000000000000000000002dbfb11e9dc94e5517a4786c0eb7483d00000000000091840000000000000001123431259656d1a8db0ebeac7421d420feab1a92938ca86d5efb947cacf2f9fb36bbfa57e33ee924bb414880fc1d222d4c5b92e7b1c091a8a518c49d8caafca8e2a5b85ba3c753513359e43410dc35ad598d1f187fa230e765edf96f14f9a9592f9c1ff514d687b462f5a92dca14d05b0aecc5555fcc02d316e2938b735feac14a7237379320eb5b52b86ee4d2537db4c99b3f70729d02606202a7616673432f5f94c9c6b1f6a1c09f484a3be187914746a6ab15ea6ab1ee487558f5bb000e7518224f2b4cd032a23c2ed876bd884d16ee470e72bb1245ea9153fa3d0497c9b8eb700d26a1e673b414dd79970a90105b5034a2ce67009942f303ec46b885f87ff3c7dd48b6f11ad978bc09c043bceae89556362ed1b5e3a9897a03e97a63b4c2ce70ce684c586347cdcd4bf96cfd157bc6f18a5d6c77b05b09e3860379284a59266077c0ed188daf155a7b43ba6b9bd78b0ed25e6e18927631b569fa6a63cd40c9a3eeea6daff2c82e334fe84eea293adcfc98c46e381fb8e31b6deed8326212
```

Use `ekfmexport` (mocked) command to generate your key data set for oso import.
Specify:
* The transport key cryptogram used for wrapping
* The number of keys in your data set
* Make sure `EP11_HSM_DOMAIN` environment variable is set to specify HSM domains

```
LIST="1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16"
for i in $LIST; do ./ekmfexport $TKEY 100000 | grep -v domain | gzip -c | base64 -w0 > keys_set_.$i.gz.b64 & done
```





