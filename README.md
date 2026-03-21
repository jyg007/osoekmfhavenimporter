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
./OSOQueue.py pre
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
You can set this id as a value to reuse later when loading the transport key
```
RSAID=rsa-1774002086208502800
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
./OSOQueue.py post   
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
./OSOQueue.py post |  jq -r .documents[].content > public.pem
```

### 2. Importing keys in OSO via OSO EKMF messages

#### 2.1 As EKMF Admin, Send OSO EKMF Message to provide transport key

Then send the transport to OSO using the `RSAID` value set when you created the RSA key pair in OSO:

```
./EKMF_SendTKEY.sh public.pem $RSAID 8c123e3317f57abe25007fda598acba69dfa0bc8d31816e81f1426597fc99f1d
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

You can verify transaction using the following command:
```
./OSOQueue.py pre | jq -r .documents[].id | xargs
```
```
ekmfimport-tkey-rsa-1774002086208502800 ekmfimport-768c60f9-b231-4683-b538-7479093f4497 ekmfimport-77264196-4966-4d3c-8437-c0cb60cff46a ekmfimport-cbe3327e-cd8e-4708-a784-d35ec1dc8a7c ekmfimport-734cfbd9-f6a6-4510-8898-f666c9b630fb ekmfimport-55dc27b0-0b78-477d-86b9-7ebbaed837d4 ekmfimport-d00a50dc-0757-4151-a417-66bc47e6adbd ekmfimport-932c0bdd-7a80-48fa-9a13-7a67699daba0 ekmfimport-dd0e20a4-8f0b-422e-b6cd-042bf71b2d70 ekmfimport-a7f7f331-3366-4075-b550-57ac7cc04325 ekmfimport-080339e7-8089-4306-a76d-5322c2614db3 ekmfimport-42d42758-9204-4218-9615-504860acf5ff ekmfimport-9b50b43a-d767-4809-9813-f241427718ee ekmfimport-d20663fc-3b5f-4cbb-8d28-9346ef5efe6f ekmfimport-2c5ccc26-aa3b-4981-88dd-2ec9844f2ce9 ekmfimport-b49bcbad-cf9b-4fbd-80ff-ee6b07332144 ekmfimport-27aea2f7-ef18-41fe-88d8-7b3be6bf16b3 ekmfimport-3432c4a5-a6d7-43a0-850a-b829b4b5326f ekmfimport-242a1c5b-ce86-49f7-8341-bb4757a0f728 ekmfimport-49c04c9d-c263-4fe1-ae46-52274c83a8a2 ekmfimport-fffc501b-3abd-4628-b9ca-637b6bbddff1 ekmfimport-019bb5cb-802b-4bd4-837f-558f68fe1a53 ekmfimport-77919d12-b393-45d4-ba65-42ddd4025c57 ekmfimport-a7317b92-4d99-4ca0-8413-e6ef66b55d45 ekmfimport-97216a63-0e27-45f4-9f65-5536e7d0c028 ekmfimport-04c49e5f-ee28-4181-82d7-1a855df0f1a7 ekmfimport-d36e9c32-499c-4747-9770-5279e39e8b67 ekmfimport-ff093484-6684-4f38-9d68-2fecac7d7e68 ekmfimport-586941c3-c9ab-426b-aef5-3c11972d48cd ekmfimport-d05c8189-116a-403c-852d-1ada11de11ba ekmfimport-c4e78d31-f79c-42af-af7f-db50efcd6d08 ekmfimport-cd67e437-b59e-4ed7-988e-f3e552f97f52 ekmfimport-cb1f36fb-1dbc-46db-a065-79b57929ea0c ekmfimport-734c1173-d151-4921-aa29-80d999908dfd ekmfimport-6e554ba8-b55b-44ef-9d1b-179d56c788e9 ekmfimport-b5e0593c-0af6-491a-8679-8c0916ed969f ekmfimport-0695a6d6-7520-4d43-8e4f-1b360a1bc581 ekmfimport-a5c60d76-c832-4266-9669-c61627d3655c ekmfimport-885eeb1b-6719-4ffe-bdab-2aaba214f959 ekmfimport-25a28c38-fa0c-4939-9fbe-595eebed5980 ekmfimport-0db119af-0439-4925-adee-3758cf3c0bbf ekmfimport-4fb43320-aa56-45aa-9415-6c3054797b5a ekmfimport-6f894c59-21c0-4bd1-bd58-8b098444ff5a ekmfimport-c03d2bc1-2894-4d32-81a6-46f7199592c6 ekmfimport-8a651cab-3b57-4895-9a08-2c4aa98014b2 ekmfimport-ba2993fe-0cbb-4c97-b223-93f88286e659 ekmfimport-7f22c3da-78a4-4e4d-a228-7de5653e86f0 ekmfimport-fb6307e2-418c-413f-8730-f2c0e8541a9b ekmfimport-d97fa1ae-272e-436e-8290-47cf5503b210 ekmfimport-cb5657e5-ac3c-48d5-9dcc-9f6074ee5e9a ekmfimport-3140e81d-9ac0-4996-a27f-44807d6e91a1 ekmfimport-0233836e-e424-43ea-945a-a174f11157d1 ekmfimport-20bae6a2-7a91-403d-adec-12c5bb303e9b ekmfimport-f9f9a366-5ebb-466f-b300-8586164de678 ekmfimport-ba86e7d3-f3f5-4156-a572-705dcaf1fea0 ekmfimport-9fa3987a-42c2-4c35-898a-e403c3636bd5 ekmfimport-4b63f202-4380-4e55-a888-42e755f4f733 ekmfimport-7fc74ecd-1885-4755-ab4e-b984a206e5a6 ekmfimport-3e3089fa-c8ea-4fa7-8169-2f377c7d3671 ekmfimport-be906083-74c1-4e38-9829-28eb38a04e16 ekmfimport-c08fbd89-8b96-497f-af78-241fb29729d7 ekmfimport-86c2e3de-7418-4a49-9f77-7f7a3b0c07b0 ekmfimport-a3e17fa2-1666-4c3b-b5cd-3014a152a051 ekmfimport-f30ea508-9b82-4598-bc9d-df903a597bb4 ekmfimport-c7230eeb-ae7c-4584-a2d3-cdb93c1aea1f
```
And in the log of the plugin

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
./OSOQueue.py post
```
```
{
  "documents": [
    {
      "content": "{\"checksum\":\"2bba8e00000100\",\"status\":\"ok\"}",
      "id": "ekmfimport-tkey-rsa-1774087290973474635",
      "metadata": "EKMFIMPORT",
      "signature": ""
    },
    {
      "content": "{\"success_count\":1600000,\"failed_count\":50,\"failed_ids\":[\"019d05a5-981d-7025-91c3-8b10d0231307\",\"019d05a5-981d-7c2d-be94-311cdd6e2251\",\"019d05a5-981e-743d-88b8-bbb192684182\",\"019d05a5-981e-7b73-b4cd-7f0c115b5724\",\"019d05a5-981f-7383-bdad-933aa4fc2035\",\"019d05a5-981f-7a7e-a45f-61677f99c1a6\",\"019d05a5-9820-7256-9ee4-044c498da30b\",\"019d05a5-9820-795a-873a-d5e93bc6f90c\",\"019d05a5-9821-70fe-8a53-816fc092982d\",\"019d05a5-9821-77ca-827b-5dc8cf45aa64\",\"019d05a5-9821-7ef5-b0dd-6b23c621a774\",\"019d05a5-9822-7682-a4c1-3d834e69b74e\",\"019d05a5-9822-7d26-9d5b-f3facff66b85\",\"019d05a5-9823-74a6-a1ac-6de5d75aca5b\",\"019d05a5-9823-7b72-9433-1d3d833e8631\",\"019d05a5-9824-72fc-b3fb-f0c3a5dd264a\",\"019d05a5-9824-79ac-a4ff-075c78776923\",\"019d05a5-9825-7124-b41f-d2010ec7ee57\",\"019d05a5-9825-77f5-8b62-6c96dead74fd\",\"019d05a5-9825-7ee1-b3ce-272a251b9077\",\"019d05a5-9826-7647-b84c-28f376247e27\",\"019d05a5-9826-7d07-9b41-ef0e9729ec68\",\"019d05a5-9827-7489-b734-057b498e5542\",\"019d05a5-9827-7b55-b30d-3393f5ae7a38\",\"019d05a5-9828-72c9-a3d0-e7ce4386546e\",\"019d05a5-9828-797a-b044-8c2639fef643\",\"019d05a5-9829-70f0-8ab1-755d8a092204\",\"019d05a5-9829-778c-a2f1-40ba065c162a\",\"019d05a5-9829-7e97-8349-611b0d980969\",\"019d05a5-982a-7613-a001-5aa57723ff8f\",\"019d05a5-982a-7d3a-bd94-9ea4511fd16f\",\"019d05a5-982b-756e-b0e6-11c0bb371da1\",\"019d05a5-982b-7c6c-a63e-83c0c5fbc24d\",\"019d05a5-982c-741b-bc27-6ef075fa51f9\",\"019d05a5-982c-7b07-a9f1-6bcbd527d715\",\"019d05a5-982d-72a0-b849-5f6b00594bac\",\"019d05a5-982d-79ab-932c-080e6971ae1e\",\"019d05a5-982e-7142-8ca2-4e04c746411e\",\"019d05a5-982e-781b-9bf9-16a2aa9ecf52\",\"019d05a5-982f-7002-b800-4f39bdbd5ca3\",\"019d05a5-982f-76c4-a1ce-726a9d4f26a9\",\"019d05a5-982f-7d8b-b451-214d41964caf\",\"019d05a5-9830-7515-8a48-f9d0b0949698\",\"019d05a5-9830-7bf6-bef9-43b3af9b7ab5\",\"019d05a5-9831-736d-9bed-259576b4a71e\",\"019d05a5-9831-7a71-abc9-217f3d8ce9ca\",\"019d05a5-9832-7221-acc0-bf41b41110e9\",\"019d05a5-9832-78d5-ae26-052c4d181495\",\"019d05a5-9833-7077-8719-d578807afcf9\",\"019d05a5-9833-7725-b16b-e2cf4c32a7f2\"]}",
      "id": "20260321-060451",
      "metadata": "EKMFKEYSIMPORT",
      "signature": ""
    }
  ],
  "count": 2
}
```

# Appendix 

## OSO - Starting EKMF Frontend and EKMF Backend Addons for OSO Haven Plugin


### Starting the EKMF FrontEnd Addon

```
export mode=frontend
./ekmfimportserver 
```
```
Frontend server listening on :8080
```


### Starting EKMF Backend Addon

Set HSM using `EP11_IBM_TARGET_HSM` environment variable

```
export EP11_IBM_TARGET_HSM="4.16 3.16"
export mode=backend
./ekmfimportserver 
```
```
Initializing adapter 04 and domain 16
Initializing adapter 03 and domain 16
Backend server listening on :9080
```

## Start OSO plugins

### Frontend Plugin

```
python FrontendPlugin.py
```
```
2026-03-20 11:08:35,844 [INFO] Starting frontend plugin in infinite loop...

```

### Backend Plugin

```
python BackendPlugin.py
```
```
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
```
```
8c123e3317f57abe25007fda598acba69dfa0bc8d31816e81f1426597fc99f1d
```

### EMFK Mock: Generation of EKMF seeds using IBM CryptoExpress cards

This procedure uses HSM cards for performance reason.  Alternative is software key generation.


Convert the hexa transkey value into a cryptogram using `createskblob` command:

```
export EP11_IBM_TARGET_HSM="4.16 3.16"
./createskblob 8c123e3317f57abe25007fda598acba69dfa0bc8d31816e81f1426597fc99f1d
```
```
Initializing adapter 04 and domain 16
Initializing adapter 03 and domain 16

TransportKey Blob: 00000000000000000000000000000000000000000000000000000000000000002dbfb11e9dc94e5517a4786c0eb7483d00000000000091840000000000000001123431259656d1a8db0ebeac7421d420feab1a92938ca86d5efb947cacf2f9fb36bbfa57e33ee924bb414880fc1d222d4c5b92e7b1c091a8a518c49d8caafca8e2a5b85ba3c753513359e43410dc35ad598d1f187fa230e765edf96f14f9a9592f9c1ff514d687b462f5a92dca14d05b0aecc5555fcc02d316e2938b735feac14a7237379320eb5b52b86ee4d2537db4c99b3f70729d02606202a7616673432f5f94c9c6b1f6a1c09f484a3be187914746a6ab15ea6ab1ee487558f5bb000e7518224f2b4cd032a23c2ed876bd884d16ee470e72bb1245ea9153fa3d0497c9b8eb700d26a1e673b414dd79970a90105b5034a2ce67009942f303ec46b885f87ff3c7dd48b6f11ad978bc09c043bceae89556362ed1b5e3a9897a03e97a63b4c2ce70ce684c586347cdcd4bf96cfd157bc6f18a5d6c77b05b09e3860379284a59266077c0ed188daf155a7b43ba6b9bd78b0ed25e6e18927631b569fa6a63cd40c9a3eeea6daff2c82e334fe84eea293adcfc98c46e381fb8e31b6deed8326212

Csum : 12071000000100
```

For convenience, set the `TKEY` environment variable with this cryptogram value.

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





