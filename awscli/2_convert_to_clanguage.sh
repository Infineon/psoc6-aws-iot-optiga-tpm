#!/bin/bash

sed 's/^/"/; s/$/\\n" \\/' tpm.pem.crt | sed 's/END CERTIFICATE-----\\n" \\/END CERTIFICATE-----"/' 
