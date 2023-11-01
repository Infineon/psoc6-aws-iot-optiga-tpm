#!/bin/bash

echo "CLIENT_CERTIFICATE:"
sed 's/^/"/; s/$/\\n" \\/' out/tpm.crt | sed 's/END CERTIFICATE-----\\n" \\/END CERTIFICATE-----"/'

echo ""
echo "ROOT_CA_CERTIFICATE:"
sed 's/^/"/; s/$/\\n" \\/' out/AmazonRootCA1.pem.crt | sed 's/END CERTIFICATE-----\\n" \\/END CERTIFICATE-----"/'
