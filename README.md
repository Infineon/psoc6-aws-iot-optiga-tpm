[![Github actions](https://github.com/infineon/psoc6-aws-iot-optiga-tpm/actions/workflows/main.yml/badge.svg)](https://github.com/infineon/psoc6-aws-iot-optiga-tpm/actions)

# PSoC 6 Onboarding to AWS IoT Core</br> using OPTIGA™ TPM SLx 9670 TPM2.0

## Introduction

This repository provides instructions for integrating the [OPTIGA™ TPM SLx 9670 TPM2.0](https://www.infineon.com/cms/en/product/security-smart-card-solutions/optiga-embedded-security-solutions/optiga-tpm/) into a [PSoC 6 Wi-Fi BT Prototyping Kit](https://www.infineon.com/cms/en/product/evaluation-boards/cy8cproto-062-4343w/). The project also contains examples of using TPM2-TSS libraries and Mbed TLS libraries with TPM as the configured crypto hardware acceleration. It includes a demonstration of TPM-based device onboarding to [AWS IoT Core](https://aws.amazon.com/iot-core/).

## Table of Contents

- **[Prerequisites](#prerequisites)**
- **[Installing ModusToolbox for First Use](#installing-modustoolbox-for-first-use)**
- **[Cross-compile TPM2-TSS for PSoc 6](#cross-compile-tpm2-tss-for-psoc-6)**
- **[Add TPM2-TSS Libraries to the MTB Project](#add-tpm2-tss-libraries-to-the-mtb-project)**
- **[Example Applications](#example-applications)**
  - **[TPM2-TSS Examples](#tpm2-tss-examples)**
  - **[Mbed TLS Examples](#mbed-tls-examples)**
  - **[TPM-based Device Onboarding to AWS IoT Core](#tpm-based-device-onboarding-to-aws-iot-core)**
- **[Miscellaneous](#miscellaneous)**
  - **[Running TPM2-TSS Examples on Linux](#running-tpm2-tss-examples-on-linux)**
  - **[Running Mbed TLS Examples on Linux](#running-mbed-tls-examples-on-linux)**
- **[License](#license)**

## Prerequisites

Hardware prerequisites:
- PSoC 6 Wi-Fi BT Prototyping Kit ([CY8CPROTO-062-4343W](https://www.infineon.com/cms/en/product/evaluation-boards/cy8cproto-062-4343w/)). \
  <img src="https://github.com/Infineon/psoc6-aws-iot-optiga-tpm/raw/master/media/CY8CPROTO-062-4343W.png" width="50%">
- [IRIDIUM9670 TPM2.0](https://www.infineon.com/cms/en/product/evaluation-boards/iridium9670-tpm2.0-linux/). \
  <img src="https://github.com/Infineon/psoc6-aws-iot-optiga-tpm/raw/master/media/IRIDIUM9670-TPM2.png" width="30%">
- The connection table:
  | IRIDIUM9670 TPM2.0 | CY8CPROTO-062-4343W | Description |
  | --- | --- | --- |
  | Pin 19 | P6_0 | MOSI |
  | Pin 21 | P6_1 | MISO |
  | Pin 23 | P6_2 | SCLK |
  | Pin 26 | P6_3 | CS |
  | Pin 7 | P9_0 | RESET |
  | Pin 1 | VDD | VDD |
  | Pin 6 | GND | GND |

Software prerequisites:
- A host machine with Ubuntu (tested on Ubuntu 22.04.1 LTS) installed.
- Familiarity with the procedure for building and programming a PSoC 6 using [ModusToolbox Eclipse IDE](https://www.infineon.com/dgdl/Infineon-ModusToolbox_3.0_Eclipse_IDE_QSG-GettingStarted-v01_00-EN.pdf?fileId=8ac78c8c8386267f0183a8e969e95911) or using [Command Line](https://www.infineon.com/dgdl/Infineon-ModusToolbox_3_0_Tools_Package_User_Guide-GettingStarted-v01_00-EN.pdf?fileId=8ac78c8c85ecb34701862f1c06796dee).
- Familiarity with the ModusToolbox PSoC 6 project [mtb-example-wifi-mqtt-client](https://github.com/Infineon/mtb-example-wifi-mqtt-client).

## Installing ModusToolbox for First Use

1. Download the [ModusToolbox™ Software for Linux](https://www.infineon.com/cms/en/design-support/tools/sdk/modustoolbox-software/) (tested on version 3.0.0.9369 and 3.1.0.12257) to your host and unpack it:
   ```
   # Set the MTB version. Option 1:
   $ export MTB_VERSION_FULL=3.1.0.12257
   $ export MTB_VERSION_SHORT=3.1

   # Option 2:
   $ export MTB_VERSION_FULL=3.0.0.9369
   $ export MTB_VERSION_SHORT=3.0
   ```
   ```all
   $ cd ~
   $ tar -C $HOME -xzf ModusToolbox_${MTB_VERSION_FULL}-linux-install.tar.gz
   ```
2. Set the environment variables:
   ```all
   $ export PATH=${HOME}/ModusToolbox/tools_${MTB_VERSION_SHORT}/project-creator/bin:$PATH
   $ export CY_TOOLS_PATHS=${HOME}/ModusToolbox/tools_${MTB_VERSION_SHORT}
   ```
3. Install packages:
   ```all
   $ sudo apt update
   $ sudo apt -y install libglib2.0-0 libgl1 make git ttylog

   $ ${CY_TOOLS_PATHS}/modus-shell/postinstall
   ```
   In addition, if you plan to run the project on the Eclipse IDE instead of just using the CLI:
   ```
   $ sudo apt -y install libxcb-xinerama0 libncurses5

   $ ${CY_TOOLS_PATHS}/openocd/udev_rules/install_rules.sh
   $ ${CY_TOOLS_PATHS}/driver_media/install_rules.sh
   $ ${CY_TOOLS_PATHS}/fw-loader/udev_rules/install_rules.sh
   $ ${CY_TOOLS_PATHS}/modus-shell/postinstall

   # Launch the IDE and import the project by: Quick Panel > Import Existing Application In-Place
   $ ~/ModusToolbox/ide_3.1/eclipse/modustoolbox-eclipse
   ```
4. Initialize the mtb-example-wifi-mqtt-client project:
   ```all
   $ mkdir ~/mtb_projects
   $ project-creator-cli \
       --board-uri https://github.com/cypresssemiconductorco/TARGET_CY8CPROTO-062-4343W \
       --board-id CY8CPROTO-062-4343W \
       --board-commit release-v4.1.0 \
       --app-uri https://github.com/Infineon/mtb-example-wifi-mqtt-client \
       --app-id mtb-example-wifi-mqtt-client \
       --app-commit release-v5.1.0 \
       --user-app-name mtb_example_wifi_mqtt_client \
       --target-dir ~/mtb_projects
   ```
5. Test build the project:
   ```all
   $ cd ~/mtb_projects/mtb_example_wifi_mqtt_client
   $ make build -j$(nproc)
   ```
6. Program the application artifact onto the board, and remember to connect your board to the host before proceeding:
   ```
   $ make program
   ```
7. Connect to the serial port to view the debug messages:
   ```
   # Look for the serial port, e.g., /dev/ttyACM0
   $ dmesg | grep tty

   # Reading from the serial port
   $ sudo ttylog -b 115200 -d /dev/ttyACM0
   ```

## Cross-compile TPM2-TSS for PSoC 6

1. Install packages:
   ```all
   $ sudo apt update
   $ sudo apt -y install autoconf-archive libcmocka0 libcmocka-dev procps iproute2 build-essential git \
       pkg-config gcc libtool automake libssl-dev uthash-dev autoconf doxygen libjson-c-dev \
       libini-config-dev libcurl4-openssl-dev uuid-dev pandoc acl libglib2.0-dev xxd jq
   ```
2. Set the environment variables:
   ```all
   $ export PATH=${HOME}/ModusToolbox/tools_${MTB_VERSION_SHORT}/gcc/bin:$PATH
   ```
3. Download tpm2-tss and its dependencies:
   ```all
   $ git clone https://github.com/tpm2-software/tpm2-tss ~/tpm2-tss
   $ cd ~/tpm2-tss
   $ git checkout d0632dabe8557754705f8d38ffffdafc9f4865d1
   ```
   ```
   $ git clone https://github.com/infineon/psoc6-aws-iot-optiga-tpm ~/psoc6-aws-iot-optiga-tpm
   ```
4. Extract the compilation flags from the MTB project:
   ```all
   # Extract the raw compilation flags from the MTB project.
   $ mtb_command=$(jq '.[] | select(.file == "source/main.c") | .command' $HOME/mtb_projects/mtb_example_wifi_mqtt_client/build/compile_commands.json)

   # Trim the beginning and the end.
   $ mtb_command_trimmed_head=$(echo $mtb_command | sed "s/.*-c //")
   $ mtb_command_trimmed_tail=$(echo $mtb_command_trimmed_head | sed "s/ -o.*//")

   # Remove single quotes and escape characters.
   $ mtb_command_cleaned_quote=$(echo $mtb_command_trimmed_tail | sed "s/'\\\\\\\"/\\\"/")
   $ mtb_command_cleaned_quote=$(echo $mtb_command_cleaned_quote | sed "s/\\\\\\\"'/\\\"/")

   # Update the path.
   $ compiler_flags=$(echo $mtb_command_cleaned_quote | sed "s#-I\.\.#-I$HOME/mtb_projects#g" | sed "s#-I\.#-I$HOME/mtb_projects/mtb_example_wifi_mqtt_client#g" | sed "s#-Ibsps#-I$HOME/mtb_projects/mtb_example_wifi_mqtt_client/bsps#g")

   # Modify and add compilation flags.
   $ compiler_flags=$(echo $compiler_flags | sed "s/nano\.specs/nosys\.specs/")
   $ compiler_flags=$(echo $compiler_flags | sed "s/\(-pipe\)/\1 -fno-pie/")

   $ echo $compiler_flags
   ```
5. Cross-compile:
   ```all
   $ ./bootstrap
   $ ./configure --host=arm-none-eabi \
     --with-crypto=mbed \
     --enable-nodl --with-maxloglevel=none --disable-util-io --disable-tcti-device \
     --disable-tcti-mssim --disable-tcti-swtpm --disable-tcti-pcap \
     --disable-tcti-libtpms --disable-tcti-cmd --disable-fapi --disable-policy \
     CFLAGS="-DPATH_MAX=256 -DTSS2_TCTI_SUPPRESS_POLL_WARNINGS $compiler_flags"

   # Overwrite the CFLAGS to modify the value of MEDTLS_USER_CONFIG_FILE to include escape characters.
   # We are doing this here because autoconf does not accept escape characters.
   $ compiler_flags="-DPATH_MAX=256 -DTSS2_TCTI_SUPPRESS_POLL_WARNINGS \
     $(echo $compiler_flags | sed 's/\"mbedtls_user_config.h\"/\\\"mbedtls_user_config.h\\\"/')"

   $ make CFLAGS="$compiler_flags" -j$(nproc)
   ```
6. Install the resulting libraries in the `/tmp/tpm2-tss` directory:
   ```all
   $ mkdir /tmp/tpm2-tss
   $ make DESTDIR=/tmp/tpm2-tss install -j$(nproc)
   ```

## Add TPM2-TSS Libraries to the MTB Project

What's currently absent from the TSS library is the platform-specific TCTI module (`Tss2_Tcti_Spi_Psoc6_Init(...)`). Once this module is implemented in MTB, the TSS library will have the capability to access the PSoC 6 SPI interface for communication with the TPM.

The following steps describe how to add TSS libraries to your MTB project:

1. Copy the platform-specific TCTI implementation into your MTB project by:
   ```all
   $ cp ~/psoc6-aws-iot-optiga-tpm/src/tcti_spi_psoc6.* ~/mtb_projects/mtb_example_wifi_mqtt_client/source/
   ```
2. Include the TSS libraries in the build by modifying the MTB Makefile:
   ```all
   $ line=`awk '/^INCLUDES/ {c++} c==1{ print NR+1; exit }' ~/mtb_projects/mtb_example_wifi_mqtt_client/Makefile`
   $ sed -i ${line}'i INCLUDES+=/tmp/tpm2-tss/usr/local/include' ~/mtb_projects/mtb_example_wifi_mqtt_client/Makefile

   $ line=`awk '/^LDLIBS/ {c++} c==1{ print NR+1; exit }' ~/mtb_projects/mtb_example_wifi_mqtt_client/Makefile`
   $ sed -i ${line}'i LDLIBS+=/tmp/tpm2-tss/usr/local/lib/libtss2-mu.a /tmp/tpm2-tss/usr/local/lib/libtss2-rc.a /tmp/tpm2-tss/usr/local/lib/libtss2-sys.a /tmp/tpm2-tss/usr/local/lib/libtss2-esys.a /tmp/tpm2-tss/usr/local/lib/libtss2-tctildr.a /tmp/tpm2-tss/usr/local/lib/libtss2-tcti-spi-helper.a' ~/mtb_projects/mtb_example_wifi_mqtt_client/Makefile
   ```
3. Copy the code along with the examples into your MTB project by:
   ```all
   $ cp ~/psoc6-aws-iot-optiga-tpm/src/tss2_* ~/mtb_projects/mtb_example_wifi_mqtt_client/source/
   ```
4. Rebuild the project:
   ```all
   $ cd ~/mtb_projects/mtb_example_wifi_mqtt_client
   $ make clean
   $ make build -j$(nproc)
   ```

## Example Applications

Once the TSS libraries are ready for use, they can be tested with some examples:
- [TPM2-TSS Examples](#tpm2-tss-examples)
- [Mbed TLS Examples](#mbed-tls-examples)
- [TPM-based Device Onboarding to AWS IoT Core](#tpm-based-device-onboarding-to-aws-iot-core)

### TPM2-TSS Examples

Add the following code snippets to the `main.c` file in the MTB project. However, hold on! Scripts are provided below to automate the copying of code for your convenience.
```snippet1
#include <stdio.h>

#include <tss2/tss2_rc.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#include "tcti_spi_psoc6.h"

void snippet_1()
{
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    ESYS_CONTEXT *esys_ctx = NULL;
    TPM2B_DIGEST *b = NULL;
    TSS2_RC rc;
    size_t size;

    rc = Tss2_Tcti_Spi_Psoc6_Init(NULL, &size, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Tss2_Tcti_Spi_Psoc6_Init failed with error code: 0x%" PRIX32 "(%s).\n", rc, Tss2_RC_Decode(rc));
        goto out;
    }

    tcti_ctx = calloc(1, size);
    if (!tcti_ctx) {
        printf("calloc has failed.\n");
        goto out;
    }

    rc = Tss2_Tcti_Spi_Psoc6_Init(tcti_ctx, &size, NULL);
    if (rc == TSS2_RC_SUCCESS) {
        rc = Esys_Initialize(&esys_ctx, tcti_ctx, NULL);
        if (rc != TSS2_RC_SUCCESS) {
            goto out_tcti_finalize;
        } else {
            rc = Esys_Startup(esys_ctx, TPM2_SU_CLEAR);
            if (rc != TPM2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
                printf("Esys_Startup failed with error code: 0x%" PRIX32 "(%s).\n", rc, Tss2_RC_Decode(rc));
                goto out_esys_finalize;
            } else {
                rc = Esys_GetRandom(esys_ctx,
                                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                    32, &b);
                if (rc != TSS2_RC_SUCCESS) {
                    printf("Esys_GetRandom failed with error code: 0x%" PRIX32 "(%s).\n", rc, Tss2_RC_Decode(rc));
                } else {
                    int i;

                    printf("Esys_GetRandom returns 0x");
                    for (i = 0; i < b->size; i++) {
                        printf("%02x", b->buffer[i]);
                    }
                    printf("\n");
                }

                free(b);
            }
        }
    } else {
        goto out_free_tcti_ctx;
    }

out_esys_finalize:
    Esys_Finalize(&esys_ctx);
out_tcti_finalize:
    Tss2_Tcti_Finalize(tcti_ctx);
out_free_tcti_ctx:
    free(tcti_ctx);
out:
    return;
}

#include "tss2_examples.h"

void snippet_2()
{
    tss2_examples();
}
```

Here is a script for automating the copying of the code snippets:
```all
$ cd ~/psoc6-aws-iot-optiga-tpm
$ sed -n $(expr `awk '/\`\`\`snippet1/{c++} c==1{ print NR; exit }' README.md` + 1)',$p' README.md > .README.md.tmp
$ sed `awk '/\`\`\`/{c++} c==1{ print NR; exit }' .README.md.tmp`',$d' .README.md.tmp > .snippet1.c
$ cat ~/mtb_projects/mtb_example_wifi_mqtt_client/source/main.c >> .snippet1.c
$ cp ~/mtb_projects/mtb_example_wifi_mqtt_client/source/main.c ~/mtb_projects/mtb_example_wifi_mqtt_client/source/main.c.bkup
$ cp .snippet1.c ~/mtb_projects/mtb_example_wifi_mqtt_client/source/main.c

$ line=$(expr `awk '/==========/{c++} c==2{ print NR; exit }' ~/mtb_projects/mtb_example_wifi_mqtt_client/source/main.c` + 1)
$ sed -i ${line}'i\\n    snippet_1();\n    snippet_2();' ~/mtb_projects/mtb_example_wifi_mqtt_client/source/main.c
```

Rebuild the project:
```all
$ cd ~/mtb_projects/mtb_example_wifi_mqtt_client
$ make clean
$ make build -j$(nproc)
```

### Mbed TLS Examples

To run the Mbed TLS examples on the MTB project, some features of the Mbed TLS library, which are disabled by default, need to be enabled:

```all
$ cp ~/mtb_projects/mtb_example_wifi_mqtt_client/configs/mbedtls_user_config.h ~/mtb_projects/mtb_example_wifi_mqtt_client/configs/mbedtls_user_config.h.bkup
$ sed -i 's/#undef MBEDTLS_X509_CSR_WRITE_C//g' ~/mtb_projects/mtb_example_wifi_mqtt_client/configs/mbedtls_user_config.h
$ sed -i 's/#undef MBEDTLS_X509_CRT_WRITE_C//g' ~/mtb_projects/mtb_example_wifi_mqtt_client/configs/mbedtls_user_config.h
$ sed -i 's/#undef MBEDTLS_X509_CREATE_C//g' ~/mtb_projects/mtb_example_wifi_mqtt_client/configs/mbedtls_user_config.h
$ sed -i 's/#undef MBEDTLS_X509_CSR_PARSE_C//g' ~/mtb_projects/mtb_example_wifi_mqtt_client/configs/mbedtls_user_config.h
```

Copy the code along with the examples into your MTB project by:
```all
$ cp ~/psoc6-aws-iot-optiga-tpm/src/mbedtls_* ~/mtb_projects/mtb_example_wifi_mqtt_client/source/
```

Add the following code snippets to the `main.c` file in the MTB project. However, hold on! Scripts are provided below to automate the copying of code for your convenience.:

```snippet2
#include "mbedtls_examples.h"

void snippet_1()
{
    mbedtls_examples();
}
```

Here is a script for automating the copying of the code snippets:
```all
$ cd ~/psoc6-aws-iot-optiga-tpm
$ sed -n $(expr `awk '/\`\`\`snippet2/{c++} c==1{ print NR; exit }' README.md` + 1)',$p' README.md > .README.md.tmp
$ sed `awk '/\`\`\`/{c++} c==1{ print NR; exit }' .README.md.tmp`',$d' .README.md.tmp > .snippet2.c
$ cat ~/mtb_projects/mtb_example_wifi_mqtt_client/source/main.c.bkup >> .snippet2.c
$ cp .snippet2.c ~/mtb_projects/mtb_example_wifi_mqtt_client/source/main.c

$ line=$(expr `awk '/==========/{c++} c==2{ print NR; exit }' ~/mtb_projects/mtb_example_wifi_mqtt_client/source/main.c` + 1)
$ sed -i ${line}'i\\n    snippet_1();' ~/mtb_projects/mtb_example_wifi_mqtt_client/source/main.c
```

Rebuild the project:
```all
$ cd ~/mtb_projects/mtb_example_wifi_mqtt_client
$ make clean
$ make build -j$(nproc)
```

### TPM-based Device Onboarding to AWS IoT Core

Based on what you have learned from the Mbed TLS examples, you can now prepare the MTB project for device onboarding to AWS IoT Core:
1. Provision the TPM with the desired key.
2. Generate the associated CSR (Certificate Signing Request).
3. Onboard the PSoC6 to AWS IoT Core by submitting the CSR and, in exchange, obtaining the AWS CA-signed client certificate.
4. Instead of using a software key, modify the code to accept the TPM-based `mbedtls_pk_context` key object. The file to be modified is `~/mtb_shared/secure-sockets/release-v3.3.0/source/COMPONENT_MBEDTLS/cy_tls.c`; look for `mbedtls_pk_init(...)`. The initialization of the key object can be found in the provided Mbed TLS examples.
5. Configure the WiFi connection in `~/mtb_projects/mtb_example_wifi_mqtt_client/configs/wifi_config.h`.
6. Lastly, configure the MQTT connection in `~/mtb_projects/mtb_example_wifi_mqtt_client/configs/mqtt_client_config.h`:
    - `ROOT_CA_CERTIFICATE`: The AWS CA certificate.
    - `CLIENT_CERTIFICATE`: The client certificate.
    - `MQTT_USERNAME`: Leave it empty.
    - `MQTT_BROKER_ADDRESS`: Your AWS IoT endpoint address.
    - `MQTT_PORT`: 8883

## Miscellaneous

### Running TPM2-TSS Examples on Linux

Build and install tpm2-tss on the host machine:
```all
$ cd ~/tpm2-tss
$ git clean -fxd
$ git reset --hard
$ ./bootstrap
$ ./configure
$ make -j$(nproc)
$ sudo make install -j$(nproc)
```

Set up a TPM simulator:
```all
# Install dependencies
$ sudo apt install -y dh-autoreconf libtasn1-6-dev net-tools libgnutls28-dev expect gawk socat libfuse-dev libseccomp-dev make libjson-glib-dev gnutls-bin

# Install libtpms-devel
$ git clone https://github.com/stefanberger/libtpms ~/libtpms
$ cd ~/libtpms
$ git checkout v0.9.5
$ ./autogen.sh --with-tpm2 --with-openssl
$ make -j$(nproc)
$ sudo make install
$ sudo ldconfig

# Install Libtpms-based TPM emulator
$ git clone https://github.com/stefanberger/swtpm ~/swtpm
$ cd ~/swtpm
$ git checkout v0.7.3
$ ./autogen.sh --with-openssl --prefix=/usr
$ make -j$(nproc)
$ sudo make install
$ sudo ldconfig
```

Launch the TPM simulator:
```all
$ mkdir /tmp/emulated_tpm
$ swtpm_setup --tpm2 --create-config-files overwrite,root

# Initialize the swtpm
$ swtpm_setup --tpm2 --config ~/.config/swtpm_setup.conf --tpm-state /tmp/emulated_tpm --overwrite --create-ek-cert --create-platform-cert --write-ek-cert-files /tmp/emulated_tpm

# Launch the swtpm
$ swtpm socket --tpm2 --flags not-need-init --tpmstate dir=/tmp/emulated_tpm --server type=tcp,port=2321 --ctrl type=tcp,port=2322 &
$ sleep 5
```

Build the example:
```all
$ cd ~/psoc6-aws-iot-optiga-tpm/src
$ gcc -Wall -o test \
  linux_main.c tss2_examples.c tss2_util.c \
  -ltss2-tctildr -ltss2-esys -ltss2-rc \
  -fsanitize=address \
  -DDEBUG \
  -DTCTILDR_ENABLE \
  -DPLATFORM_LOCK_TEST \
  -DTCTI_NAME_CONF=\"swtpm:host=localhost,port=2321\"
```

Execute the example:
```all
$ ./test

# Perform a hardware TPM reset to re-enable the platform hierarchy.
# For further details, refer to PLATFORM_LOCK_TEST in the source code.
$ swtpm_ioctl --tcp localhost:2322 -i
```

### Running Mbed TLS Examples on Linux

Launch the TPM simulator according to prior instructions.

Set up the Mbed TLS library on your Linux system:
```all
# Install dependencies
$ sudo apt install -y cmake

# Install Mbed TLS library
$ git clone https://github.com/Mbed-TLS/mbedtls/ ~/mbedtls
$ cd ~/mbedtls
$ git checkout mbedtls-2.25.0
$ mkdir build_dir
$ cd build_dir
$ cmake -DCMAKE_BUILD_TYPE=Debug -DUSE_SHARED_MBEDTLS_LIBRARY=On -DCMAKE_C_FLAGS="-Wno-error=free-nonheap-object" ..
$ cmake --build .
```

Build the example:
```all
$ cd ~/psoc6-aws-iot-optiga-tpm/src
$ gcc -Wall -o test \
  linux_mbedtls_main.c mbedtls_examples.c mbedtls_tpm.c \
  mbedtls_tpm_pk_rsa.c mbedtls_tpm_pk_ecp.c \
  mbedtls_tpm_entropy.c tss2_util.c \
  -I${HOME}/mbedtls/library \
  -I${HOME}/mbedtls/build_dir/include \
  -L${HOME}/mbedtls/build_dir/library \
  -lmbedcrypto -lmbedtls -lmbedx509 \
  -ltss2-tctildr -ltss2-esys -ltss2-rc \
  -fsanitize=address \
  -DDEBUG \
  -DTCTILDR_ENABLE \
  -DTCTI_NAME_CONF=\"swtpm:host=localhost,port=2321\"
```

Execute the example:
```all
$ LD_LIBRARY_PATH=${HOME}/mbedtls/build_dir/library ./test
```

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
