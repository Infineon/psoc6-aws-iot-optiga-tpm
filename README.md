# PSoC 6 Onboarding to AWS IoT Core</br> using OPTIGA™ TPM SLx 9670 TPM2.0

## Introduction

This repository demonstrates how an [OPTIGA™ TPM SLx 9670 TPM2.0](https://www.infineon.com/cms/en/product/security-smart-card-solutions/optiga-embedded-security-solutions/optiga-tpm/) can be integrated into a [PSoC 6 Wi-Fi BT Prototyping Kit](https://www.cypress.com/documentation/development-kitsboards/psoc-6-wi-fi-bt-prototyping-kit-cy8cproto-062-4343w) to enable TPM backed onboarding to [AWS IoT Core](https://aws.amazon.com/iot-core/).

## Prerequisites

Hardware prerequisites:
- PSoC 6 Wi-Fi BT Prototyping Kit ([CY8CPROTO-062-4343W](https://www.cypress.com/documentation/development-kitsboards/psoc-6-wi-fi-bt-prototyping-kit-cy8cproto-062-4343w))\
  <img src="https://github.com/Infineon/psoc6-aws-iot-optiga-tpm/raw/master/media/CY8CPROTO-062-4343W.png" width="50%">
- [IRIDIUM9670 TPM2.0](https://www.infineon.com/cms/en/product/evaluation-boards/iridium9670-tpm2.0-linux/)\
  <img src="https://github.com/Infineon/psoc6-aws-iot-optiga-tpm/raw/master/media/IRIDIUM9670-TPM2.png" width="30%">

Software prerequisites:
- A host machine with Ubuntu (tested on 18.04.5 LTS) installed
- Familiar with the procedure of building and programming a PSoC 6 using [ModusToolbox](https://www.cypress.com/documentation/application-notes/an228571-getting-started-psoc-6-mcu-modustoolbox)
- Familiar with the ModusToolbox PSoC 6 project [mtb-example-anycloud-mqtt-client](https://github.com/cypresssemiconductorco/mtb-example-anycloud-mqtt-client)

## Getting Started

For detailed setup and information, please find the Application Note at [link](https://github.com/Infineon/psoc6-aws-iot-optiga-tpm/raw/master/documents/tpm-appnote-psoc6-aws-iot.pdf).

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
