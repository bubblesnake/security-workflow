#!/usr/bin/env bash

espsecure.py sign_data --version 2 --keyfile ~/esp/projects/security-workflow/secure_boot_signing_key.pem --output bootloader-signed.bin build/bootloader/bootloader.bin
espsecure.py sign_data --version 2 --keyfile ~/esp/projects/security-workflow/secure_boot_signing_key.pem --output hello-world-signed.bin build/hello_world.bin

espsecure.py encrypt_flash_data --aes_xts --keyfile ~/esp/projects/security-workflow/my_flash_encryption_key.bin --address 0x2000 --output bootloader-signed-enc.bin ./bootloader-signed.bin
espsecure.py encrypt_flash_data --aes_xts --keyfile ~/esp/projects/security-workflow/my_flash_encryption_key.bin --address 0x12000 --output partition-table-enc.bin build/partition_table/partition-table.bin
espsecure.py encrypt_flash_data --aes_xts --keyfile ~/esp/projects/security-workflow/my_flash_encryption_key.bin --address 0x20000 --output hello-world-signed-enc.bin ./hello-world-signed.bin

esptool.py -p /dev/cu.usbserial-1110 --chip esp32c5 write_flash --force 0x2000 ./bootloader-signed-enc.bin
esptool.py -p /dev/cu.usbserial-1110 --chip esp32c5 write_flash --force 0x12000 ./partition-table-enc.bin
esptool.py -p /dev/cu.usbserial-1110 --chip esp32c5 write_flash --force 0x20000 ./hello-world-signed-enc.bin
