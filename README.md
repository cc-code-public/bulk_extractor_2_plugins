# bulk_extractor_2_plugins
Digital currency and more plugins for bulk_extractor version 2.0 beta
# bulk_extractor_plugins
Digital currency and more plugins for [bulk_extractor](https://github.com/simsong/bulk_extractor) version 2.0 beta by @simsong


If you are looking for predecessor plugins: https://github.com/cc-code-public/bulk_extractor_1_6_plugins

Included:
-------------------------------------------------
All plugins are designed to be used offline. All verification processes are implemented in the plugins themselves.

* bitcoin:
  * P2PKH and P2SH verified by sha256 checksum 
  * P2WPKH verified by bech32 checksum
 
* monero:
  * Standard-Address
  * Subaddress
  * Integrated-Address
all verified by Keccak-f[1600] (FIPS202_SHA3_256()) checksums

* mnemonic:
  * BIP-0039
  * Electrum Wallets (> version 2.0)
only englisch dictionaries and verified by HMAC-SHA-512

* ethereum:
  * Adresses without checksum
  * Adresses with checksum are verified (FIPS202_SHA3_256())

* hardware wallets:
  * supported hardware wallets: Trezor, Trezor v2, Ledger HW.1 / Nano, 'Ledger Blue /  Nano S / Aramis / HW.2 / Nano X, coinkite, digitalbox / bitbox, safe-t, keepkey
  * Windows Registry format "VID_XXXX&PID_XXXX"
  * Linux log format "XXXX:XXXX"

* domains:
  * Search against a SECONDLEVEL.TOPLEVEL domain list (domains_list.csv)
  * This plugin is disabled by default. If you want to use it start bulk with the parameter: **-e domains**
The file has to be located in the current execution path
 
* tor addresses:
  * v2 no verification possible
  * v3 verified by sha3-256 checksum
 

Installation for Ubuntu 20 LTS:
-------------------------------------------------

- sudo apt install git  
- sudo apt install sleuthkit libafflib-dev
(Others as require. For example: sudo apt install libsqlite3-dev)  

- mkdir ~/Development  
- cd ~/Development  
- git clone https://github.com/simsong/bulk_extractor.git --recursive  
(INFO: bulk_extractor version 2.0. Do not forget that **recursive**, because there are dependencies to other repositories now!)  
- cd bulk_extractor  
- bash etc/CONFIGURE_UBUNTU20LTS.bash  
(Or any other suitable script in the etc directory. Otherwise you will have to install the dependencies by hand.)

- cp src/Makefile.am src/Makefile.am.bak  
- ***Add*** to _src/Makefile.am_:  
  - Extend the variable **CLEANFILES** with:  
  "scan_bitcoin.cpp scan_monero.cpp scan_domains.cpp scan_ethereum.cpp scan_hwallets.cpp scan_mnemonics.cpp scan_torurls.cpp"  

  As an example, the passage in the file could look like this:
  ```
  CLEANFILES     = scan_accts.cpp scan_base16.cpp scan_email.cpp scan_gps.cpp \
   scan_bitcoin.cpp scan_monero.cpp scan_domains.cpp scan_ethereum.cpp scan_hwallets.cpp scan_mnemonics.cpp scan_torurls.cpp \
   be13_api/config.h be13_api/dfxml/src/config.h config.h *.d *~
  ```  

  - Extend the variable **flex_scanners** with:  
  "scan_bitcoin.flex \  
   extern/Keccak-more-compact.h extern/Keccak-more-compact.c \  
   scan_monero.flex \  
   scan_ethereum.flex \  
   scan_hwallets.flex \  
   scan_mnemonics.flex \  
   scan_domains.flex \  
   scan_torurls.flex extern/base32.h extern/base32.c"  

  As an example, the passage in the file could look like this:
  ```
  flex_scanners = \
   sbuf_flex_scanner.h \
   scan_base16.flex \
   scan_accts.flex \
   scan_email.flex scan_email.h \
   scan_gps.flex \
   scan_bitcoin.flex \
   extern/Keccak-more-compact.h extern/Keccak-more-compact.c \
   scan_monero.flex \
   scan_ethereum.flex \
   scan_hwallets.flex \
   scan_mnemonics.flex \
   scan_domains.flex \
   scan_torurls.flex extern/base32.h extern/base32.c
  ```  

- cp src/bulk_extractor_scanners.h src/bulk_extractor_scanners.h.bak  
- ***Add*** to _src/bulk_extractor_scanners.h_:  
  - Extend the list of **flex-based scanners** with:  
    "SCANNER(bitcoin)  
    SCANNER(monero)  
    SCANNER(domains)  
    SCANNER(ethereum)  
    SCANNER(hwallets)  
    SCANNER(mnemonics)  
    SCANNER(torurls)"  

  As an example, the passage in the file could look like this:
  ```
  /* flex-based scanners */
  SCANNER(base16)
  SCANNER(email)
  SCANNER(accts)
  SCANNER(gps)
  SCANNER(bitcoin)
  SCANNER(monero)
  SCANNER(domains)
  SCANNER(ethereum)
  SCANNER(hwallets)
  SCANNER(mnemonics)
  SCANNER(torurls)
  ```  

- cd ~/Development  
- git clone https://github.com/cc-code-public/bulk_extractor_2_plugins.git  
- cd bulk_extractor_2_plugins  
  
  
- cp -R extern ~/Development/bulk_extractor/src  
- cp scan_bitcoin.flex scan_domains.flex domains_list.csv scan_hwallets.flex scan_mnemonics.flex scan_monero.flex scan_torurls.flex scan_ethereum.flex ~/Development/bulk_extractor/src  
  
  
- cd ~/Development/bulk_extractor/  
- bash bootstrap.sh  
- ./configure  
- make  
(**make install** if you want)

-------------------------------------------------

**And it is DONE!**

****ADDITIONAL****  
Currently the plugin system of bulk is not used. Instead, the plugins are integrated directly into bulk_extractor. They should therefore be available for each execution without using special configuration.
The plugins have been tested but are still under development and more or less proof of concepts. Therefore they are offered as is. 
