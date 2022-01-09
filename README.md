# bulk_extractor_2_plugins
Digital currency and more plugins for bulk_extractor version 2.0 beta
# bulk_extractor_plugins
Digital currency plugins for bulk_extractor version 1.6.0  

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

sudo apt install git  
sudo apt install sleuthkit libafflib-dev libewf-dev  
(Others as require. For example: sudo apt install libsqlite3-dev)  

mkdir ~/Development  
cd ~/Development  
git clone https://github.com/simsong/bulk_extractor.git --recursive  
(INFO: bulk_extractor version 2.0. Do not forget that **recursive**, because there are dependencies to other repositories now!)  
cd bulk_extractor  
bash etc/CONFIGURE_UBUNTU20LTS.bash  
mv src/Makefile.am src/Makefile.am.bak  
mv src/bulk_extractor_scanners.h src/bulk_extractor_scanners.h.bak  

cd ~/Development  
git clone https://github.com/cc-code-public/bulk_extractor_2_plugins.git  
cd bulk_extractor_2_plugins  

cp -R extern ~/Development/bulk_extractor/src  
cp Makefile.am bulk_extractor_scanners.h scan_bitcoin.flex scan_domains.flex scan_hwallets.flex scan_mnemonics.flex scan_monero.flex scan_torurls.flex scan_ethereum.flex ~/Development/bulk_extractor/src  

cd ~/Development/bulk_extractor/  
bash bootstrap.sh  
./configure  
make  
(**make install** if you want)

-------------------------------------------------

**And it is DONE!**

****ADDITIONAL****  
Currently the plugin system of bulk is not used. Instead, the plugins are integrated directly into bulk_extractor. They should therefore be available for each execution without using special configuration.
The plugins have been tested but are still in development. Therefore they are offered as is. 
