%{

/* bulk_extractor include statements */
#include "config.h"

/* C include statements */
#include <cstring>
#include <cstdlib>

/* C include sha */
#include <openssl/sha.h>
#include <stdio.h>

/* bech32 reference https://github.com/sipa/bech32/tree/master/ref/c */
#include "extern/segwit_addr.h"
#include "extern/segwit_addr.c"


/* Include the flex scanner */
#include "sbuf_flex_scanner.h"

class bitcoin_scanner : public sbuf_scanner {
public:
    bitcoin_scanner(const scanner_params &sp):
        sbuf_scanner(*sp.sbuf),
        bitcoin_recorder(sp.named_feature_recorder("bitcoin")),
        alert_recorder(sp.named_feature_recorder(feature_recorder_set::ALERT_RECORDER_NAME)){
        }

        class feature_recorder &bitcoin_recorder;
        class feature_recorder &alert_recorder;
};

#define YY_EXTRA_TYPE bitcoin_scanner * /* holds our class pointer */
YY_EXTRA_TYPE yybitcoin_get_extra (yyscan_t yyscanner ); 

inline class bitcoin_scanner *get_extra(yyscan_t yyscanner) {
  return yybitcoin_get_extra(yyscanner);
}



/*
* Validity check for bitcoin.
* copied from:
* https://rosettacode.org/wiki/Bitcoin/address_validation#C
*/

int unbase58(const char *s, unsigned char *out) {

    //~ [a-km-zA-HJ-NP-Z1-9]
    static const char *tmpl = "123456789"
        "ABCDEFGHJKLMNPQRSTUVWXYZ"
        "abcdefghijkmnopqrstuvwxyz";
    int i, j, c;
    const char *p;

    //~ fill 35 bytes from start of pointer with 0
    memset(out, 0, 35);
    for (i = 0; s[i]; i++) {

        //~ compare with allowed character
        if (!(p = strchr(tmpl, s[i]))) {
            //~ bad char
            return 0;
        }

        c = p - tmpl;

        for (j = 25; j--; ) {
            c += 58 * out[j];
            out[j] = c % 256;
            c /= 256;
        }

        if (c) {
            //~ address too long
            return 0;
        }
    }


    return 1;
}

int valid_bitcoin(const char *s) {
    unsigned char dec[35], d1[SHA256_DIGEST_LENGTH], d2[SHA256_DIGEST_LENGTH];

    if (!unbase58(s, dec)) {
        return 0;
    }
 
    SHA256(SHA256(dec, 21, d1), SHA256_DIGEST_LENGTH, d2);
 
    if (memcmp(dec + 21, d2, 4)) {
        //~ bad digest
        return 0;
    }
 
    return 1;
}


bool check_base58(const char *buf, int len) {

    /* Call the validate digits function */
    if (!valid_bitcoin(buf)) {

    /* Return false (0) if validate test failed */
        return 0;
    }

    /* Return true (1) all tests passed */
    return 1;
}

bool check_bech32(const char *buf, int len) {

    uint8_t witprog[40];
    size_t witprog_len;
    int witver;

    char temps[len+1];
    memset(temps, '\0', sizeof(temps));
    size_t i;
    for ( i = 0; i < len; i++ ) {
        temps[i] = tolower(buf[i]);
    }

    /* BECH32 function */
    if (!segwit_addr_decode(&witver, witprog, &witprog_len, "bc", temps)) {
        return 0;
    }
    
    /* Return true (1) all tests passed */
    return 1;
}

#define SCANNER "scan_bitcoin"

%}

%option reentrant
%option noyywrap
%option 8bit
%option batch
%option case-insensitive
%option pointer
%option noyymore
%option prefix="yybitcoin_"

STARTP  [13]
BLOCKP  [a-km-zA-HJ-NP-Z1-9]{25,35}
STARTBx  (?:BC)|(?:bc)[01]
BLOCKB4   [ac-hj-np-zAC-HJ-NP-Z02-9]{7,76}

%%

{STARTP}{BLOCKP} {

    bitcoin_scanner &s = *yybitcoin_get_extra(yyscanner);
    if(check_base58(yytext, yyleng)){
        s.bitcoin_recorder.write_buf(SBUF, POS, yyleng);
    }    
    s.pos += yyleng;
    
}

{STARTBx}{BLOCKB4} {

    bitcoin_scanner &s = *yybitcoin_get_extra(yyscanner);
    if(check_bech32(yytext, yyleng)){
        s.bitcoin_recorder.write_buf(SBUF, POS, yyleng);
    }
    s.pos += yyleng;
    
}

.|\n { 
     /**
      * The no-match rule.
      * If we are beyond the end of the margin, call it quits.
      */
     bitcoin_scanner &s = *yybitcoin_get_extra(yyscanner);
     /* putchar(yytext[0]); */ /* Uncomment for debugging */
     s.pos++; 
}

%%

extern "C"
void scan_bitcoin(struct scanner_params &sp) {
    //assert(sp.sp_version==scanner_params::CURRENT_SP_VERSION);
    sp.check_version();
    if ( sp.phase==scanner_params::PHASE_INIT ) {
        //assert(sp.info->si_version==scanner_info::CURRENT_SI_VERSION);
        sp.info->set_name("bitcoin");
        sp.info->author         = "Christian C., https://github.com/cc-code-public";
        sp.info->description    = "Scans for BTC Addresses";
        sp.info->scanner_version= "0.72";
        
        /* Define the feature files this scanner created */
        //sp.info->feature_names.insert(FEATURE_NAME);
        sp.info->feature_defs.push_back( feature_recorder_def( "bitcoin" ));

        /* Define the histograms to make */
        //sp.info->histogram_defs.insert(histogram_def("url","","histogram"));


        /*scan_btc_valid_debugg = sp.info->config->debug;*/  // get debug value
        return;
    }
    if ( sp.phase==scanner_params::PHASE_SCAN ) {
        bitcoin_scanner lexer(sp);
        yyscan_t scanner;
        yybitcoin_lex_init(&scanner);
        yybitcoin_set_extra(&lexer,scanner);
        try {
            yybitcoin_lex(scanner);
        }
        catch (sbuf_scanner::sbuf_scanner_exception &e ) {
            std::cerr << "Scanner " << SCANNER << "Exception " << e.what() << " processing " << sp.sbuf->pos0 << "\n";
        }
                
        yybitcoin_lex_destroy(scanner);
    }
    if ( sp.phase==scanner_params::PHASE_INIT ) {
        // avoids defined but not used
        (void)yyunput;
        (void)yy_fatal_error;
    }
}
