%{

/* bulk_extractor include statements */
#include "config.h"

/* C include statements */
#include <cstring>
#include <cstdlib>
#include <stdio.h>

/* C include sha */
#ifndef Keccak_more_compact_h
#define Keccak_more_compact_h
extern "C" {
    #include "extern/Keccak-more-compact.h"
}
#endif

/* Include the flex scanner */
#include "sbuf_flex_scanner.h"


class ethereum_scanner : public sbuf_scanner {
public:
    ethereum_scanner(const scanner_params &sp):
        sbuf_scanner(*sp.sbuf),
        ethereum_recorder(sp.named_feature_recorder("ethereum")),
        alert_recorder(sp.named_feature_recorder(feature_recorder_set::ALERT_RECORDER_NAME)){
        }

        class feature_recorder &ethereum_recorder;
        class feature_recorder &alert_recorder;
};

#define YY_EXTRA_TYPE ethereum_scanner * /* holds our class pointer */
YY_EXTRA_TYPE yyethereum_get_extra (yyscan_t yyscanner ); 
 
inline class ethereum_scanner *get_extra(yyscan_t yyscanner) {
  return yyethereum_get_extra(yyscanner);
}


bool check_address_checksum(const char* buf, int len) {
    int start = 2;
    char subbuff[len + 1 - start]; //without 0x

    memset(subbuff, '\0', sizeof(subbuff));
    memcpy(subbuff, &buf[start], len - start);

//~ all lower case
    size_t i;
    for (i = 0; i < len; i++) {
        subbuff[i] = tolower(subbuff[i]);
    }
    
    // Check each case
    uint8_t output[32];
    FIPS202_SHA3_256((uint8_t*)subbuff, len - start, output);

    for (i = 0; i < sizeof(subbuff)/2; i++) {
            //~ printf("%.2X", output[i]);
            
            int high = output[i]>>4;
            int low = output[i]&0xF;
            
            if (high >= 8) {
                //~ printf(": %i --> 1 yes\n", high);
                if (buf[i*2+2] != toupper(subbuff[i*2])) {
                    //~ printf("bad %c not %c\n", buf[i*2+2], toupper(subbuff[i*2]));
                    return 0;
                }
            } else {
                if (buf[i*2+2] != subbuff[i*2]) {
                    //~ printf("\tbad %c not %c\n", buf[i*2+2], subbuff[i*2]);
                    return 0;
                }
            }
                
            if (low >= 8) {
                //~ printf(": %i --> 2 yes\n", low);
                if (buf[i*2+2+1] != toupper(subbuff[i*2+1])) {
                    //~ printf("bad %c not %c\n", buf[i*2+1+2], toupper(subbuff[i*2+1]));
                    return 0;
                }
            } else {
                if (buf[i*2+2+1] != subbuff[i*2+1]) {
                    //~ printf("\tbad %c not %c\n", buf[i*2+1+2], subbuff[i*2+1]);
                    return 0;
                }
            }
    }

    /* Return true (1) all tests passed */
    return 1;
}


#define SCANNER "scan_ethereum"

%}

%option reentrant
%option noyywrap
%option 8bit
%option batch
%option case-sensitive
%option pointer
%option noyymore
%option prefix="yyethereum_"

FORMIDENT 0x
LOWER [0-9a-f]
UPPER [0-9A-F]
CHECKSUM [0-9a-fA-F]


%%

{FORMIDENT}{LOWER}{40} {

    ethereum_scanner &s = *yyethereum_get_extra(yyscanner);
    //possible addresses unfortunately without the possibility of verification
    s.ethereum_recorder.write_buf(SBUF, POS, yyleng);
    s.pos += yyleng;
    
}

{FORMIDENT}{UPPER}{40} {

    ethereum_scanner &s = *yyethereum_get_extra(yyscanner);
    //possible addresses unfortunately without the possibility of verification
    s.ethereum_recorder.write_buf(SBUF, POS, yyleng);
    s.pos += yyleng;
    
}

{FORMIDENT}{CHECKSUM}{40} {

    ethereum_scanner& s = *yyethereum_get_extra(yyscanner);
    if (check_address_checksum(yytext, yyleng)) {
        s.ethereum_recorder.write_buf(SBUF, POS, yyleng);
    }
    s.pos += yyleng;

}

.|\n { 
     /**
      * The no-match rule.
      * If we are beyond the end of the margin, call it quits.
      */
     ethereum_scanner &s = *yyethereum_get_extra(yyscanner);
     /* putchar(yytext[0]); */ /* Uncomment for debugging */
     s.pos++; 
}

%%

extern "C"
void scan_ethereum(struct scanner_params &sp) {
    //assert(sp.sp_version==scanner_params::CURRENT_SP_VERSION);
    sp.check_version();
    if ( sp.phase==scanner_params::PHASE_INIT ) {
        //assert(sp.info->si_version==scanner_info::CURRENT_SI_VERSION);
        sp.info->set_name("ethereum");
        sp.info->author         = "Christian C., https://github.com/cc-code-public";
        sp.info->description    = "Scans for ETH Addresses";
        sp.info->scanner_version= "0.11";
        
        /* Define the feature files this scanner created */
        //sp.info->feature_names.insert(FEATURE_NAME);
        sp.info->feature_defs.push_back( feature_recorder_def( "ethereum" ));

        /* Define the histograms to make */
        //sp.info->histogram_defs.insert(histogram_def("url","","histogram"));


        /*scan_btc_valid_debugg = sp.info->config->debug;*/  // get debug value
        return;
    }
    if ( sp.phase==scanner_params::PHASE_SCAN ) {
        ethereum_scanner lexer(sp);
        yyscan_t scanner;
        yyethereum_lex_init(&scanner);
        yyethereum_set_extra(&lexer,scanner);
        try {
            yyethereum_lex(scanner);
        }
        catch (sbuf_scanner::sbuf_scanner_exception &e ) {
            std::cerr << "Scanner " << SCANNER << "Exception " << e.what() << " processing " << sp.sbuf->pos0 << "\n";
        }
                
        yyethereum_lex_destroy(scanner);
    }
    if ( sp.phase==scanner_params::PHASE_INIT ) {
        // avoids defined but not used
        (void)yyunput;
        (void)yy_fatal_error;
    }
}
