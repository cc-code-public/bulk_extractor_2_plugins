%{

/* bulk_extractor include statements */
#include "config.h"

/* C include statements */
#include <cstring>
#include <cstdlib>

/* C include sha */
#ifndef Keccak_more_compact_h
#define Keccak_more_compact_h
extern "C" {
    #include "extern/Keccak-more-compact.h"
}
#endif

/* Include the flex scanner */
#include "sbuf_flex_scanner.h"


class monero_scanner : public sbuf_scanner {
public:
    monero_scanner(const scanner_params &sp):
        sbuf_scanner(*sp.sbuf),
        monero_recorder(sp.named_feature_recorder("monero")),
        alert_recorder(sp.named_feature_recorder(feature_recorder_set::ALERT_RECORDER_NAME)){
        }

        class feature_recorder &monero_recorder;        
        class feature_recorder &alert_recorder;
};

#define YY_EXTRA_TYPE monero_scanner * /* holds our class pointer */
YY_EXTRA_TYPE yymonero_get_extra (yyscan_t yyscanner ); 
 
inline class monero_scanner *get_extra(yyscan_t yyscanner) {
  return yymonero_get_extra(yyscanner);
}

uint64_t safe_add(uint64_t a, uint64_t b) {
    if (a > 0 && b > UINT64_MAX - a) {
        printf("%s\n", "overflow" );
        /* handle overflow */
    } else if (a < 0 && b < 0 - a) {
        /* handle underflow */
        printf("%s\n", "underflow" );
    }
    return a + b;
}

int unbase58(const char *s, uint64_t *value, size_t len) {
    //~ [a-km-zA-HJ-NP-Z1-9]
    static const char *tmpl = "123456789"
        "ABCDEFGHJKLMNPQRSTUVWXYZ"
        "abcdefghijkmnopqrstuvwxyz";
    int b58len = strlen(tmpl);
    uint64_t multi = 1;
    uint64_t c;
    int i;
    const char *p;

    for (i = len - 1; i >= 0; i--) {
        //~ compare with allowed character
        if (!(p = strchr(tmpl, s[i]))) {
            //~ bad char
            return 0;
        }

        c = p - tmpl;
        *value = safe_add(c * multi, *value);
        multi *= b58len;
    }
    return 1;
}


int check_xmr(const char *s, int full_len, int data_len) {
    // 11 or less Base58 characters
    int full_encoded_block_size = 11;
    
    size_t full_block_count = full_len / full_encoded_block_size;
    size_t last_block_size = full_len % full_encoded_block_size;

    int start = 0;
    char subbuff[12];
    char hexbuff[19];
    uint64_t out = 0;

    char hex[data_len];
    int checksum_len = 4;
    char hex_checksum[checksum_len + 1];
    int hexcounter = 0;
    char tmpchar[3];
    
    for ( int i = 0; i < full_block_count; i++) {
        out = 0;
        memcpy( subbuff, &s[start], full_encoded_block_size );
        subbuff[full_encoded_block_size] = '\0';


        if (!unbase58(subbuff, &out, full_encoded_block_size))
            return 0;
            
        memset(hexbuff, '\0', sizeof(hexbuff));
        sprintf(hexbuff, "%016" PRIx64, out);

        for (int j = 0; j < 16; ) {
            memset(tmpchar, '\0', sizeof(tmpchar));
            tmpchar[0] = hexbuff[j];
            j++;
            tmpchar[1] = hexbuff[j];
            j++;
            tmpchar[2] = '\0';
            hex[hexcounter++] = strtol(tmpchar, NULL, 16);
            
        }
        start += full_encoded_block_size;
    }
    
    out = 0;
    memset(subbuff, '\0', sizeof(subbuff));
    memcpy( subbuff, &s[start], last_block_size);
    memset(hexbuff, '\0', sizeof(hexbuff));

    if (!unbase58(subbuff, &out, last_block_size))
            return 0;
    
    sprintf(hexbuff, "%010" PRIx64, out);
    
    for (int j = 0; hexcounter < data_len + checksum_len; ) {
        memset(tmpchar, '\0', sizeof(tmpchar));
        tmpchar[0] = hexbuff[j];
        j++;
        tmpchar[1] = hexbuff[j];
        j++;
        tmpchar[2] = '\0';
        if (hexcounter < data_len) {
            hex[hexcounter] = strtol(tmpchar, NULL, 16);
            hexcounter++;
        } else {
            hex_checksum[hexcounter-data_len] = strtol(tmpchar, NULL, 16);
            hexcounter++;
        }
    }
    
    uint8_t output[(data_len - 1) / 2];
    
    /* Keccak function */
    FIPS202_SHA3_256((uint8_t*)hex, data_len, output);

    if (hex_checksum[0] == (char)output[0] &&
        hex_checksum[1] == (char)output[1] &&
        hex_checksum[2] == (char)output[2] &&
        hex_checksum[3] == (char)output[3]) {
            return 1;
    }
    
    return 0;
}
 

#define SCANNER "scan_monero"
#define XMR_STD_SUB 65
#define XMR_INT 73

%}

%option reentrant
%option noyywrap
%option 8bit
%option batch
%option case-insensitive
%option pointer
%option noyymore
%option prefix="yymonero_"

BLOCK   [a-km-zA-HJ-NP-Z1-9]

START_STD_SUB  [48][0-9AB]
BLOCK_STD_SUB  {BLOCK}{93}

START_INT    4
BLOCK_INT    {BLOCK}{105}
%%

{START_STD_SUB}{BLOCK_STD_SUB} {

    monero_scanner &s = *yymonero_get_extra(yyscanner);
    if(check_xmr(yytext,yyleng, XMR_STD_SUB)){
        s.monero_recorder.write_buf(SBUF,POS,yyleng);
    }    
    s.pos += yyleng;
    
}

{START_INT}{BLOCK_INT} {

    monero_scanner &s = *yymonero_get_extra(yyscanner);
    if(check_xmr(yytext,yyleng, XMR_INT)){
        s.monero_recorder.write_buf(SBUF,POS,yyleng);
    }    
    s.pos += yyleng;
    
}

.|\n { 
     /**
      * The no-match rule.
      * If we are beyond the end of the margin, call it quits.
      */
     monero_scanner &s = *yymonero_get_extra(yyscanner);
     /* putchar(yytext[0]); */ /* Uncomment for debugging */
     s.pos++; 
}

%%

extern "C"
void scan_monero(struct scanner_params &sp) {
    //assert(sp.sp_version==scanner_params::CURRENT_SP_VERSION);
    sp.check_version();
    if ( sp.phase==scanner_params::PHASE_INIT ) {
        //assert(sp.info->si_version==scanner_info::CURRENT_SI_VERSION);
        sp.info->set_name("monero");
        sp.info->author         = "Christian C., https://github.com/cc-code-public";
        sp.info->description    = "Scans for monero Addresses";
        sp.info->scanner_version= "0.62";
        
        /* Define the feature files this scanner created */
        //sp.info->feature_names.insert(FEATURE_NAME);
        sp.info->feature_defs.push_back( feature_recorder_def( "monero" ));

        /* Define the histograms to make */
        //sp.info->histogram_defs.insert(histogram_def("url","","histogram"));


        /*scan_monero_valid_debugg = sp.info->config->debug;*/  // get debug value
        return;
    }
    if ( sp.phase==scanner_params::PHASE_SCAN ) {
        monero_scanner lexer(sp);
        yyscan_t scanner;
        yymonero_lex_init(&scanner);
        yymonero_set_extra(&lexer,scanner);
        try {
            yymonero_lex(scanner);
        }
        catch (sbuf_scanner::sbuf_scanner_exception &e ) {
            std::cerr << "Scanner " << SCANNER << "Exception " << e.what() << " processing " << sp.sbuf->pos0 << "\n";
        }
                
        yymonero_lex_destroy(scanner);
    }
    if ( sp.phase==scanner_params::PHASE_INIT ) {
        // avoids defined but not used
        (void)yyunput;            
        (void)yy_fatal_error;
    }
}
