%{

/* bulk_extractor include statements */
#include "config.h"


/* C include statements */
#include <cstring>
#include <ctype.h>

extern "C" {
    #include "extern/base32.h"
}

/**
 * openssl
 */
#include <openssl/evp.h>

/* Include the flex scanner */
#include "sbuf_flex_scanner.h"


class torurls_scanner : public sbuf_scanner {
public:
    torurls_scanner(const scanner_params &sp):
        sbuf_scanner(*sp.sbuf),
        torurls_recorder(sp.named_feature_recorder("torurls")),
        alert_recorder(sp.named_feature_recorder(feature_recorder_set::ALERT_RECORDER_NAME)){
        }

        class feature_recorder &torurls_recorder;
        class feature_recorder &alert_recorder;
};

#define YY_EXTRA_TYPE torurls_scanner * /* holds our class pointer */
YY_EXTRA_TYPE yytorurls_get_extra (yyscan_t yyscanner );

inline class torurls_scanner *get_extra(yyscan_t yyscanner) {
  return yytorurls_get_extra(yyscanner);
}

#define ONION_V2 16
#define ONION_V3 56


int validate_torurl(const char *buf) {

	//~ copy second lvl domain
    char toraddress[ONION_V3+1];
    memset(toraddress, '\0', ONION_V3+1);
    memcpy(toraddress, buf, ONION_V3);

	//~ all uppercase
	for(int i=0;i<strlen(toraddress);i++){
        toraddress[i] = toupper(toraddress[i]);
    }
    
	int plain_buffer_len = 36;
    unsigned char plain_buffer[plain_buffer_len];
    memset(plain_buffer, '\0', plain_buffer_len);
    
    const unsigned char *coded = (const unsigned char*)toraddress;
    unsigned char *plain = plain_buffer;
    //~ decode second lvl domain
    //~ onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
    base32_decode(coded, plain);

    //~ VERSION == v3?
    if (plain[34] != '\x03') {
		return 0;
	}

	//~ prepair CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]
	int hash_plain_len = 48;
	unsigned char hash_plain[hash_plain_len+1];
    memset(hash_plain, '\0', hash_plain_len+1);
	memcpy(hash_plain, (const char*)".onion checksum", 15);
	memcpy(hash_plain+15, plain, 32);
	memcpy(hash_plain+47, (const char*)"\x03", 1);
	
//~ ###########################################################
	//~ openssl sha3-256

	EVP_MD_CTX * mdctx;
	unsigned char * digest;
	unsigned int digest_len;
	const EVP_MD * algo = EVP_sha3_256();


	if ((mdctx = EVP_MD_CTX_new()) == NULL) {
		return 0;
	}

	// initialize digest engine
	if (EVP_DigestInit_ex(mdctx, algo, NULL) != 1) { // returns 1 if successful
		return 0;
	}

	if (EVP_DigestUpdate(mdctx, (const char*)hash_plain, hash_plain_len) != 1) { // returns 1 if successful
		return 0;
	}

	digest_len = EVP_MD_size(algo);

	if ((digest = (unsigned char *)OPENSSL_malloc(digest_len)) == NULL) {
		return 0;
	}

	// produce digest
	if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) { // returns 1 if successful
		OPENSSL_free(digest);
		return 0;
	}

	if (plain[32] == digest[0] && plain[33] == digest[1]) {
		return 1;
	}
	

	OPENSSL_free(digest);
	EVP_MD_CTX_free(mdctx);	
	
    
	return  0;
}

#define SCANNER "scan_torurls"

%}

%option reentrant
%option noyywrap
%option 8bit
%option batch
%option case-insensitive
%option pointer
%option noyymore
%option prefix="yytorurls_"
%option yylineno

TLD     (\.onion)
BASE32		[a-zA-Z2-7]
%%


{BASE32}{56}{TLD} {
	//~ v3
	torurls_scanner &s = *yytorurls_get_extra(yyscanner);
    
    if(validate_torurl(yytext)){
        s.torurls_recorder.write_buf(SBUF,POS,yyleng);
    }
    s.pos += yyleng; 
}

{BASE32}{16}{TLD} {
	//~ v2
    torurls_scanner &s = *yytorurls_get_extra(yyscanner);
    s.torurls_recorder.write_buf(SBUF,POS,yyleng);
    s.pos += yyleng;
}

.|\n {
     /**
      * The no-match rule.
      * If we are beyond the end of the margin, call it quits.
      */
     torurls_scanner &s = *yytorurls_get_extra(yyscanner);
     /* putchar(yytext[0]); */ /* Uncomment for debugging */
     s.pos++;
}

%%

extern "C"
void scan_torurls(struct scanner_params &sp) {
    //assert(sp.sp_version==scanner_params::CURRENT_SP_VERSION);
    sp.check_version();
    if ( sp.phase==scanner_params::PHASE_INIT ) {
        //assert(sp.info->si_version==scanner_info::CURRENT_SI_VERSION);
        sp.info->set_name("torurls");
        sp.info->author         = "Christian C., https://github.com/cc-code-public";
        sp.info->description    = "Scans for tor onion urls v2 and v3";
        sp.info->scanner_version= "0.11";

        /* Define the feature files this scanner created */
        //sp.info->feature_names.insert(FEATURE_NAME);
        sp.info->feature_defs.push_back( feature_recorder_def( "torurls" ));

        /* Define the histograms to make */
        //sp.info->histogram_defs.insert(histogram_def("url","","histogram"));


        /*scan_torurls_valid_debugg = sp.info->config->debug;*/  // get debug value
        return;
    }
    if ( sp.phase==scanner_params::PHASE_SCAN ) {
        torurls_scanner lexer(sp);
        yyscan_t scanner;
        yytorurls_lex_init(&scanner);
        yytorurls_set_extra(&lexer,scanner);

        try {
            yytorurls_lex(scanner);
        }
        catch (sbuf_scanner::sbuf_scanner_exception &e ) {
            std::cerr << "Scanner " << SCANNER << "Exception " << e.what() << " processing " << sp.sbuf->pos0 << "\n";
        }

        yytorurls_lex_destroy(scanner);
    }
    if ( sp.phase==scanner_params::PHASE_INIT ) {
        // avoids defined but not used
        (void)yyunput;
        (void)yy_fatal_error;
    }
}
