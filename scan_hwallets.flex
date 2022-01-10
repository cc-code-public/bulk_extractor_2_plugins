%{
/* https://github.com/spesmilo/electrum/tree/master/contrib/udev */

/* bulk_extractor include statements */
#include "config.h"


/* Include the flex scanner */
#include "sbuf_flex_scanner.h"


class hwallets_scanner : public sbuf_scanner {
public:
	hwallets_scanner(const scanner_params &sp):
		sbuf_scanner(*sp.sbuf),
		hwallets_recorder(sp.named_feature_recorder("hwallets")),
        alert_recorder(sp.named_feature_recorder(feature_recorder_set::ALERT_RECORDER_NAME)){
		}

		class feature_recorder &hwallets_recorder;		
		class feature_recorder &alert_recorder;
};


#define YY_EXTRA_TYPE hwallets_scanner * /* holds our class pointer */
YY_EXTRA_TYPE yyhwallets_get_extra (yyscan_t yyscanner ); 
 
inline class hwallets_scanner *get_extra(yyscan_t yyscanner) {
    return yyhwallets_get_extra(yyscanner);
}


#define SCANNER "scan_hwallets"

%}

%option reentrant
%option noyywrap
%option 8bit
%option batch
%option case-insensitive
%option pointer
%option noyymore
%option prefix="yyhwallets_"


%%

((VID_)?03eb(:|&PID_)240[23]) {
    //~ digitalbitbox, bitbox02 Windows
    hwallets_scanner &s = *yyhwallets_get_extra(yyscanner);
    s.hwallets_recorder.write_buf(SBUF,POS,yyleng);
    s.pos += yyleng; 
}

((VID_)?0e79(:|&PID_)000[12]) {
    //~ keepkey Windows
    hwallets_scanner &s = *yyhwallets_get_extra(yyscanner);
    s.hwallets_recorder.write_buf(SBUF,POS,yyleng);
    s.pos += yyleng; 
}

((VID_)?0e79(:|&PID_)600[01]) {
    //~ safe-t Windows
    hwallets_scanner &s = *yyhwallets_get_extra(yyscanner);
    s.hwallets_recorder.write_buf(SBUF,POS,yyleng);
    s.pos += yyleng; 
}

((VID_)?d13e(:|&PID_)cc10) {
    //~ Coinkite Windows
    hwallets_scanner &s = *yyhwallets_get_extra(yyscanner);
    s.hwallets_recorder.write_buf(SBUF,POS,yyleng);
    s.pos += yyleng; 
}

((VID_)?2581(:|&PID_)([1234]b7c)|(VID_)?2c97(:|&PID_)([01234]0[01][0123456789abcdef])) {
    //~ Ledger Windows
    hwallets_scanner &s = *yyhwallets_get_extra(yyscanner);
    s.hwallets_recorder.write_buf(SBUF,POS,yyleng);
    s.pos += yyleng; 
}

((VID_)?534c(:|&PID_)0001|(VID_)?1209(:|&PID_)53c[01]) {
    //~ Trezor Windows
    hwallets_scanner &s = *yyhwallets_get_extra(yyscanner);
    s.hwallets_recorder.write_buf(SBUF,POS,yyleng);
    s.pos += yyleng; 
}

.|\n { 
    /**
    * The no-match rule.
    * If we are beyond the end of the margin, call it quits.
    */
    hwallets_scanner &s = *yyhwallets_get_extra(yyscanner);
    /* putchar(yytext[0]); */ /* Uncomment for debugging */
    s.pos++; 
}

%%

extern "C"
void scan_hwallets(struct scanner_params &sp) {
    //assert(sp.sp_version==scanner_params::CURRENT_SP_VERSION);
    sp.check_version();
    if ( sp.phase==scanner_params::PHASE_INIT ) {
        //assert(sp.info->si_version==scanner_info::CURRENT_SI_VERSION);
        sp.info->set_name("hwallets");
        sp.info->author         = "Christian C., https://github.com/cc-code-public";
        sp.info->description    = "Scans for hardware wallets";
        sp.info->scanner_version= "0.14";
        
        /* Define the feature files this scanner created */
        //sp.info->feature_names.insert(FEATURE_NAME);
        sp.info->feature_defs.push_back( feature_recorder_def( "hwallets" ));

        /* Define the histograms to make */
        //sp.info->histogram_defs.insert(histogram_def("url","","histogram"));


        /*scan_hwallets_valid_debugg = sp.info->config->debug;*/  // get debug value
        return;
    }
    if ( sp.phase==scanner_params::PHASE_SCAN ) {
        hwallets_scanner lexer(sp);
		yyscan_t scanner;
        yyhwallets_lex_init(&scanner);
		yyhwallets_set_extra(&lexer,scanner);
        
        
        try {
            yyhwallets_lex(scanner);
        }
        catch (sbuf_scanner::sbuf_scanner_exception &e ) {
            std::cerr << "Scanner " << SCANNER << "Exception " << e.what() << " processing " << sp.sbuf->pos0 << "\n";
        }
                
        yyhwallets_lex_destroy(scanner);
    }
    if ( sp.phase==scanner_params::PHASE_INIT ) {
        // avoids defined but not used
        (void)yyunput;
        (void)yy_fatal_error;
    }
}
