%{

/* bulk_extractor include statements */
#include "config.h"


/* C include statements */
#include <cstring>
#include <cstdlib>

#include <algorithm>    // std::find
#include <vector>       // std::vector, std::begin, std::end
#include <array>
#include <sstream>

/**
 * libbitcoin https://github.com/libbitcoin/libbitcoin-system
 */
#include "extern/array_slice.hpp"
#include "extern/sha256.c"
#include "extern/zeroize.c"
#include "extern/compat.hpp"
#include "extern/compat.h"
#include "extern/mnemonic.hpp"
#include "extern/dictionary_en.cpp"
#include "extern/mnemonic.cpp"

/**
 * openssl
 */
#include <openssl/hmac.h>

/* Include the flex scanner */
#include "sbuf_flex_scanner.h"


class mnemonics_scanner : public sbuf_scanner {
public:
    mnemonics_scanner(const scanner_params &sp):
        sbuf_scanner(*sp.sbuf),
        mnemonics_recorder(sp.named_feature_recorder("mnemonics")),
        alert_recorder(sp.named_feature_recorder(feature_recorder_set::ALERT_RECORDER_NAME)){
        }

        class feature_recorder &mnemonics_recorder;
        class feature_recorder &alert_recorder;
};

#define YY_EXTRA_TYPE mnemonics_scanner * /* holds our class pointer */
YY_EXTRA_TYPE yymnemonics_get_extra (yyscan_t yyscanner );

inline class mnemonics_scanner *get_extra(yyscan_t yyscanner) {
  return yymnemonics_get_extra(yyscanner);
}


std::vector<std::string> split_string(const std::string& s, char delimiter) {
   std::vector<std::string> tokens;
   std::string token;
   std::istringstream tokenStream(s);
   while (std::getline(tokenStream, token, delimiter))
   {
      tokens.push_back(token);
   }
   return tokens;
}

bool HMAC_SHA_512(const char* pass, int passlen) {

    const char salt[] = "Seed version";
    uint32_t outputBytes = 64;
    char hexResult[2*outputBytes+1];
    memset(hexResult,0,sizeof(hexResult));
    unsigned char hmac[64];
    unsigned int res_len;
    HMAC_CTX *ctx;
    ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, (unsigned char*)salt, strlen(salt), EVP_sha512(), NULL);
    HMAC_Update(ctx, (const unsigned char*)pass, passlen);
    HMAC_Final(ctx, hmac, &res_len);
    HMAC_CTX_free(ctx);

    switch (hmac[0]) {
        case 0x00000001:
            //~ '01'      # Standard wallet
            return 1;
            break;
        case 0x00000010:
            if (hexResult[1]>>4 == 0x0000 || hexResult[1]>>4 == 0x0001 || hexResult[1]>>4 == 0x0002) {
                //~ '100'     # Segwit wallet
                //~ '101'     # Two-factor authentication
                //~ '102'     # Two-factor auth, using segwit
                return 1;
            }
            break;
    }

    return 0;
}


int check_bip39(const char *buf, size_t len, size_t *modify_scanner) {


    #define NUMBER_OF_STRING_BIP39 2048

    const char *arr_bip39[NUMBER_OF_STRING_BIP39] = {
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident", "account",
        "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict",
        "address", "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree",
        "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha",
        "already", "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger",
        "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety", "any", "apart",
        "apology", "appear", "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army", "around",
        "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
        "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn",
        "average", "avocado", "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge",
        "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket",
        "battle", "beach", "bean", "beauty", "because", "become", "beef", "before", "begin", "behave", "behind", "believe", "below", "belt",
        "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter",
        "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board",
        "boat", "body", "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box",
        "boy", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli",
        "broken", "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet",
        "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable",
        "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon",
        "capable", "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual",
        "cat", "catalog", "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century",
        "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap", "check", "cheese",
        "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar",
        "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean", "clerk", "clever", "click", "client",
        "cliff", "climb", "clinic", "clip", "clock", "clog", "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast",
        "coconut", "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come", "comfort", "comic", "common", "company",
        "concert", "conduct", "confirm", "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy", "coral",
        "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle", "craft",
        "cram", "crane", "crash", "crater", "crawl", "crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop",
        "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard",
        "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance", "danger", "daring",
        "dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease",
        "deer", "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend",
        "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk", "despair", "destroy", "detail", "detect", "develop",
        "device", "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner",
        "dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide",
        "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove",
        "draft", "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive", "drop", "drum", "dry", "duck", "dumb",
        "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo",
        "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either", "elbow", "elder", "electric", "elegant", "element",
        "elephant", "elevator", "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable",
        "enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough", "enrich",
        "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode", "erosion", "error", "erupt",
        "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact", "example", "excess", "exchange",
        "excite", "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand", "expect", "expire",
        "explain", "expose", "express", "extend", "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame",
        "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault", "favorite", "feature", "february",
        "federal", "fee", "feed", "feel", "female", "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file", "film", "filter",
        "final", "find", "fine", "finger", "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee",
        "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot", "force",
        "forest", "forget", "fork", "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame", "frequent", "fresh", "friend",
        "fringe", "frog", "front", "frost", "frown", "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy",
        "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate", "gather", "gauge", "gaze", "general",
        "genius", "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance", "glare",
        "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue", "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel",
        "gossip", "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green", "grid", "grief", "grit", "grocery",
        "group", "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand",
        "happy", "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health", "heart", "heavy", "hedgehog", "height",
        "hello", "helmet", "help", "hen", "hero", "hidden", "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday",
        "hollow", "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host", "hotel", "hour", "hover", "hub", "huge", "human",
        "humble", "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify", "idle",
        "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose", "improve", "impulse", "inch", "include",
        "income", "increase", "index", "indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury",
        "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest",
        "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel",
        "job", "join", "joke", "journey", "joy", "judge", "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup", "key",
        "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know", "lab", "label",
        "labor", "ladder", "lady", "lake", "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law", "lawn", "lawsuit",
        "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens",
        "leopard", "lesson", "letter", "level", "liar", "liberty", "library", "license", "life", "lift", "light", "like", "limb", "limit", "link", "lion", "liquid",
        "list", "little", "live", "lizard", "load", "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge", "love",
        "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet", "maid", "mail", "main",
        "major", "make", "mammal", "man", "manage", "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin",
        "marine", "market", "marriage", "mask", "mass", "master", "match", "material", "math", "matrix", "matter", "maximum", "maze",
        "meadow", "mean", "measure", "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory", "mention", "menu",
        "mercy", "merge", "merit", "merry", "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind",
        "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile", "model", "modify",
        "mom", "moment", "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning", "mosquito", "mother", "motion",
        "motor", "mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music",
        "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin", "narrow", "nasty", "nation", "nature", "near", "neck", "need",
        "negative", "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral", "never", "news", "next", "nice", "night", "noble",
        "noise", "nominee", "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice", "novel", "now", "nuclear", "number",
        "nurse", "nut", "oak", "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean", "october", "odor", "off", "offer",
        "office", "often", "oil", "okay", "old", "olive", "olympic", "omit", "once", "one", "onion", "online", "only", "open", "opera", "opinion", "oppose",
        "option", "orange", "orbit", "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer",
        "output", "outside", "oval", "oven", "over", "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair", "palace", "palm",
        "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot", "party", "pass", "patch", "path", "patient", "patrol",
        "pattern", "pause", "pave", "payment", "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper",
        "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill",
        "pilot", "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play", "please", "pledge", "pluck", "plug",
        "plunge", "poem", "poet", "point", "polar", "pole", "police", "pond", "pony", "pool", "popular", "portion", "position", "possible", "post",
        "potato", "pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare", "present", "pretty", "prevent",
        "price", "pride", "primary", "print", "priority", "prison", "private", "prize", "problem", "process", "produce", "profit", "program", "project",
        "promote", "proof", "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch",
        "pupil", "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question",
        "quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally", "ramp", "ranch", "random",
        "range", "rapid", "rare", "rate", "rather", "raven", "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe",
        "record", "recycle", "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject", "relax", "release", "relief", "rely",
        "remain", "remember", "remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report", "require",
        "rescue", "resemble", "resist", "resource", "response", "result", "retire", "retreat", "return", "reunion", "reveal", "review", "reward",
        "rhythm", "rib", "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road",
        "roast", "robot", "robust", "rocket", "romance", "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber",
        "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail", "salad", "salmon", "salon", "salt", "salute",
        "same", "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme",
        "school", "science", "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea", "search", "season", "seat", "second",
        "secret", "section", "security", "seed", "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series", "service",
        "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine", "ship",
        "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side", "siege",
        "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple", "since", "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch",
        "ski", "skill", "skin", "skirt", "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan", "slot", "slow", "slush",
        "small", "smart", "smile", "smoke", "smooth", "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft",
        "solar", "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup", "source", "south",
        "space", "spare", "spatial", "spawn", "speak", "special", "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit",
        "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium",
        "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting", "stock",
        "stomach", "stone", "stool", "story", "stove", "strategy", "street", "strike", "strong", "struggle", "student", "stuff", "stumble", "style",
        "subject", "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun", "sunny", "sunset",
        "super", "supply", "supreme", "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow", "swamp",
        "swap", "swarm", "swear", "sweet", "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table",
        "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target", "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant",
        "tennis", "tent", "term", "test", "text", "thank", "that", "theme", "then", "theory", "there", "they", "thing", "this", "thought", "three", "thrive",
        "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco",
        "today", "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top", "topic",
        "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic",
        "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble",
        "truck", "true", "truly", "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle", "twelve",
        "twenty", "twice", "twin", "twist", "two", "type", "typical", "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo",
        "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock", "until", "unusual", "unveil", "update",
        "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge", "usage", "use", "used", "useful", "useless", "usual", "utility", "vacant",
        "vacuum", "vague", "valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle", "velvet", "vendor", "venture",
        "venue", "verb", "verify", "version", "very", "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video", "view", "village",
        "vintage", "violin", "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote", "voyage",
        "wage", "wagon", "wait", "walk", "wall", "walnut", "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave", "way",
        "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird", "welcome", "west", "wet", "whale", "what",
        "wheat", "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing", "wink",
        "winner", "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder", "wood", "wool", "word", "work", "world",
        "worry", "worth", "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year", "yellow", "you", "young", "youth", "zebra", "zero",
        "zone", "zoo" };


    char *ptr = NULL;
    char *saveptr = NULL;
    char tmp[len+1];
    memset(tmp, '\0', len+1);
    memcpy(tmp, buf, len);

    size_t newstarter = 0;
    size_t count_words = 0;

    //~ wort für wort
    for (ptr = strtok_r(tmp, " ", &saveptr);
         ptr != NULL;
         ptr = strtok_r(NULL, " ", &saveptr)) {

        newstarter = newstarter + strlen(ptr) + 1;

        if (strlen(ptr) > 8 || strlen(ptr) < 3) {
            return newstarter;
        }

        //~ gegen wortliste testen
        for (int i = 0; i < NUMBER_OF_STRING_BIP39; i++) {

            //~ wort ist vorhanden
            if (strcmp(ptr, arr_bip39[i]) == 0) {
                count_words++;

                /* zu viele worte */
                if (count_words == 24) {
                    *modify_scanner = newstarter;
                    return 0;
                }

                /* wort gefunden */
                break;
            }

            //~ wortliste durchlaufen aber letztes wort nicht gefunden
            if (i+1 == NUMBER_OF_STRING_BIP39) {

                //~ letztes wort nicht gefunden, aber vielleicht schon genug worte
                //~ if (count_words == 9 ||
                if (count_words == 12 ||
                count_words == 15 ||
                count_words == 18 ||
                count_words == 24) {
                    
                    //~ Leerzeichen davor und dahinter!
                    *modify_scanner = newstarter - strlen(ptr) - 2;

                    return 0;
                }

                //~ wortliste durchlaufen, letztes wort nicht gefunden und nicht genug worte
                return newstarter;
            }
        }

    }

    //~ letztes wort auch gefunden, waren es genug?
    //~ if (count_words == 9 ||
    if (count_words == 12 ||
    count_words == 15 ||
    count_words == 18 ||
    count_words == 24) {

        *modify_scanner = 0;
        
        return  0;
    }

    return  newstarter;
}

#define SCANNER "scan_mnemonics"

%}

%option reentrant
%option noyywrap
%option 8bit
%option batch
%option case-insensitive
%option pointer
%option noyymore
%option prefix="yymnemonics_"
%option yylineno

DELIM     ([-;:,#\t \n\r])
BLOCK_BIP39 ([a-zA-Z]{3,12})
DB_BIP39    ({BLOCK_BIP39}{DELIM})
%%


{DB_BIP39}{11,}{BLOCK_BIP39} {

    mnemonics_scanner &s = *yymnemonics_get_extra(yyscanner);

    char yytext_lower[yyleng+1];
    const char delimiter[10] = {' ', ',', '-', ';', ':', '#', '\t', '\n', '\r', '\0'};
    size_t i;
    
    //~ alles Kleinbuchstaben
    memset(yytext_lower, '\0', yyleng+1);
    memcpy(yytext_lower, yytext, yyleng);

    for ( i = 0; i < yyleng; i++ ) {
        yytext_lower[i] = tolower(yytext_lower[i]);

        for ( int j = 0; j < sizeof(delimiter) - 1; j++ ) {
            if (yytext_lower[i] == delimiter[j]) {
                if ( i == yyleng - 1) {
                    yytext_lower[i] = '\0';
                } else {
                    yytext_lower[i] = ' ';
                }

                break;
            }
        }
    }


    size_t modify_scanner = 0;
    int cb39 = check_bip39((const char*)yytext_lower, yyleng, &modify_scanner);

    if ( cb39 == 0 ){

        if (modify_scanner == 0) {

            //~ treffer ist komplett ein mnemonic
            if (HMAC_SHA_512(yytext_lower, yyleng) || libbitcoin::system::wallet::validate_mnemonic(split_string(yytext_lower, ' '), language::en)) {
                if (HMAC_SHA_512(yytext_lower, yyleng)) {
                    //~ tue etwas
                }
                
                if (libbitcoin::system::wallet::validate_mnemonic(split_string(yytext_lower, ' '), language::en)) {
                    //~ tue etwas
                }

                s.mnemonics_recorder.write_buf(SBUF, POS, yyleng);
                s.pos += yyleng;
            } else {
                s.pos++;
                yyless(1);
            }
        } else if ( modify_scanner > 0 ) {
            //~ treffer ist nicht komplett ein mnemonic. ende wieder zum puffer
            if ( modify_scanner > yyleng ) {
                if (HMAC_SHA_512(yytext_lower, yyleng) || libbitcoin::system::wallet::validate_mnemonic(split_string(yytext_lower, ' '), language::en)) {
                    if (HMAC_SHA_512(yytext_lower, yyleng)) {
                        //~ tue etwas
                    }
                    if (libbitcoin::system::wallet::validate_mnemonic(split_string(yytext_lower, ' '), language::en)) {
                        //~ tue etwas
                    }
                    s.mnemonics_recorder.write_buf(SBUF, POS, yyleng);
                    s.pos += yyleng;
                } else {
                    s.pos++;
                    yyless(1);
                }
                
            //~ treffer sollte eigentlich nicht größer als yyleng sein, aber wenn doch, nicht weiter gehen
            } else {

                char argv[modify_scanner+1];
                memset(argv, '\0', modify_scanner+1);
                memcpy(argv, yytext_lower, modify_scanner);

                if (HMAC_SHA_512(argv, modify_scanner) || libbitcoin::system::wallet::validate_mnemonic(split_string(argv, ' '), language::en)) {
                    if (HMAC_SHA_512(argv, modify_scanner)) {
                        //~ tue etwas
                    }
                    if (libbitcoin::system::wallet::validate_mnemonic(split_string(argv, ' '), language::en)) {
                        //~ tue etwas
                    }
                    s.mnemonics_recorder.write_buf(SBUF, POS, modify_scanner);
                    s.pos += modify_scanner;
                    yyless(modify_scanner);
                } else {
                    s.pos++;
                    yyless(1);
                }

            //~ treffer ist nicht komplett ein mnemonic. ende wieder zum puffer
            }
        } else {
            //~ sollte nicht vorkommen, aber wenn dann zumindest ein zeichen weiter
            s.pos++;
            yyless(1);
        }
    }

    if ( cb39 > 0 ) {
        //~ keine ausreichenden treffer, ab erster neuer möglichkeit wieder zum puffer
        if ( cb39 < yyleng ) {
            s.pos += cb39;
            yyless(cb39);
        } else {
            s.pos += yyleng;
            yyless(yyleng);
        }
    }

}

.|\n {
     /**
      * The no-match rule.
      * If we are beyond the end of the margin, call it quits.
      */
     mnemonics_scanner &s = *yymnemonics_get_extra(yyscanner);
     /* putchar(yytext[0]); */ /* Uncomment for debugging */
     s.pos++;
}

%%

extern "C"
void scan_mnemonics(struct scanner_params &sp) {
    //assert(sp.sp_version==scanner_params::CURRENT_SP_VERSION);
    sp.check_version();
    if ( sp.phase==scanner_params::PHASE_INIT ) {
        //assert(sp.info->si_version==scanner_info::CURRENT_SI_VERSION);
        sp.info->set_name("mnemonics");
        sp.info->author         = "Christian C., https://github.com/cc-code-public";
        sp.info->description    = "Scans for mnemonics";
        sp.info->scanner_version= "0.92";

        /* Define the feature files this scanner created */
        //sp.info->feature_names.insert(FEATURE_NAME);
        sp.info->feature_defs.push_back( feature_recorder_def( "mnemonics" ));

        /* Define the histograms to make */
        //sp.info->histogram_defs.insert(histogram_def("url","","histogram"));


        /*scan_mnemonics_valid_debugg = sp.info->config->debug;*/  // get debug value
        return;
    }
    if ( sp.phase==scanner_params::PHASE_SCAN ) {
        mnemonics_scanner lexer(sp);
        yyscan_t scanner;
        yymnemonics_lex_init(&scanner);
        yymnemonics_set_extra(&lexer,scanner);

        try {
            yymnemonics_lex(scanner);
        }
        catch (sbuf_scanner::sbuf_scanner_exception &e ) {
            std::cerr << "Scanner " << SCANNER << "Exception " << e.what() << " processing " << sp.sbuf->pos0 << "\n";
        }

        yymnemonics_lex_destroy(scanner);
    }
    if ( sp.phase==scanner_params::PHASE_INIT ) {
        // avoids defined but not used
        (void)yyunput;
        (void)yy_fatal_error;
    }
}
