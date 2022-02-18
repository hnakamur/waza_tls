const std = @import("std");
const math = std.math;
const mem = std.mem;
const asn1 = @import("asn1.zig");
const memx = @import("../memx.zig");
const rsa = @import("rsa.zig");
const bigint = @import("big_int.zig");

// Pkcs1PrivateKey is a structure which mirrors the PKCS #1 ASN.1 for an RSA private key.
const Pkcs1PrivateKey = struct {
    version: u64,
    n: math.big.int.Const,
    e: u64,
    d: math.big.int.Const,
    p: math.big.int.Const,
    q: math.big.int.Const,

    // We ignore these values, if present, because rsa will calculate them.
    dp: ?math.big.int.Const = null,
    dq: ?math.big.int.Const = null,
    qinv: ?math.big.int.Const = null,

    additional_primes: []Pkcs1AdditionalRsaPrime = &[_]Pkcs1AdditionalRsaPrime{},

    pub fn parse(input: *asn1.String, allocator: mem.Allocator) !Pkcs1PrivateKey {
        var s = try input.readAsn1(.sequence);
        var key = blk: {
            const version = try s.readAsn1Uint64();

            var n = try s.readAsn1BigInt(allocator);
            errdefer bigint.deinitConst(n, allocator);

            const e = try s.readAsn1Uint64();

            var d = try s.readAsn1BigInt(allocator);
            errdefer bigint.deinitConst(d, allocator);

            var p = try s.readAsn1BigInt(allocator);
            errdefer bigint.deinitConst(p, allocator);

            var q = try s.readAsn1BigInt(allocator);
            errdefer bigint.deinitConst(q, allocator);

            break :blk Pkcs1PrivateKey{
                .version = version,
                .n = n,
                .e = e,
                .d = d,
                .p = p,
                .q = q,
            };
        };
        errdefer key.deinit(allocator);

        if (!s.empty()) {
            key.dp = try s.readAsn1BigInt(allocator);
        }
        if (!s.empty()) {
            key.dq = try s.readAsn1BigInt(allocator);
        }
        if (!s.empty()) {
            key.qinv = try s.readAsn1BigInt(allocator);
        }
        if (!s.empty()) {
            var primes = std.ArrayListUnmanaged(Pkcs1AdditionalRsaPrime){};
            errdefer memx.deinitArrayListAndElems(Pkcs1AdditionalRsaPrime, &primes, allocator);
            s = try s.readAsn1(.sequence);
            while (!s.empty()) {
                var prime = try Pkcs1AdditionalRsaPrime.parse(&s, allocator);
                try primes.append(allocator, prime);
            }
            if (primes.items.len > 0) {
                key.additional_primes = primes.toOwnedSlice(allocator);
            }
        }
        return key;
    }

    pub fn deinit(self: *Pkcs1PrivateKey, allocator: mem.Allocator) void {
        allocator.free(self.n.limbs);
        allocator.free(self.d.limbs);
        allocator.free(self.p.limbs);
        allocator.free(self.q.limbs);
        if (self.dp) |dp| bigint.deinitConst(dp, allocator);
        if (self.dq) |dq| bigint.deinitConst(dq, allocator);
        if (self.qinv) |qinv| bigint.deinitConst(qinv, allocator);
        memx.deinitSliceAndElems(Pkcs1AdditionalRsaPrime, self.additional_primes, allocator);
    }
};

//priv={Version:0 N:+22295364975752508575061097572215548363601639861957558178792407355786478259555016313127021656834637097852747804876062503601273677042568544224214532129708505393452433481004948944475537647247610436458197647653560741071242798074354384526507150934229843916418098918144553487537839134902970548767340742818459173873350059765758153486592679828943321134392209951585654350727556760487018710623952783472748790514694865698914010172519781708672267169515849530543530211474777493550778014290012317103620433280961020867689081854987830217773597715131823149554233324377585009042096026387318557027460960407243607723661849550265407122309
// E:65537
// D:+1132509422223783527570355582616011726237543053549242583230845538969027970857052494108669226476685031337287294847680120763669989027186332662807424469533234881895771107286959656929048702682260328409438026901425205716254440618116876666444028647329770212212274765376859156812387910342127179407761681688857448308945887896915094743529668509142450278578209382997953583483803667429648116129073309601831472721471971166986608432488314490721329906628368246917928028763804488890813061768161263660825651572328332907928679462815961877356544989225723146262935277499689665811515511553305068692180307210355950327960001917561423822753
// P:+157878347955603381302847217997149137095046419016859735070550412385609459421709317352575061533007168847877855909432111352664495259232352233996456080148274962404613224696490025744793904875621556111624254827411600524990959685831592702654948820355858121222746609680241744080730640794906876237725508145497883119289
// Q:+141218636149031268791218888005720237855857334450175210196495398165437912436524784421396550325301822903664163623259894213501374166004924212059165083235948374210984366313262532710724778001109379509167300456663134602270205178928882343374505506876289330508057112510935543232275289980285690139131100890732368379181
// Dp:+112675953567106168327480246690886927832317716048576840387183643415354856730268549072005025452543514480702365907073380598717921735204156599183915043971729936014022221931564276273879568987708424920411390070380438399002123340790714946996046831171773988799480097877137297952118868149292450406139054160083197081625
// Dq:+135732534441058160312917420302551589221024907370660644605145820312786663141265738368985307559715689252250016491337168262243695318534815158487859800694502709002916157566545923645898721196696231512915718190726879651671612896927067575438355072457456722432107444255555500003726944949390053062453380170104255864213
// Qinv:+40041939306488695671404239543802894911914580651196509767081669807386604921150039818985333883728460287647241865242561633960946000194659545101714774337291374686453922991227990611088431424266023774010571806853041666769079118075656557827204755865020821020388655735016125896178553917679028317151779115460233086828
// AdditionalPrimes:[]}

// priv={Version:1
// N:+18961699171858658863122777622624371763409050135295605702331620887025662236912449218484765306073434563194395861591485508080158893256079404468091711449608187978918027239135053955119486613494309548175842773147031298960615099294667956875661333170024291323053822230427995942774090114046853901739933259648675158088688472677718372451692804582725773373490528738779156535435211401717538203685232757125803191260536672205063405176621721733184596849971497767380788557698822554573068771212034341293584743032089492354633131537823218300694992395538006218839776135838797774184572964901068063636131858282451461728383046820464894168229
// E:65537
// D:+15650917115561015800872232978595949862975863375172505529119836127115464135427957154351204578585171266024347311242959199751104188043309265076169996172469068168082026419789914226287951979345425953263409050925353366043333231602714815330386280875596213763839437247237019087974060977748942642722874149582341153001703552449804227149800065160953073069538060908456456684436777663918251427759068378195099517628890501499984915276282512444092809019436840553521571025938774611715874863404127231722045246505355115310944985620400567774190359165034577961970645390450161154867861967517649983780915560116538633506914981560063658177473
// P:+34126769037348143058554255770867690474954956000174105913464932329877783318656253224051650052984307834891944131837375892014731932682363234065914811696930671539374792178438138061195415985858158479757002265051
// Q:+31324556874410004224104056502614821764873085293468692019990050740491408485366632742668783719395355226621754449075100358540881318343294096232661230399769175473454978471730515682178476164634585465258914947959
// Dp:+498334039836156261455916852659114390108364632072975866444694451068755643925630320817514214881761182202291690711634171973970405413385135343410294563284292119919765569293151931345102966239929469843408321523
// Dq:+18484915582967369628805106751638396889309881450777548486825689646119973934770727294352389361183697270768721967186939152939714117301807465671329789652878116060552021566683033454271180969392525722621164787789
// Qinv:+7501901392418248979013783497973094758958211697714606490878944732817022601222514572297691487705985102389786071329194028431143402589759477419064039165302583595077147724196958140948420085806935637995627338511
// AdditionalPrimes:[{Prime:+17737693364258932716680102051613185592891634132831926975571183870850107066019302428502543858583461027757440044821479793818069280258573331647862867476866445115839049727967332871063993681440382299738617639481
// Exp:+2408799165996376110875580332626720047862055690407009019066840661772219553650179160072518429915815541557306809877033891770767911169283040903092596861988058066908273838883520187870508930296159459048685429473
// Coeff:+9086327348159149802015028376751226996956460209872933808887772794568433598890548990501765910551677911795528435031705196489959771331687971870930175425726308212774333319781846835752275453535191486556845509082}]}

const Pkcs1AdditionalRsaPrime = struct {
    prime: math.big.int.Const,

    // We ignore these values because rsa will calculate them.
    exp: math.big.int.Const,
    coeff: math.big.int.Const,

    pub fn parse(input: *asn1.String, allocator: mem.Allocator) !Pkcs1AdditionalRsaPrime {
        var s = try input.readAsn1(.sequence);

        var prime = try s.readAsn1BigInt(allocator);
        errdefer bigint.deinitConst(prime, allocator);

        var exp = try s.readAsn1BigInt(allocator);
        errdefer bigint.deinitConst(exp, allocator);

        var coeff = try s.readAsn1BigInt(allocator);
        errdefer bigint.deinitConst(coeff, allocator);

        return Pkcs1AdditionalRsaPrime{
            .prime = prime,
            .exp = exp,
            .coeff = coeff,
        };
    }

    pub fn deinit(self: *Pkcs1AdditionalRsaPrime, allocator: mem.Allocator) void {
        allocator.free(self.prime.limbs);
        allocator.free(self.exp.limbs);
        allocator.free(self.coeff.limbs);
    }
};

pub fn parsePkcs1PrivateKey(allocator: mem.Allocator, der: []const u8) !rsa.PrivateKey {
    var input = asn1.String.init(der);
    var priv = try Pkcs1PrivateKey.parse(&input, allocator);
    errdefer priv.deinit(allocator);
    if (!input.empty()) {
        std.log.warn("trailing data", .{});
        return error.Asn1SyntaxError;
    }
    if (priv.version > 1) {
        return error.UnsupportedRsaPrivateKeyVersion;
    }
    if (!priv.n.positive or !priv.d.positive or !priv.p.positive or !priv.q.positive) {
        return error.RsaPrivateContainsKeyZeroOrNegativeValue;
    }
    for (priv.additional_primes) |*a| {
        if (!a.prime.positive) {
            return error.RsaPrivateContainsKeyZeroOrNegativePrime;
        }
    }

    var public_key = rsa.PublicKey{
        .modulus = priv.n,
        .exponent = priv.e,
    };
    var primes = try allocator.alloc(math.big.int.Const, 2 + priv.additional_primes.len);
    errdefer allocator.free(primes);
    primes[0] = priv.p;
    primes[1] = priv.q;
    for (priv.additional_primes) |*a, i| {
        primes[i + 2] = a.prime;
        // We ignore the other two values because rsa will calculate
        // them as needed.
    }

    const private_key = rsa.PrivateKey{
        .public_key = public_key,
        .d = priv.d,
        .primes = primes,
    };

    if (priv.dp) |dp| bigint.deinitConst(dp, allocator);
    if (priv.dq) |dq| bigint.deinitConst(dq, allocator);
    if (priv.qinv) |qinv| bigint.deinitConst(qinv, allocator);
    for (priv.additional_primes) |*a| {
        allocator.free(a.exp.limbs);
        allocator.free(a.coeff.limbs);
    }
    allocator.free(priv.additional_primes);

    return private_key;
}

const testing = std.testing;
const fmtx = @import("../fmtx.zig");

// openssl genrsa -out priv-rsa.pem
// openssl rsa -outform DER -in priv-rsa.pem -out priv-rsa.der
const priv_rsa_der = @embedFile("../../tests/priv-rsa.der");

// openssl genrsa -out priv-rsa-2.pem -primes 2
// openssl rsa -outform DER -in priv-rsa-2.pem -out priv-rsa-2.der
const priv_rsa_2_der = @embedFile("../../tests/priv-rsa-2.der");

// generated by TestMarshalPKCS1PrivateKey in rsa_test.go
const priv_rsa_3_der = @embedFile("../../tests/priv-rsa-3.der");

// test "Pkcs1PrivateKey.parse" {
//     testing.log_level = .err;
//     const allocator = testing.allocator;
//     var s = asn1.String.init(priv_rsa_3_der);
//     var key = try Pkcs1PrivateKey.parse(&s, allocator);
//     defer key.deinit(allocator);
//     std.log.debug("key={}", .{key});
// }

// test "parsePkcs1PrivateKey" {
//     testing.log_level = .err;
//     const allocator = testing.allocator;
//     // var s = asn1.String.init(priv_rsa_3_der);
//     // var key = try Pkcs1PrivateKey.parse(&s, allocator);
//     var key = try parsePkcs1PrivateKey(allocator, priv_rsa_3_der);
//     defer key.deinit(allocator);
//     std.log.debug("key={}", .{key});
// }
