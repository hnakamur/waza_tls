package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestHashSize(t *testing.T) {
	testCases := []struct {
		want int
		hash crypto.Hash
	}{
		{32, crypto.SHA256},
		{48, crypto.SHA384},
		{64, crypto.SHA512},
		{20, crypto.SHA1},
	}
	for _, c := range testCases {
		got := c.hash.Size()
		if got != c.want {
			t.Errorf("size mismatch for %v, got=%d, want=%d", c.hash, got, c.want)
		}
	}
}

func TestHashSum(t *testing.T) {
	testCases := []struct {
		label string
		input string
		want  string
	}{
		{"clientHello",
			"01000071030364e7e0e63f9c2da3aeca81309762f8eb7caf23cd5f7d29677fb24924eb1fe94f20c426d088a4903a1852ae28d320b3ace18310625550f5391d6239b5cef60fbf210002c02b010000260000000e000c0000096e617275682e646576000a000a0008001d001700180019000b00020100",
			"654b9c3edbedda370c9d5ed031cf82f9668a219d5e0ed7c123e1c0cd3d50f1a5"},
		{"serverHello",
			"0200002e0303a4358691d929b9959eb8907551dd76cc737f60946b821235444f574e4752440100c02b000006000b00020100",
			"c474608c867539e5956bada4c297f13e53210652292106bf0c2dd213b152bd02"},
		{"cert",
			"0b000eea000ee70004603082045c30820344a0030201020212034dd1332d2a42f32701cc5e2e2c3c710f14300d06092a864886f70d01010b05003032310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310b3009060355040313025233301e170d3232303230353038313133315a170d3232303530363038313133305a301431123010060355040313096e617275682e6465763059301306072a8648ce3d020106082a8648ce3d030107034200045b3917b15de879c18ede3aa45241e55dffc18e7fbb14278dcaf04e2a663ad86b9a50f410d832ecb4611fa45e679573bfa509187130684ab69836803526e874aca38202533082024f300e0603551d0f0101ff040403020780301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff04023000301d0603551d0e04160414bd3439b15b09e385e3e34383f0b3517ae5dea3a9301f0603551d23041830168014142eb317b75856cbae500940e61faf9d8b14c2c6305506082b0601050507010104493047302106082b060105050730018615687474703a2f2f72332e6f2e6c656e63722e6f7267302206082b060105050730028616687474703a2f2f72332e692e6c656e63722e6f72672f30230603551d11041c301a82096e617275682e646576820d7777772e6e617275682e646576304c0603551d20044530433008060667810c0102013037060b2b0601040182df130101013028302606082b06010505070201161a687474703a2f2f6370732e6c657473656e63727970742e6f726730820104060a2b06010401d6790204020481f50481f200f00075006f5376ac31f03119d89900a45115ff77151c11d902c10029068db2089a37d9130000017ec9271ebb0000040300463044022027f3722c3c6fd7f47b8148cef714a7f03ad096e70a132a47dfa13d837226eac3022002db0aef92ea7ca62824d9b1078e0f45f4932053d5d6285eba9921d264592f5b00770046a555eb75fa912030b5a28969f4f37d112c4174befd49b885abf2fc70fe6d470000017ec9271ebb000004030048304602210099802c915e0ebcb23490beb93b1a105ef69cb298f3a070a2f55ada8ee97db47f022100c9ed90f21537a69b76325e7b42a450c757355bf0483f77086bef729990ac5e46300d06092a864886f70d01010b05000382010100858387974318cd56351ff66372b1d0db2143e303045a63c9cf5722cc38036c4fc50f6b901df6b31b31fe5e9cf567d831e1958e1ddc03431996c8a4a1058fa97db3a9d7bfd832f032661a1248d41e12dbe9864cad2478dde90bd02843cf85dbcb099bdff53ddd06c6480e28259b5a71b876359d37dbd2ee7214b6715705808672a2aeb7eb2a228758e8ee3262413b8b3650c36b998ba9ce643224d83c370bc22320b85f943ff6e74f7d798d9e8cec0f3db3dece3ba7dcfe06217f426e6c74c288841fe6a86551d063a5fedc8e8964ce068864d83d93349f3b3b1ed8d3a940a98e81bd0ce6bc197838c930f841ccbc511c259d5b0c99f0904b8d596ea1f4c0a74d00051a30820516308202fea003020102021100912b084acf0c18a753f6d62e25a75f5a300d06092a864886f70d01010b0500304f310b300906035504061302555331293027060355040a1320496e7465726e65742053656375726974792052657365617263682047726f7570311530130603550403130c4953524720526f6f74205831301e170d3230303930343030303030305a170d3235303931353136303030305a3032310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310b300906035504031302523330820122300d06092a864886f70d01010105000382010f003082010a0282010100bb021528ccf6a094d30f12ec8d5592c3f882f199a67a4288a75d26aab52bb9c54cb1af8e6bf975c8a3d70f4794145535578c9ea8a23919f5823c42a94e6ef53bc32edb8dc0b05cf35938e7edcf69f05a0b1bbec094242587fa3771b313e71cace19befdbe43b45524596a9c153ce34c852eeb5aeed8fde6070e2a554abb66d0e97a540346b2bd3bc66eb66347cfa6b8b8f572999f830175dba726ffb81c5add286583d17c7e709bbf12bf786dcc1da715dd446e3ccad25c188bc60677566b3f118f7a25ce653ff3a88b647a5ff1318ea9809773f9d53f9cf01e5f5a6701714af63a4ff99b3939ddc53a706fe48851da169ae2575bb13cc5203f5ed51a18bdb150203010001a382010830820104300e0603551d0f0101ff040403020186301d0603551d250416301406082b0601050507030206082b0601050507030130120603551d130101ff040830060101ff020100301d0603551d0e04160414142eb317b75856cbae500940e61faf9d8b14c2c6301f0603551d2304183016801479b459e67bb6e5e40173800888c81a58f6e99b6e303206082b0601050507010104263024302206082b060105050730028616687474703a2f2f78312e692e6c656e63722e6f72672f30270603551d1f0420301e301ca01aa0188616687474703a2f2f78312e632e6c656e63722e6f72672f30220603551d20041b30193008060667810c010201300d060b2b0601040182df13010101300d06092a864886f70d01010b0500038202010085ca4e473ea3f7854485bcd56778b29863ad754d1e963d336572542d81a0eac3edf820bf5fccb77000b76e3bf65e94dee4209fa6ef8bb203e7a2b5163c91ceb4ed3902e77c258a47e6656e3f46f4d9f0ce942bee54ce12bc8c274bb8c1982fa2afcd71914a08b7c8b8237b042d08f908573e83d904330a472178098227c32ac89bb9ce5cf264c8c0be79c04f8e6d440c5e92bb2ef78b10e1e81d4429db5920ed63b921f81226949357a01d6504c10a22ae100d4397a1181f7ee0e08637b55ab1bd30bf876e2b2aff214e1b05c3f51897f05eacc3a5b86af02ebc3b33b9ee4bdeccfce4af840b863fc0554336f668e136176a8e99d1ffa540a734b7c0d063393539756ef2ba76c89302e9a94b6c17ce0c02d9bd81fb9fb768d40665b3823d7753f88e7903ad0a3107752a43d8559772c4290ef7c45d4ec8ae468430d7f2855f18a179bbe75e708b07e18693c3b98fdc6171252aafdfed255052688b92dce5d6b5e3da7dd0876c842131ae82f5fbb9abc889173de14ce5380ef6bd2bbd968114ebd5db3d20a77e59d3e2f858f95bb848cdfe5c4f1629fe1e5523afc811b08dea7c9390172ffdaca20947463ff0e9b0b7ff284d6832d6675e1e69a393b8f59d8b2f0bd25243a66f3257654d3281df3853855d7e5d6629eab8dde495b5cdb5561242cdc44ec6253844506decce005518fee94964d44eca979cb45bc073a8abb847c20005643082056030820448a00302010202104001772137d4e942b8ee76aa3c640ab7300d06092a864886f70d01010b0500303f31243022060355040a131b4469676974616c205369676e617475726520547275737420436f2e311730150603550403130e44535420526f6f74204341205833301e170d3231303132303139313430335a170d3234303933303138313430335a304f310b300906035504061302555331293027060355040a1320496e7465726e65742053656375726974792052657365617263682047726f7570311530130603550403130c4953524720526f6f7420583130820222300d06092a864886f70d01010105000382020f003082020a0282020100ade82473f41437f39b9e2b57281c87bedcb7df38908c6e3ce657a078f775c2a2fef56a6ef6004f28dbde68866c4493b6b163fd14126bbf1fd2ea319b217ed1333cba48f5dd79dfb3b8ff12f1219a4bc18a8671694a66666c8f7e3c70bfad292206f3e4c0e680aee24b8fb7997e94039fd347977c99482353e838ae4f0a6f832ed149578c8074b6da2fd0388d7b0370211b75f2303cfa8faeddda63abeb164fc28e114b7ecf0be8ffb5772ef4b27b4ae04c12250c708d0329a0e15324ec13d9ee19bf10b34a8c3f89a36151deac870794f46371ec2ee26f5b9881e1895c34796c76ef3b906279e6dba49a2f26c5d010e10eded9108e16fbb7f7a8f7c7e50207988f360895e7e237960d36759efb0e72b11d9bbc03f94905d881dd05b42ad641e9ac0176950a0fd8dfd5bd121f352f28176cd298c1a80964776e4737baceac595e689d7f72d689c50641293e593edd26f524c911a75aa34c401f46a199b5a73a516e863b9e7d72a712057859ed3e5178150b038f8dd02f05b23e7b4a1c4b730512fcc6eae050137c439374b3ca74e78e1f0108d030d45b7136b407bac130305c48b7823b98a67d608aa2a32982ccbabd83041ba2830341a1d605f11bc2b6f0a87c863b46a8482a88dc769a76bf1f6aa53d198feb38f364dec82b0d0a28fff7dbe21542d422d0275de179fe18e77088ad4ee6d98b3ac6dd27516effbc64f533434f0203010001a382014630820142300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106304b06082b06010505070101043f303d303b06082b06010505073002862f687474703a2f2f617070732e6964656e74727573742e636f6d2f726f6f74732f647374726f6f74636178332e703763301f0603551d23041830168014c4a7b1a47b2c71fadbe14b9075ffc4156085891030540603551d20044d304b3008060667810c010201303f060b2b0601040182df130101013030302e06082b060105050702011622687474703a2f2f6370732e726f6f742d78312e6c657473656e63727970742e6f7267303c0603551d1f043530333031a02fa02d862b687474703a2f2f63726c2e6964656e74727573742e636f6d2f445354524f4f544341583343524c2e63726c301d0603551d0e0416041479b459e67bb6e5e40173800888c81a58f6e99b6e300d06092a864886f70d01010b050003820101000a73006c966eff0e52d0aedd8ce75a06ad2fa8e38fbfc90a031550c2e56c42bb6f9bf4b44fc244880875cceb079b14626e78deec27ba395cf5a2a16e5694701053b1bbe4afd0a2c32b01d496f4c5203533f9d86136e0718db4b8b5aa824595c0f2a92328e7d6a1cb6708daa0432caa1b931fc9def5ab695d13f55b865822ca4d55e470676dc257c5463941cf8a5883586d99fe57e8360ef00e23aafd8897d0e35c0e9449b5b51735d22ebf4e85ef18e08592eb063b6c29230960dc45024c12183be9fb0ededc44f85898aeeabd4545a1885d66cafe10e96f82c811420dfbe9ece38600de9d10e338faa47db1d8e8498284069b2be86b4f010c38772ef9dde739",
			"7842bfc1b3636fc268b51ecad58de7e7800b997e3c3fb66364811529df4cb715"},
		{"skx",
			"0c00007003001d206d4acc64731fa0d53d7e8d4f551057a53270d78da4eeb61aa986e7f1ec48ff18020300483046022100d54345042e87cebb78cc9ad9926da3be0cf57914b5d6cb39cf69d9843446c33302210095386de1778b765d8a89ac76cccc79f849584d1a572f3c630132a25abd2550c5",
			"b86ed75067503e00d398e7f52dab9a3d76f48d4feabd96297ac23c270abe6e9d"},
		{"helloDone",
			"0e000000",
			"85e67255e165e98968cea5da019b0f0849bfbad5f586b16a445379525ea7c34d"},
		{"ckx",
			"100000212060b9e8916c446809fabf21891537e445cb697b649685a8a9517f5a91dfbb5237",
			"25a62ff5b8b6c9b0d2e8b2cefb06dccb4d4310fc84df6d157050c408c59f7b94"},
		{"clientFinished",
			"1400000c6233d41be000ad376a2cdf4d",
			"de98b05bc3471d226472aa4a05d9767c4440d3dff55a08c65ccdff3691fc853e"},
	}
	h := sha256.New()
	for i, c := range testCases {
		h.Write(fromHex(c.input))
		if got, want := h.Sum(nil), fromHex(c.want); !bytes.Equal(got, want) {
			t.Errorf("hash mismatch, i=%d, label=%s, got=%x, want=%x", i, c.label, got, want)
		}
	}
}

func fromHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
