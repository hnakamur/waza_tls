package main

import (
	"fmt"
	"log"
	"math/big"
	"math/bits"
	"testing"
)

func TestBigIntSetBytes(t *testing.T) {
	var i big.Int
	i.SetBytes([]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0xfe})
	if got, want := i.String(), "335812727627494322174"; got != want {
		t.Errorf("result mismatch, got=%s, want=%s", got, want)
	}
}

func TestBigIntSetStringEmpty(t *testing.T) {
	i, ok := new(big.Int).SetString("0", 0)
	if !ok {
		t.Fatal("failed to set string")
	}
	log.Printf("i=%s", i.String())
}

func TestBitsLeadingZeros(t *testing.T) {
	if got, want := bits.LeadingZeros(1), 63; got != want {
		t.Errorf("result mismatch, got=%d, want=%d", got, want)
	}
}

func TestBigIntDivMod(t *testing.T) {
	testCases := []struct {
		x, y int64
		q, r int64 // T-division
		d, m int64 // Euclidean division
	}{
		{5, 3, 1, 2, 1, 2},
		{-5, 3, -1, -2, -2, 1},
		{5, -3, -1, 2, -1, 2},
		{-5, -3, 1, -2, 2, 1},
		{1, 2, 0, 1, 0, 1},
		{8, 4, 2, 0, 2, 0},
	}
	for _, c := range testCases {
		x := big.NewInt(c.x)
		y := big.NewInt(c.y)

		q1 := new(big.Int).Quo(x, y)
		if got, want := q1.Int64(), c.q; got != want {
			t.Errorf("Quo mismatch, got=%d, want=%d", got, want)
		}

		r1 := new(big.Int).Rem(x, y)
		if got, want := r1.Int64(), c.r; got != want {
			t.Errorf("Rem mismatch, got=%d, want=%d", got, want)
		}

		q2, r2 := new(big.Int).QuoRem(x, y, new(big.Int))
		if got, want := q2.Int64(), c.q; got != want {
			t.Errorf("QuoRem quo mismatch, got=%d, want=%d", got, want)
		}
		if got, want := r2.Int64(), c.r; got != want {
			t.Errorf("QuoRem rem mismatch, got=%d, want=%d", got, want)
		}

		d1 := new(big.Int).Div(x, y)
		if got, want := d1.Int64(), c.d; got != want {
			t.Errorf("Div mismatch, got=%d, want=%d", got, want)
		}

		m1 := new(big.Int).Mod(x, y)
		if got, want := m1.Int64(), c.m; got != want {
			t.Errorf("Mod mismatch, got=%d, want=%d", got, want)
		}

		d2, m2 := new(big.Int).DivMod(x, y, new(big.Int))
		if got, want := d2.Int64(), c.d; got != want {
			t.Errorf("DivMod div mismatch, got=%d, want=%d", got, want)
		}
		if got, want := m2.Int64(), c.m; got != want {
			t.Errorf("DivMod mod mismatch, got=%d, want=%d", got, want)
		}
	}

}

var gcdTests = []struct {
	d, x, y, a, b string
}{
	// a <= 0 || b <= 0
	// {"0", "0", "0", "0", "0"},
	// {"7", "0", "1", "0", "7"},
	// {"7", "0", "-1", "0", "-7"},
	// {"11", "1", "0", "11", "0"},
	// {"7", "-1", "-2", "-77", "35"},
	// {"935", "-3", "8", "64515", "24310"},
	{"935", "-3", "-8", "64515", "-24310"},
	// {"935", "3", "-8", "-64515", "-24310"},

	// {"1", "-9", "47", "120", "23"},
	// {"7", "1", "-2", "77", "35"},
	// {"935", "-3", "8", "64515", "24310"},
	// {"935000000000000000", "-3", "8", "64515000000000000000", "24310000000000000000"},
	// {"1", "-221", "22059940471369027483332068679400581064239780177629666810348940098015901108344", "98920366548084643601728869055592650835572950932266967461790948584315647051443", "991"},
}

func testGcd(t *testing.T, d, x, y, a, b *big.Int) {
	var X *big.Int
	if x != nil {
		X = new(big.Int)
	}
	var Y *big.Int
	if y != nil {
		Y = new(big.Int)
	}

	D := new(big.Int).GCD(X, Y, a, b)
	if D.Cmp(d) != 0 {
		t.Errorf("GCD(%s, %s, %s, %s): got d = %s, want %s", x, y, a, b, D, d)
	}
	if x != nil && X.Cmp(x) != 0 {
		t.Errorf("GCD(%s, %s, %s, %s): got x = %s, want %s", x, y, a, b, X, x)
	}
	if y != nil && Y.Cmp(y) != 0 {
		t.Errorf("GCD(%s, %s, %s, %s): got y = %s, want %s", x, y, a, b, Y, y)
	}

	// check results in presence of aliasing (issue #11284)
	a2 := new(big.Int).Set(a)
	b2 := new(big.Int).Set(b)
	a2.GCD(X, Y, a2, b2) // result is same as 1st argument
	if a2.Cmp(d) != 0 {
		t.Errorf("aliased z = a GCD(%s, %s, %s, %s): got d = %s, want %s", x, y, a, b, a2, d)
	}
	if x != nil && X.Cmp(x) != 0 {
		t.Errorf("aliased z = a GCD(%s, %s, %s, %s): got x = %s, want %s", x, y, a, b, X, x)
	}
	if y != nil && Y.Cmp(y) != 0 {
		t.Errorf("aliased z = a GCD(%s, %s, %s, %s): got y = %s, want %s", x, y, a, b, Y, y)
	}

	a2 = new(big.Int).Set(a)
	b2 = new(big.Int).Set(b)
	b2.GCD(X, Y, a2, b2) // result is same as 2nd argument
	if b2.Cmp(d) != 0 {
		t.Errorf("aliased z = b GCD(%s, %s, %s, %s): got d = %s, want %s", x, y, a, b, b2, d)
	}
	if x != nil && X.Cmp(x) != 0 {
		t.Errorf("aliased z = b GCD(%s, %s, %s, %s): got x = %s, want %s", x, y, a, b, X, x)
	}
	if y != nil && Y.Cmp(y) != 0 {
		t.Errorf("aliased z = b GCD(%s, %s, %s, %s): got y = %s, want %s", x, y, a, b, Y, y)
	}

	a2 = new(big.Int).Set(a)
	b2 = new(big.Int).Set(b)
	D = new(big.Int).GCD(a2, b2, a2, b2) // x = a, y = b
	if D.Cmp(d) != 0 {
		t.Errorf("aliased x = a, y = b GCD(%s, %s, %s, %s): got d = %s, want %s", x, y, a, b, D, d)
	}
	if x != nil && a2.Cmp(x) != 0 {
		t.Errorf("aliased x = a, y = b GCD(%s, %s, %s, %s): got x = %s, want %s", x, y, a, b, a2, x)
	}
	if y != nil && b2.Cmp(y) != 0 {
		t.Errorf("aliased x = a, y = b GCD(%s, %s, %s, %s): got y = %s, want %s", x, y, a, b, b2, y)
	}

	a2 = new(big.Int).Set(a)
	b2 = new(big.Int).Set(b)
	D = new(big.Int).GCD(b2, a2, a2, b2) // x = b, y = a
	if D.Cmp(d) != 0 {
		t.Errorf("aliased x = b, y = a GCD(%s, %s, %s, %s): got d = %s, want %s", x, y, a, b, D, d)
	}
	if x != nil && b2.Cmp(x) != 0 {
		t.Errorf("aliased x = b, y = a GCD(%s, %s, %s, %s): got x = %s, want %s", x, y, a, b, b2, x)
	}
	if y != nil && a2.Cmp(y) != 0 {
		t.Errorf("aliased x = b, y = a GCD(%s, %s, %s, %s): got y = %s, want %s", x, y, a, b, a2, y)
	}
}

func TestGcd(t *testing.T) {
	for _, test := range gcdTests {
		d, _ := new(big.Int).SetString(test.d, 0)
		// x, _ := new(big.Int).SetString(test.x, 0)
		// y, _ := new(big.Int).SetString(test.y, 0)
		a, _ := new(big.Int).SetString(test.a, 0)
		b, _ := new(big.Int).SetString(test.b, 0)

		testGcd(t, d, nil, nil, a, b)
		// testGcd(t, d, x, nil, a, b)
		// testGcd(t, d, nil, y, a, b)
		// testGcd(t, d, x, y, a, b)
	}
}

func TestUintSubOverflow(t *testing.T) {
	a := uint(2)
	b := uint(3)
	if got, want := a-b, uint(18446744073709551615); got != want {
		t.Errorf("result mismatch, got=%d, want=%d", got, want)
	}
}

var expTests = []struct {
	x, y, m string
	out     string
}{
	// y <= 0
	// {"0", "0", "", "1"},
	// {"1", "0", "", "1"},
	// {"-10", "0", "", "1"},
	// {"1234", "-1", "", "1"},
	// {"1234", "-1", "0", "1"},
	// {"17", "-100", "1234", "865"},
	// {"2", "-100", "1234", ""},

	// m == 1
	// {"0", "0", "1", "0"},
	// {"1", "0", "1", "0"},
	// {"-10", "0", "1", "0"},
	// {"1234", "-1", "1", "0"},

	// misc
	// {"5", "1", "3", "2"},
	// {"5", "-7", "", "1"},
	// {"-5", "-7", "", "1"},
	// {"5", "0", "", "1"},
	// {"-5", "0", "", "1"},
	// {"5", "1", "", "5"},
	// {"-5", "1", "", "-5"},
	// {"-5", "1", "7", "2"},
	// {"-2", "3", "2", "0"},
	// {"5", "2", "", "25"},
	// {"1", "65537", "2", "1"},
	// {"0x8000000000000000", "2", "", "0x40000000000000000000000000000000"},
	// {"0x8000000000000000", "2", "6719", "4944"},
	// {"0x8000000000000000", "3", "6719", "5447"},
	// {"0x8000000000000000", "1000", "6719", "1603"},
	// {"0x8000000000000000", "1000000", "6719", "3199"},
	// {"0x8000000000000000", "-1000000", "6719", "3663"}, // 3663 = ModInverse(3199, 6719) Issue #25865

	// {"0xffffffffffffffffffffffffffffffff", "0x12345678123456781234567812345678123456789", "0x01112222333344445555666677778889", "0x36168FA1DB3AAE6C8CE647E137F97A"},

	{
		"2938462938472983472983659726349017249287491026512746239764525612965293865296239471239874193284792387498274256129746192347",
		"298472983472983471903246121093472394872319615612417471234712061",
		"29834729834729834729347290846729561262544958723956495615629569234729836259263598127342374289365912465901365498236492183464",
		"23537740700184054162508175125554701713153216681790245129157191391322321508055833908509185839069455749219131480588829346291",
	},
	// // test case for issue 8822
	// {
	// 	"11001289118363089646017359372117963499250546375269047542777928006103246876688756735760905680604646624353196869572752623285140408755420374049317646428185270079555372763503115646054602867593662923894140940837479507194934267532831694565516466765025434902348314525627418515646588160955862839022051353653052947073136084780742729727874803457643848197499548297570026926927502505634297079527299004267769780768565695459945235586892627059178884998772989397505061206395455591503771677500931269477503508150175717121828518985901959919560700853226255420793148986854391552859459511723547532575574664944815966793196961286234040892865",
	// 	"0xB08FFB20760FFED58FADA86DFEF71AD72AA0FA763219618FE022C197E54708BB1191C66470250FCE8879487507CEE41381CA4D932F81C2B3F1AB20B539D50DCD",
	// 	"0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
	// 	"21484252197776302499639938883777710321993113097987201050501182909581359357618579566746556372589385361683610524730509041328855066514963385522570894839035884713051640171474186548713546686476761306436434146475140156284389181808675016576845833340494848283681088886584219750554408060556769486628029028720727393293111678826356480455433909233520504112074401376133077150471237549474149190242010469539006449596611576612573955754349042329130631128234637924786466585703488460540228477440853493392086251021228087076124706778899179648655221663765993962724699135217212118535057766739392069738618682722216712319320435674779146070442",
	// },
	// {
	// 	"-0x1BCE04427D8032319A89E5C4136456671AC620883F2C4139E57F91307C485AD2D6204F4F87A58262652DB5DBBAC72B0613E51B835E7153BEC6068F5C8D696B74DBD18FEC316AEF73985CF0475663208EB46B4F17DD9DA55367B03323E5491A70997B90C059FB34809E6EE55BCFBD5F2F52233BFE62E6AA9E4E26A1D4C2439883D14F2633D55D8AA66A1ACD5595E778AC3A280517F1157989E70C1A437B849F1877B779CC3CDDEDE2DAA6594A6C66D181A00A5F777EE60596D8773998F6E988DEAE4CCA60E4DDCF9590543C89F74F603259FCAD71660D30294FBBE6490300F78A9D63FA660DC9417B8B9DDA28BEB3977B621B988E23D4D954F322C3540541BC649ABD504C50FADFD9F0987D58A2BF689313A285E773FF02899A6EF887D1D4A0D2",
	// 	"0xB08FFB20760FFED58FADA86DFEF71AD72AA0FA763219618FE022C197E54708BB1191C66470250FCE8879487507CEE41381CA4D932F81C2B3F1AB20B539D50DCD",
	// 	"0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
	// 	"21484252197776302499639938883777710321993113097987201050501182909581359357618579566746556372589385361683610524730509041328855066514963385522570894839035884713051640171474186548713546686476761306436434146475140156284389181808675016576845833340494848283681088886584219750554408060556769486628029028720727393293111678826356480455433909233520504112074401376133077150471237549474149190242010469539006449596611576612573955754349042329130631128234637924786466585703488460540228477440853493392086251021228087076124706778899179648655221663765993962724699135217212118535057766739392069738618682722216712319320435674779146070442",
	// },

	// // test cases for issue 13907
	// {"0xffffffff00000001", "0xffffffff00000001", "0xffffffff00000001", "0"},
	// {"0xffffffffffffffff00000001", "0xffffffffffffffff00000001", "0xffffffffffffffff00000001", "0"},
	// {"0xffffffffffffffffffffffff00000001", "0xffffffffffffffffffffffff00000001", "0xffffffffffffffffffffffff00000001", "0"},
	// {"0xffffffffffffffffffffffffffffffff00000001", "0xffffffffffffffffffffffffffffffff00000001", "0xffffffffffffffffffffffffffffffff00000001", "0"},

	// {
	// 	"2",
	// 	"0xB08FFB20760FFED58FADA86DFEF71AD72AA0FA763219618FE022C197E54708BB1191C66470250FCE8879487507CEE41381CA4D932F81C2B3F1AB20B539D50DCD",
	// 	"0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73", // odd
	// 	"0x6AADD3E3E424D5B713FCAA8D8945B1E055166132038C57BBD2D51C833F0C5EA2007A2324CE514F8E8C2F008A2F36F44005A4039CB55830986F734C93DAF0EB4BAB54A6A8C7081864F44346E9BC6F0A3EB9F2C0146A00C6A05187D0C101E1F2D038CDB70CB5E9E05A2D188AB6CBB46286624D4415E7D4DBFAD3BCC6009D915C406EED38F468B940F41E6BEDC0430DD78E6F19A7DA3A27498A4181E24D738B0072D8F6ADB8C9809A5B033A09785814FD9919F6EF9F83EEA519BEC593855C4C10CBEEC582D4AE0792158823B0275E6AEC35242740468FAF3D5C60FD1E376362B6322F78B7ED0CA1C5BBCD2B49734A56C0967A1D01A100932C837B91D592CE08ABFF",
	// },
	// {
	// 	"2",
	// 	"0xB08FFB20760FFED58FADA86DFEF71AD72AA0FA763219618FE022C197E54708BB1191C66470250FCE8879487507CEE41381CA4D932F81C2B3F1AB20B539D50DCD",
	// 	"0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF72", // even
	// 	"0x7858794B5897C29F4ED0B40913416AB6C48588484E6A45F2ED3E26C941D878E923575AAC434EE2750E6439A6976F9BB4D64CEDB2A53CE8D04DD48CADCDF8E46F22747C6B81C6CEA86C0D873FBF7CEF262BAAC43A522BD7F32F3CDAC52B9337C77B3DCFB3DB3EDD80476331E82F4B1DF8EFDC1220C92656DFC9197BDC1877804E28D928A2A284B8DED506CBA304435C9D0133C246C98A7D890D1DE60CBC53A024361DA83A9B8775019083D22AC6820ED7C3C68F8E801DD4EC779EE0A05C6EB682EF9840D285B838369BA7E148FA27691D524FAEAF7C6ECE2A4B99A294B9F2C241857B5B90CC8BFFCFCF18DFA7D676131D5CD3855A5A3E8EBFA0CDFADB4D198B4A",
	// },
}

func TestExp(t *testing.T) {
	for i, test := range expTests {
		x, ok1 := new(big.Int).SetString(test.x, 0)
		y, ok2 := new(big.Int).SetString(test.y, 0)

		var ok3, ok4 bool
		var out, m *big.Int

		if len(test.out) == 0 {
			out, ok3 = nil, true
		} else {
			out, ok3 = new(big.Int).SetString(test.out, 0)
		}

		if len(test.m) == 0 {
			m, ok4 = nil, true
		} else {
			m, ok4 = new(big.Int).SetString(test.m, 0)
		}

		if !ok1 || !ok2 || !ok3 || !ok4 {
			t.Errorf("#%d: error in input", i)
			continue
		}

		z1 := new(big.Int).Exp(x, y, m)
		// if z1 != nil && !isNormalized(z1) {
		// 	t.Errorf("#%d: %v is not normalized", i, *z1)
		// }
		if !(z1 == nil && out == nil || z1.Cmp(out) == 0) {
			t.Errorf("#%d: got %x want %x", i, z1, out)
		}

		// if m == nil {
		// 	// The result should be the same as for m == 0;
		// 	// specifically, there should be no div-zero panic.
		// 	m = &big.Int{abs: nat{}} // m != nil && len(m.abs) == 0
		// 	z2 := new(big.Int).Exp(x, y, m)
		// 	if z2.Cmp(z1) != 0 {
		// 		t.Errorf("#%d: got %x want %x", i, z2, z1)
		// 	}
		// }
	}
}

func TestBigIntSetBytes2(t *testing.T) {
	testCases := []struct {
		input string
		want  string
	}{
		{input: "\x4a", want: "74"},
		{input: "\xd9\xaa", want: "55722"},
		{input: "\x47\x5f\x17", want: "4677399"},
		{input: "\x8c\x46\x12\xaa", want: "2353402538"},
		{input: "\xd7\x54\xeb\xec\x53", want: "924842716243"},
		{input: "\xaa\x6a\x28\xef\xe4\x94", want: "187372930065556"},
		{input: "\x3b\x7d\x1d\x4c\x92\x7f\xcc", want: "16744588418121676"},
		{input: "\x63\xff\xb2\x36\xe2\x30\xf0\x0a", want: "7205673877608919050"},
		{input: "\x26\xaf\xe3\x47\xe1\xb9\xaf\x1e\x36", want: "713650327612122144310"},
		{input: "\xa3\xa0\x63\xcf\xd9\xd8\xf5\x8f\xa9\xcc", want: "772704407966201488058828"},
		{
			input: "\xf3\x73\x00\x14\xc3\xb4\x5e\xcd\x79\x6c\x86",
			want:  "294312047808122719137524870",
		},
		{
			input: "\xc6\xfb\x2c\x1a\x1e\x56\x12\xbe\xd7\x57\xc8\x4b",
			want:  "61581680591276142991196538955",
		},
		{
			input: "\xfd\xf9\x03\x3d\x29\x9e\xbb\x56\x52\x67\x61\x95\x47",
			want:  "20121790799163960969827622950215",
		},
		{
			input: "\x87\x28\x2c\x91\x46\x84\x78\x6c\x74\x61\x11\xbe\x33\xfe",
			want:  "2741308215961231365498022024590334",
		},
		{
			input: "\x19\xab\xed\x9c\xc8\x61\xa1\x0d\xfb\xb2\xf6\x88\x80\x36\x3b",
			want:  "133294539102018743538753550516500027",
		},
		{
			input: "\x7b\x14\xe5\x40\x2f\xa7\x72\xc4\xe0\x92\xa4\xa9\xbb\x20\xd2\x86",
			want:  "163603539175865214120185492597282755206",
		},
		{
			input: "\xf2\xec\xf4\xd7\x94\xa0\x3d\x94\x5d\x68\x15\xed\xf7\x64\x74\x4d\x76",
			want:  "82663301894799255685983276547661284789622",
		},
		{
			input: "\x9c\xf3\xd2\xc7\x6a\x4b\x68\xba\xd9\xf1\xf2\xbe\x0c\x17\x58\x1a\x0a\x1f",
			want:  "13672485393818486146765023671054315829201439",
		},
		{
			input: "\x58\x6f\x9d\x99\x9d\x7a\x75\x19\x4c\xdd\xcc\xaf\xb3\x31\x45\x18\xa4\x63\xe4",
			want:  "1972188669730284504550489401945552795554046948",
		},
	}
	for _, c := range testCases {
		n := new(big.Int).SetBytes([]byte(c.input))
		got := n.String()
		if got != c.want {
			t.Errorf("result mismatch, input=%x, got=%v, want=%v", c.input, got, c.want)
		}
	}
}

func TestMod(t *testing.T) {
	testCases := []struct {
		a    string
		b    string
		want string
	}{
		{"17694774222311561", "458948883992", "1"},
		{
			"237934373742502196773711020334249533855437519268329331127996513076407519013378763037128952305053737425643207526811874248822497304120841397396740933665562386116406569665410881715710641431127597590879227797097512559732858629398863647933492076261754988287045337601508593073845315700540762139732699324323002763882356541049457793494480174872894450490195493781427758333854872063235882903706055421841331781485822640244239616780040447171443917696979497891518136474554688580907579220",
			"2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919",
			"1",
		},
		{"-90", "13", "1"},
		{"40", "-13", "1"},
		{"-51", "-13", "1"},
	}
	for _, c := range testCases {
		a := new(big.Int)
		if _, ok := a.SetString(c.a, 10); !ok {
			t.Fatal(fmt.Errorf("invalid a=%s", c.a))
		}

		b := new(big.Int)
		if _, ok := b.SetString(c.b, 10); !ok {
			t.Fatal(fmt.Errorf("invalid b=%s", c.b))
		}

		got := new(big.Int)
		got.Mod(a, b)
		if got.String() != c.want {
			t.Errorf("result mismatch, a=%s, b=%s, got=%d, want=%s", c.a, c.b, got, c.want)
		}
	}
}
