package sm2

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"gm/sm3"
	"io"
	"math/big"
)

var one = new(big.Int).SetInt64(1)
var two = new(big.Int).SetInt64(2)
var sm2h = new(big.Int).SetInt64(1)
var sm2P256V1 P256V1Curve

type P256V1Curve struct {
	*elliptic.CurveParams
	A *big.Int
}

// 公私钥
type PrivateKey struct {
	D     *big.Int
	Curve P256V1Curve
	PublicKey
}
type PublicKey struct {
	X, Y  *big.Int
	Curve P256V1Curve
}

type C struct {
	C1,C2,C3 *big.Int
}


// 初始化sm2P256V1椭圆曲线
func init(){
	sm2P256V1.CurveParams = &elliptic.CurveParams{Name: "SM2-P-256-V1"}
	sm2P256V1.P, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	sm2P256V1.A, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
	sm2P256V1.B, _ = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	sm2P256V1.N, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	sm2P256V1.Gx, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	sm2P256V1.Gy, _ = new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	sm2P256V1.BitSize = 256
}

// 密钥生成
func GenerateKey(random io.Reader) (*PrivateKey, *PublicKey, error) {
	if random == nil {
		random = rand.Reader
	}
	k, _ := genrateRand(sm2P256V1, rand.Reader)

	priv := new(PrivateKey)
	priv.Curve = sm2P256V1
	priv.D = k
	pub := new(PublicKey)
	pub.Curve = sm2P256V1
	pub.X, pub.Y = sm2P256V1.ScalarBaseMult(k.Bytes())

	return priv, pub, nil
}

// 加密
func Encrypt(pub *PublicKey, data []byte)(Cipertext C ,err error){
	C2 := make([]byte, len(data))
	copy(C2, data)
	var C1 []byte
	var kpx, kpy *big.Int
	for{
		// 1 <= k <= n-1
		k, _ := genrateRand(sm2P256V1, rand.Reader)
		C1x, C1y := sm2P256V1.ScalarBaseMult(k.Bytes())
		C1 = elliptic.Marshal(sm2P256V1, C1x, C1y)
		if(pub.X == sm2P256V1.Params().Gx && pub.Y == sm2P256V1.Params().Gy){
			return Cipertext, errors.New("S is G")
		}
		kpx, kpy = sm2P256V1.ScalarMult(pub.X, pub.Y, k.Bytes())
		// t = kdf(x2 || y2, M_lengh)
		// c2 = M & t
		kdf(sm3.New(), kpx, kpy, C2)
		if(!notEncrypted(C2, data)){
			break
		}
	}
	// C3 = hash(x2 || M || y2)
	hash := sm3.New()
	hash.Write(kpx.Bytes())
	hash.Write(data)
	hash.Write(kpy.Bytes())
	C3 := hash.Sum(nil)

	return C{new(big.Int).SetBytes(C1), new(big.Int).SetBytes(C2), new(big.Int).SetBytes(C3)}, nil
}

func Decrypt(priv *PrivateKey, Cipertext C)(data []byte, err error){
	C1x, C1y := elliptic.Unmarshal(sm2P256V1, Cipertext.C1.Bytes())
	if(!sm2P256V1.IsOnCurve(C1x, C1y)){
		return nil, errors.New("C1 is not on sm2-p256-v1")
	}
	if(C1x == sm2P256V1.Params().Gx && C1y == sm2P256V1.Params().Gy){
		return nil, errors.New("C1 is G")
	}
	kpx, kpy := sm2P256V1.ScalarMult(C1x, C1y, priv.D.Bytes())
	// t = KDF(x2||y2, M'_lengh)
	// encrypt M' = C2 & t
	C2 := Cipertext.C2.Bytes()
	kdf(sm3.New(), kpx, kpy, C2)
    // verify hash(x2|| M'||y2) == C3
	hash := sm3.New()
	hash.Write(kpx.Bytes())
	hash.Write(C2)
	hash.Write(kpy.Bytes())
	C3 := Cipertext.C3.Bytes()
	if(!bytes.Equal(C3, hash.Sum(nil))){
		return nil, errors.New("C3 hash error")
	}
	return C2, nil
}

func genrateRand(c elliptic.Curve, random io.Reader) (k *big.Int, err error) {
	if random == nil {
		random = rand.Reader
	}
	params := c.Params()
	b := make([]byte, 256/7 + 8)
	_, err = io.ReadFull(random, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, two)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

