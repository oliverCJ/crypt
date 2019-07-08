package crypy

import (
	"math/rand"
	"time"
)

// 可接收自定义码表，字符长度必须为64，必须为合法的ascii字符，不包含换行符
type Crypt6 struct {
	lEncode    [64]byte
	lDecodeMap [256]byte
	rEncode    [64]byte
	rDecodeMap [256]byte
	password   uint8
}

const crypt6DefaultLStd = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#"
const crypt6DefaultRStd = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#"

var DefaultEncrypt6 = NewCrypt6(crypt6DefaultLStd, crypt6DefaultRStd, 0)

func NewCrypt6(newCryptLStd, newCryptRStd string, password uint8) *Crypt6 {
	if len(newCryptLStd) != len(newCryptRStd) || len(newCryptLStd) != 64 {
		panic("crypt character is not 64-bytes long")
	}
	for i := 0; i < len(newCryptLStd); i++ {
		if newCryptLStd[i] < 33 || newCryptLStd[i] > 126 {
			panic("crypt character contains non-display character")
		}
		if newCryptRStd[i] < 33 || newCryptRStd[i] > 126 {
			panic("crypt character contains non-display character")
		}
	}
	c := new(Crypt6)
	copy(c.lEncode[:], newCryptLStd)
	copy(c.rEncode[:], newCryptRStd)

	if password != 0 {
		c.password = password
	} else {
		c.password = 0
	}

	for i := 0; i < len(c.lDecodeMap); i++ {
		c.lDecodeMap[i] = 0xFF
		c.rDecodeMap[i] = 0xFF
	}
	// 生成解码映射map
	for i := 0; i < len(newCryptLStd); i++ {
		c.lDecodeMap[newCryptLStd[i]] = byte(i)
		c.rDecodeMap[newCryptRStd[i]] = byte(i)
	}
	return c
}

// 加密数据并返回字符串
func (c *Crypt6) EnCryptToString(src []byte) string {
	buf := make([]byte, c.EnCryptLen(len(src)))
	c.EnCrypt(buf, []byte(src))
	return string(buf)
}

// 解密字符串
func (c *Crypt6) DeCryptString(src string) ([]byte, error) {
	dbuf := make([]byte, c.DeCryptLen(len(src)))
	n, err := c.DeCrypt(dbuf, []byte(src))
	return dbuf[:n], err
}

func (c *Crypt6) EnCryptLen(n int) int {
	return n * 2
}

func (c *Crypt6) DeCryptLen(n int) int {
	if (n % 2) != 0 {
		panic("illegal crypt data length")
	}
	return n / 2
}

// 加密
func (c *Crypt6) EnCrypt(dst, src []byte) {
	if len(src) == 0 {
		return
	}

	p := c.password & 0x3F

	si, di := 0, 0
	n := len(src)
	for si < n {
		dst[di+0] = c.lEncode[src[si+0]>>2^p]
		dst[di+1] = c.rEncode[src[si+0]&0x3F^p]

		si++
		di += 2
	}
	return
}

func (c *Crypt6) DeCrypt(dst, src []byte) (n int, err error) {
	if len(src) == 0 {
		return 0, nil
	}
	if (len(src) % 2) != 0 {
		return 0, CorruptInputError(len(src))
	}

	p := c.password & 0x3F

	si, di := 0, 0
	n = len(src) / 2
	for di < n {
		dst[di+0] = (c.lDecodeMap[src[si+0]]^p)<<2 | (c.rDecodeMap[src[si+1]]^p)&0x03
		si += 2
		di++
	}
	return n, nil
}

func GetRandomMapString() string {
	baseText := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'()*+-./,:;<=>?@[]^_`{}|~"
	baseTextBytes := []byte(baseText)

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	randInt64 := func(min, max int64, rn *rand.Rand) int64 {
		if min >= max || max == 0 {
			return max
		}
		return rn.Int63n(max-min) + min
	}

	for i := len(baseTextBytes) - 1; i >= 0; i-- {
		r := randInt64(0, int64(i), r)
		a := baseTextBytes[i]
		baseTextBytes[i] = baseTextBytes[r]
		baseTextBytes[r] = a
	}

	return string(baseTextBytes[:64])
}
