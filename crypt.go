// 基于base64编码方式衍生的可逆加解密方式
// 4位加密
package encrypt

import (
	"strconv"
)

// 可接收自定义码表，字符长度必须为16，必须为合法的ascii可显示字符
type Crypt struct {
	lEncode    [16]byte
	lDecodeMap [256]byte
	rEncode    [16]byte
	rDecodeMap [256]byte
	password   uint8
}

// 默认码表
const cryptDefaultLStd = "ABCDEFGHIJKLMNOP"
const cryotDefaultRstd = "ABCDEFGHIJKLMNOP"

var DefaultEncrypt = NewCrypt(cryptDefaultLStd, cryotDefaultRstd, 0)

// 初始化
func NewCrypt(newCryptLStd, newCryptRStd string, password uint8) *Crypt {
	if len(newCryptLStd) != len(newCryptRStd) || len(newCryptLStd) != 16 {
		panic("crypt character is not 16-bytes long")
	}
	for i := 0; i < len(newCryptLStd); i++ {
		if newCryptLStd[i] < 33 || newCryptLStd[i] > 126 {
			panic("crypt character contains non-display character")
		}
		if newCryptRStd[i] < 33 || newCryptRStd[i] > 126 {
			panic("crypt character contains non-display character")
		}
	}
	c := new(Crypt)
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
func (c *Crypt) EnCryptToString(src []byte) string {
	buf := make([]byte, c.EnCryptLen(len(src)))
	c.EnCrypt(buf, []byte(src))
	return string(buf)
}

// 解密字符串
func (c *Crypt) DeCryptString(src string) ([]byte, error) {
	dbuf := make([]byte, c.DeCryptLen(len(src)))
	n, err := c.DeCrypt(dbuf, []byte(src))
	return dbuf[:n], err
}

func (c *Crypt) EnCryptLen(n int) int {
	return n * 2
}

func (c *Crypt) DeCryptLen(n int) int {
	if (n % 2) != 0 {
		panic("illegal crypt data length")
	}
	return n / 2
}

// 加密方法
func (c *Crypt) EnCrypt(dst, src []byte) {
	if len(src) == 0 {
		return
	}

	p := c.password & 0x0F

	si, di := 0, 0
	n := len(src)
	for si < n {
		dst[di+0] = c.lEncode[src[si+0]>>4^p]
		dst[di+1] = c.rEncode[src[si+0]&0x0F^p]

		si++
		di += 2
	}
	return
}

// 解密方法
func (c *Crypt) DeCrypt(dst, src []byte) (n int, err error) {
	if len(src) == 0 {
		return 0, nil
	}
	if (len(src) % 2) != 0 {
		return 0, CorruptInputError(len(src))
	}

	p := c.password & 0x0F

	si, di := 0, 0
	n = len(src) / 2
	for di < n {
		dst[di+0] = (c.lDecodeMap[src[si+0]]^p)<<4 | c.rDecodeMap[src[si+1]] ^ p
		si += 2
		di++
	}
	return n, nil
}

// 错误定义
type CorruptInputError int64

func (e CorruptInputError) Error() string {
	return "illegal crypt data at input byte " + strconv.FormatInt(int64(e), 10)
}
