package crypy_test

import (
	"fmt"

	encrypt "github.com/oliverCJ/crypt"
)

func ExampleCrypt_EnCryptToString() {
	src := "Hello, 世界"
	enc := encrypt.DefaultEncrypt.EnCryptToString([]byte(src))
	fmt.Println(enc)
	dec, err := encrypt.DefaultEncrypt.DeCryptString(enc)
	if err != nil {
		fmt.Println("decrypt error:", err)
		return
	}
	fmt.Println(string(dec))
	// Output:
	// EHGKGCGCGACCCPOLLHJJOIJKIC
	// Hello, 世界
}

func ExampleCrypt6_EnCryptToString() {
	src := "Hello, 世界"
	enc := encrypt.DefaultEncrypt6.EnCryptToString([]byte(src))
	fmt.Println(enc)
	dec, err := encrypt.DefaultEncrypt6.DeCryptString(enc)
	if err != nil {
		fmt.Println("decrypt error:", err)
		return
	}
	fmt.Println(string(dec))
	// Output:
	// SIZlbsbsbvLsIg5ku4lW5nlVjM
	// Hello, 世界
}

func ExampleNewCrypt() {
	var (
		selfCryptDefaultStd = "qazwsxedcrfvtgby"
		selfCryptDefaultDStd = "plzokmijnuhbygvt"
		src                 = "hello world"
		password			uint8 = 254
	)

	newCrypt := encrypt.NewCrypt(selfCryptDefaultStd, selfCryptDefaultDStd, password)
	enc := newCrypt.EnCryptToString([]byte(src))
	fmt.Println(enc)
	dec, err := newCrypt.DeCryptString(enc)
	if err != nil {
		fmt.Println("decrypt error:", err)
		return
	}
	fmt.Println(string(dec))
	// Output:
	// cicbczczcltvruclryczch
	// hello world
}

func ExampleNewCrypt6() {
	var (
		selfCryptLStd = "!au^%AfgSy)-(OJ.Lz1ciox]d|v:nVEB[~wq-'h,9N6Ft=b8M{UTPH@lrZ}WD3mX"
		selfCryptRStd = "OTrjpUl5F3ktH|.vu(igBDw`_q>2-L{m*@dXM;&zCb01/!~WQa-N6#)EV[}e]A?+"
		src                 = "hello world"
		password			uint8 = 254

	)
	newCrypt := encrypt.NewCrypt6(selfCryptLStd, selfCryptRStd, password)
	enc := newCrypt.EnCryptToString([]byte(src))
	fmt.Println(enc)
	dec, err := newCrypt.DeCryptString(enc)
	if err != nil {
		fmt.Println("decrypt error:", err)
		return
	}
	fmt.Println(string(dec))
	// Output:
	// -w,2'i'i'(@{q3'(wH'i,>
	// hello world
}

func ExampleGetRandomMapString() {
	str := encrypt.GetRandomMapString()
	fmt.Println(str)
	// Output:
	//
}
