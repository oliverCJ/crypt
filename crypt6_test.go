package crypy

import (
	"github.com/stretchr/testify/require"
	"testing"
)

var pairsForCrypt6 = []TearData{
	{"\x14\xfb\x9c\x03\xd9\x7e", "FU!7ncAD2Zf!"},
	{"\x14\xfb\x9c\x03\xd9", "FU!7ncAD2Z"},
	{"\x14\xfb\x9c\x03", "FU!7ncAD"},
	{"", ""},
	{"f", "Zm"},
	{"f1", "ZmMx"},
	{"中", "5ku4rt"},
	{"中国", "5ku4rt5lmbv9"},
	{"中国人民", "5ku4rt5lmbv95ku6u65mswkR"},
	{"中a", "5ku4rtYh"},
	{"a国", "Yh5lmbv9"},
	{"中a国", "5ku4rtYh5lmbv9"},
	{"中a国b人c民", "5ku4rtYh5lmbv9Yi5ku6u6Yj5mswkR"},
	{"中a国!@#123&*()", "5ku4rtYh5lmbv9IhQAIjMxMyMzJmKqKoKp"},
}

func TestCrypt6_EnCryptToString(t *testing.T) {
	for _, p := range pairsForCrypt6 {
		de := DefaultEncrypt6.EnCryptToString([]byte(p.Decode))
		require.EqualValues(t, p.Encode, de)
	}
}

func TestCrypt6_DeCryptString(t *testing.T) {
	for _, p := range pairsForCrypt6 {
		de, err := DefaultEncrypt6.DeCryptString(p.Encode)
		require.NoError(t, err)
		require.EqualValues(t, p.Decode, de)
	}
}

// 基准测试
func BenchmarkCrypt6_EnCryptToString(b *testing.B) {
	str := "最是那一低头的温柔，像一朵水莲花不胜凉风的娇羞，道一声珍重，道一声真正，那一声珍重里的蜜田的忧愁。"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DefaultEncrypt6.EnCryptToString([]byte(str))
	}
}

func BenchmarkCrypt6_DeCryptString(b *testing.B) {
	str := "5mncgA5mmYrv6pgCoj5ku4gA5kv9jO5lpkt05nmahE5mu4qp5mnflU7vv8jM5lgDjP5ku4gA5mnct15mswt06ojOsy6oiKsx5ku4jN6ogDnc5lhHiJ6pojjO5nmahE5lqohH5nv!ne7vv8jM6pgBkT5ku4gA5lojsw5njPjN6phHjN7vv8jM6pgBkT5ku4gA5lojsw5nncnf5mrtoj7vv8jM6pgCoj5ku4gA5lojsw5njPjN6phHjN6phHjM5nmahE6oncnc5nlUsw5nmahE5lv#pn5mhEgB4jgAgC"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DefaultEncrypt6.DeCryptString(str)
	}
}