package crypy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type TearData struct {
	Decode, Encode string
}

var pairs = []TearData{
	{"\x14\xfb\x9c\x03\xd9\x7e", "BEPLJMADNJHO"},
	{"\x14\xfb\x9c\x03\xd9", "BEPLJMADNJ"},
	{"\x14\xfb\x9c\x03", "BEPLJMAD"},
	{"", ""},
	{"f", "GG"},
	{"f1", "GGDB"},
	{"中", "OELIKN"},
	{"中国", "OELIKNOFJLLN"},
	{"中国人民", "OELIKNOFJLLNOELKLKOGLAJB"},
	{"中a", "OELIKNGB"},
	{"a国", "GBOFJLLN"},
	{"中a国", "OELIKNGBOFJLLN"},
	{"中a国b人c民", "OELIKNGBOFJLLNGCOELKLKGDOGLAJB"},
	{"中a国!@#123&*()", "OELIKNGBOFJLLNCBEACDDBDCDDCGCKCICJ"},
}

func TestCrypt_EnCryptToString(t *testing.T) {
	for _, p := range pairs {
		de := DefaultEncrypt.EnCryptToString([]byte(p.Decode))
		require.EqualValues(t, p.Encode, de)
	}
}

func TestCrypt_DeCryptString(t *testing.T) {
	for _, p := range pairs {
		de, err := DefaultEncrypt.DeCryptString(p.Encode)
		require.NoError(t, err)
		require.EqualValues(t, p.Decode, string(de))
	}
}

// 基准测试
func BenchmarkCrypt_EnCryptToString(b *testing.B) {
	str := "最"
	//str := "最是那一低头的温柔，像一朵水莲花不胜凉风的娇羞，道一声珍重，道一声真正，那一声珍重里的蜜田的忧愁。"
	//str := "最是那一低头的温柔，像一朵水莲花不胜凉风的娇羞，道一声珍重，道一声真正，那一声珍重里的蜜田的忧愁。最是那一低头的温柔，像一朵水莲花不胜凉风的娇羞，道一声珍重，道一声真正，那一声珍重里的蜜田的忧愁。最是那一低头的温柔，像一朵水莲花不胜凉风的娇羞，道一声珍重，道一声真正，那一声珍重里的蜜田的忧愁。最是那一低头的温柔，像一朵水莲花不胜凉风的娇羞，道一声珍重，道一声真正，那一声珍重里的蜜田的忧愁。"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DefaultEncrypt.EnCryptToString([]byte(str))
	}
}

func BenchmarkCrypt_DeCryptString(b *testing.B) {
	str := "OGJMIAOGJIKPOJICKDOELIIAOELNIOOFKELEOHJKIEOGLIKJOGJPJEOPLMIMOFIDIPOELIIAOGJMLFOGLALEOIIOLCOIIKLBOELIINOIIDJMOFIHIJOJKDIOOHJKIEOFKIIHOHLOJOOPLMIMOJIBJDOELIIAOFKDLAOHIPINOJIHINOPLMIMOJIBJDOELIIAOFKDLAOHJMJPOGKNKDOPLMIMOJICKDOELIIAOFKDLAOHIPINOJIHINOJIHIMOHJKIEOIJMJMOHJELAOHJKIEOFLPKHOGIEIBODIAIC"
	//str := "OGJMIAOGJIKPOJICKDOELIIAOELNIOOFKELEOHJKIEOGLIKJOGJPJE"
	//str := "OG"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DefaultEncrypt.DeCryptString(str)
	}
}