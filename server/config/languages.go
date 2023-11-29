package config

import "golang.org/x/text/language"

var (
	Matcher             language.Matcher
	DefaultLanguageTags []language.Tag
)

func init() {
	DefaultLanguageTags = []language.Tag{
		language.English,
		language.German,
		language.French,
	}

	Matcher = language.NewMatcher(DefaultLanguageTags)
}
