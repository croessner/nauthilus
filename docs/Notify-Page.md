You can customize the notify template. For this, you should use the default file **notify.html** and make changes as you
need.

There are several template fields that are required for Nauthilus to work.

## Fields and description

| Name                                                                          | Description                                                                                                                    |
|-------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|
| {{ .Title }}                                                                  | The page title shown in the browser tab                                                                                        |
| {{ if .WantWelcome }} {{ .Welcome }} {{ end }}                                | A company name above the logo                                                                                                  |
| {{ .LogoImage }}                                                              | The company logo                                                                                                               |
| {{ .LogoImageAlt }}                                                           | The "alt" name for the company logo                                                                                            |
| {{ .NotifyMessage }}                                                          | This is some Nauthilus message sent to the user                                                                                 |
| {{ .LanguageCurrentName }}                                                    | The button name of the currently displayed language                                                                            |
| {{ range .LanguagePassive }} {{ .LanguageLink }} {{ LanguageName }} {{ end }} | This block is used to render alternative page languages                                                                        | 
| {{ .LanguageTag }}                                                            | The HTML **lang** attribute                                                                                                    |
