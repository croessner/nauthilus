<!-- TOC -->
  * [Fields and description](#fields-and-description)
    * [Technical preview](#technical-preview)
    * [Example preview](#example-preview)
<!-- TOC -->

You can customize the two-factor template. For this, you should use the default file **twofactor.html** and make changes
as you need.

There are several template fields that are required for Nauthilus to work.

## Fields and description

| Name                                                                          | Description                                                                                                                                         |
|-------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| {{ .Title }}                                                                  | The page title shown in the browser tab                                                                                                             |
| {{ if .WantWelcome }} {{ .Welcome }} {{ end }}                                | A company name above the logo                                                                                                                       |
| {{ .LogoImage }}                                                              | The company logo                                                                                                                                    |
| {{ .LogoImageAlt }}                                                           | The "alt" name for the company logo                                                                                                                 |
| {{ .ApplicationName }}                                                        | The client name as defined with the hydra create client command                                                                                     |
| {{ if .WantAbout }} {{ .AboutUri }} {{ .About }} {{ end }}                    | An URI and link text for the end user to describe the application                                                                                   |
| {{ .PostLoginEndpoint }}                                                      | This is the Nauthilus endpoint for the Hydra server                                                                                                  |
| {{ .CSRFToken }}                                                              | **Very important**: This field must be available in your template and the hidden input field must have the name **csrf_token**                      |
| {{ .LoginChallenge }}                                                         | **Very important**: This field must be available in your template and the hidden input field must have the name **ory.hydra.login_challenge**       |
| {{ .User }}                                                                   | _Obsolete since 2.3.0_<br/>**Very important** This field must be available in your template and the hidden input field must have the name **_user** |
| {{ .Submit }}                                                                 | The text for the submit button                                                                                                                      |
| {{ if .WantTos }} {{ .TosUri }} {{ .Tos }} {{ end }}                          | Display a terms of service link if available                                                                                                        |
| {{ if .WantPolicy }} {{ .PolicyUri }} {{ .Policy }} {{ end }}                 | Display a policy link if available                                                                                                                  |
| {{ .LanguageCurrentName }}                                                    | The button name of the currently displayed language                                                                                                 |
| {{ range .LanguagePassive }} {{ .LanguageLink }} {{ LanguageName }} {{ end }} | This block is used to render alternative page languages                                                                                             | 
| {{ .LanguageTag }}                                                            | The HTML **lang** attribute                                                                                                                         |

### Technical preview

![](https://nauthilus.io/wp-content/uploads/2023/02/skeleton-twofactor.png)

### Example preview

![](https://nauthilus.io/wp-content/uploads/2023/02/example-twofactor.png)
