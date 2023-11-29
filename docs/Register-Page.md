<!-- TOC -->
  * [Fields and description](#fields-and-description)
    * [Technical preview](#technical-preview)
    * [Example preview](#example-preview)
<!-- TOC -->

You can customize the register template. For this, you should use the default file **register.html** and make changes as
you need.

There are several template fields that are required for Nauthilus to work.

## Fields and description

| Name                                                                          | Description                                                                                                                    |
|-------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|
| {{ .Title }}                                                                  | The page title shown in the browser tab                                                                                        |
| {{ if .WantWelcome }} {{ .Welcome }} {{ end }}                                | A company name above the logo                                                                                                  |
| {{ .LogoImage }}                                                              | The company logo                                                                                                               |
| {{ .LogoImageAlt }}                                                           | The "alt" name for the company logo                                                                                            |
| {{ .PostLoginEndpoint }}                                                      | This is the Nauthilus endpoint for the Hydra server                                                                             |
| {{ .CSRFToken }}                                                              | **Very important**: This field must be available in your template and the hidden input field must have the name **csrf_token** |
| {{ .Login }}                                                                  | This is the label for the login field                                                                                          |
| {{ .LoginPlaceholder }}                                                       | This is the help text which is displayed in the input field                                                                    |
| {{ .Privacy }}                                                                | A small user information that data is handled with data privacy in mind                                                        |
| {{ .Password }}                                                               | This is the label for the password field                                                                                       |
| {{ .PasswordPlaceholder }}                                                    | This is the help text which is displayed in the input field                                                                    |
| {{ .Submit }}                                                                 | The text for the submit button                                                                                                 |
| {{ .LanguageCurrentName }}                                                    | The button name of the currently displayed language                                                                            |
| {{ range .LanguagePassive }} {{ .LanguageLink }} {{ LanguageName }} {{ end }} | This block is used to render alternative page languages                                                                        | 
| {{ if .HaveError }} {{ .ErrorMessage }} {{ end }}                             | If an error occurred, display it to the user                                                                                   |
| {{ .LanguageTag }}                                                            | The HTML **lang** attribute                                                                                                    |

Not supported yet (version 2.3.x):

| Name                                                                          | Description                                                                                                                                   |
|-------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| {{ if .WantTos }} {{ .TosUri }} {{ .Tos }} {{ end }}                          | Display a terms of service link if available                                                                                                  |
| {{ if .WantPolicy }} {{ .PolicyUri }} {{ .Policy }} {{ end }}                 | Display a policy link if available                                                                                                            |

### Technical preview

The template is derived from the login page, so it looks similar to it. There is currently no support for terms of
service nor policy. This may come in future releases, therefor the template already ships with the necessary HTML block.

![](https://nauthilus.io/wp-content/uploads/2023/02/skeleton-login-1.png)

### Example preview

The template is derived from the login page, so it looks similar to it. There is currently no support for terms of
service nor policy. This may come in future releases, therefor the template already ships with the necessary HTML block.

![](https://nauthilus.io/wp-content/uploads/2023/02/example-login-1.png)
