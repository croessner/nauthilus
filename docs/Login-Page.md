<!-- TOC -->
  * [Fields and description](#fields-and-description)
    * [Technical preview](#technical-preview)
    * [Example preview](#example-preview)
<!-- TOC -->

You can customize the login template. For this, you should use the default file **login.html** and make changes as you
need.

There are several template fields that are required for Nauthilus to work.

## Fields and description

| Name                                                                          | Description                                                                                                                                   |
|-------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| {{ .Title }}                                                                  | The page title shown in the browser tab                                                                                                       |
| {{ if .WantWelcome }} {{ .Welcome }} {{ end }}                                | A company name above the logo                                                                                                                 |
| {{ .LogoImage }}                                                              | The company logo                                                                                                                              |
| {{ .LogoImageAlt }}                                                           | The "alt" name for the company logo                                                                                                           |
| {{ .ApplicationName }}                                                        | The client name as defined with the hydra create client command                                                                               |
| {{ if .WantAbout }} {{ .AboutUri }} {{ .About }} {{ end }}                    | An URI and link text for the end user to describe the application                                                                             |
| {{ .PostLoginEndpoint }}                                                      | This is the Nauthilus endpoint for the Hydra server                                                                                            |
| {{ .CSRFToken }}                                                              | **Very important**: This field must be available in your template and the hidden input field must have the name **csrf_token**                |
| {{ .LoginChallenge }}                                                         | **Very important**: This field must be available in your template and the hidden input field must have the name **ory.hydra.login_challenge** |
| {{ .Login }}                                                                  | This is the label for the login field                                                                                                         |
| {{ .LoginPlaceholder }}                                                       | This is the help text which is displayed in the input field                                                                                   |
| {{ .Privacy }}                                                                | A small user information that data is handled with data privacy in mind                                                                       |
| {{ .Password }}                                                               | This is the label for the password field                                                                                                      |
| {{ .PasswordPlaceholder }}                                                    | This is the help text which is displayed in the input field                                                                                   |
| {{ .Submit }}                                                                 | The text for the submit button                                                                                                                |
| {{ .Remember }}                                                               | A text for the label checkbox to tell the user that the login form is being remembered for some time                                          |
| {{ if .WantTos }} {{ .TosUri }} {{ .Tos }} {{ end }}                          | Display a terms of service link if available                                                                                                  |
| {{ if .WantPolicy }} {{ .PolicyUri }} {{ .Policy }} {{ end }}                 | Display a policy link if available                                                                                                            |
| {{ .LanguageCurrentName }}                                                    | The button name of the currently displayed language                                                                                           |
| {{ range .LanguagePassive }} {{ .LanguageLink }} {{ LanguageName }} {{ end }} | This block is used to render alternative page languages                                                                                       | 
| {{ if .HaveError }} {{ .ErrorMessage }} {{ end }}                             | If an error occurred, display it to the user                                                                                                  |
| {{ .LanguageTag }}                                                            | The HTML **lang** attribute                                                                                                                   |

### Technical preview

![](https://nauthilus.io/wp-content/uploads/2023/02/skeleton-login-1.png)

### Example preview

![](https://nauthilus.io/wp-content/uploads/2023/02/example-login-1.png)
