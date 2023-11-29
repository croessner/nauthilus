<!-- TOC -->
  * [Fields and description](#fields-and-description)
    * [Technical preview](#technical-preview)
    * [Example preview](#example-preview)
<!-- TOC -->

You can customize the consent template. For this, you should use the default file **consent.html** and make changes as
you need.

There are several template fields that are required for Nauthilus to work.

## Fields and description

| Name                                                                          | Description                                                                                                                                     |
|-------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| {{ .Title }}                                                                  | The page title shown in the browser tab                                                                                                         |
| {{ if .WantWelcome }} {{ .Welcome }} {{ end }}                                | A company name above the logo                                                                                                                   |
| {{ .LogoImage }}                                                              | The company logo                                                                                                                                |
| {{ .LogoImageAlt }}                                                           | The "alt" name for the company logo                                                                                                             |
| {{ .ConsentMessage }}                                                         | A descriptive text that asks the end user for consent                                                                                           |
| {{ .ApplicationName }}                                                        | The client name as defined with the hydra create client command                                                                                 |
| {{ if .WantAbout }} {{ .AboutUri }} {{ .About }} {{ end }}                    | An URI and link text for the end user to describe the application                                                                               |
| {{ .PostConsentEndpoint }}                                                    | This is the Nauthilus endpoint for the Hydra server                                                                                              |
| {{ .CSRFToken }}                                                              | **Very important**: This field must be available in your template and the hidden input field must have the name **csrf_token**                  |
| {{ .ConsentChallenge }}                                                       | **Very important**: This field must be available in your template and the hidden input field must have the name **ory.hydra.consent_challenge** |
| {{ range .Scopes }} {{ .ScopeName }} {{ .ScopeDescription }}  {{ end }}       | This will render all scopes for that application. The scope name should be replaced by a nice human understandable description                  |
| {{ .AcceptSubmit }}                                                           | Text for the accept button                                                                                                                      |
| {{ .RejectSubmit }}                                                           | Text for the reject button                                                                                                                      |
| {{ .Remember }}                                                               | A text for the label checkbox to tell the user that the consent form is being remembered for some time                                          |
| {{ if .WantTos }} {{ .TosUri }} {{ .Tos }} {{ end }}                          | Display a terms of service link if available                                                                                                    |
| {{ if .WantPolicy }} {{ .PolicyUri }} {{ .Policy }} {{ end }}                 | Display a policy link if available                                                                                                              |
| {{ .LanguageCurrentName }}                                                    | The button name of the currently displayed language                                                                                             |
| {{ range .LanguagePassive }} {{ .LanguageLink }} {{ LanguageName }} {{ end }} | This block is used to render alternative page languages                                                                                         | 
| {{ .LanguageTag }}                                                            | The HTML **lang** attribute                                                                                                                     |

The template does have a CSS section that disables pointer events. It also changes the checkbox appearance. You may
want to change this.

### Technical preview

![](https://nauthilus.io/wp-content/uploads/2023/02/skeleton-consent-1.png)

### Example preview

![](https://nauthilus.io/wp-content/uploads/2023/02/example-consent-1.png)