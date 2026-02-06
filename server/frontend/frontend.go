// Copyright (C) 2024 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package frontend

import (
	"log/slog"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

// Scope represents a scope used in the ConsentPageData struct. It contains the name and description of the scope.
type Scope struct {
	// ScopeName represents the name of the scope.
	ScopeName string

	// ScopeDescription represents a detailed description of the scope.
	ScopeDescription string
}

// Language represents a language used in various page data structs.
type Language struct {
	// LanguageLink represents the link associated with the language
	LanguageLink string

	// LanguageName represents the name of the language
	LanguageName string
}

type NotifyPageData struct {
	// Determines if the Welcome message should be displayed
	WantWelcome bool

	// Determines if the Policy should be displayed
	WantPolicy bool

	// Determines if the Terms of Service (TOS) should be displayed
	WantTos bool

	// The title of the Notify page
	Title string

	// The Welcome message
	Welcome string

	// The path or URL to logo image to be displayed
	LogoImage string

	// The alt text for the logo image
	LogoImageAlt string

	// The Notify message
	NotifyMessage string

	// The language tag for the page
	LanguageTag string

	// The current name of the language
	LanguageCurrentName string

	// A list of other available languages
	LanguagePassive []Language
}

// GetLocalized is a function that returns the localized message based on the message ID and the context provided.
func GetLocalized(ctx *gin.Context, cfg config.File, logger *slog.Logger, messageID string) string {
	localizer := ctx.MustGet(definitions.CtxLocalizedKey).(*i18n.Localizer)

	localizeConfig := i18n.LocalizeConfig{
		MessageID: messageID,
	}
	localization, err := localizer.Localize(&localizeConfig)
	if err != nil {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			cfg,
			logger,
			definitions.DbgAuth,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			"message_id", messageID,
			definitions.LogKeyMsg, "Failed to get localized message",
			definitions.LogKeyError, err,
		)

		return messageID
	}

	return localization
}

// CreateLanguagePassive creates a slice of Language structs for non-current languages.
func CreateLanguagePassive(ctx *gin.Context, cfg config.File, destPage string, languageTags []language.Tag, currentName string) []Language {
	var languagePassive []Language

	for _, languageTag := range languageTags {
		languageName := cases.Title(languageTag, cases.NoLower).String(display.Self.Name(languageTag))
		if languageName != currentName {
			baseName, _ := languageTag.Base()

			var sb strings.Builder

			sb.WriteString(destPage)
			sb.WriteByte('/')
			sb.WriteString(baseName.String())
			sb.WriteByte('?')
			sb.WriteString(ctx.Request.URL.RawQuery)

			languagePassive = append(
				languagePassive,
				Language{
					LanguageLink: sb.String(),
					LanguageName: languageName,
				},
			)
		}
	}

	return languagePassive
}

type LoginPageData struct {
	// InDevelopment is a flag that is true, if the build-tag dev is used.
	InDevelopment bool

	// Determines if the Welcome message should be displayed
	WantWelcome bool

	// Determines if the Policy should be displayed
	WantPolicy bool

	// Determines if the Terms of Service (TOS) should be displayed
	WantTos bool

	// Determines if the About information should be displayed
	WantAbout bool

	// WantRemember is a flag for the regular login page.
	WantRemember bool

	// Indicates if there was an error
	HaveError bool

	// The title of the Login page
	Title string

	// The Welcome message
	Welcome string

	// The path or URL to logo image to be displayed
	LogoImage string

	// The alternate text for the logo image
	LogoImageAlt string

	// The name of the application
	ApplicationName string

	// The login details
	Login string

	// The placeholder for the login input form
	LoginPlaceholder string

	// The Privacy statement
	Privacy string

	// User password
	Password string

	// Placeholder for password input form
	PasswordPlaceholder string

	// The Policy terms
	Policy string

	// The URL to the policy document
	PolicyUri string

	// The Terms of Service
	Tos string

	// The URL to the Terms of Service document
	TosUri string

	// Information about the service or company
	About string

	// The URL to more About information
	AboutUri string

	// Information regarding remember functionality
	Remember string

	// Text for Submit button
	Submit string

	// Error message if any
	ErrorMessage string

	// Alternate choices text
	Or string

	// Information on the device being used
	Device string

	// CSRF security token
	CSRFToken string

	// Login challenge token
	LoginChallenge string

	// Endpoint for submitting login
	PostLoginEndpoint string

	// Endpoint for device login
	DeviceLoginEndpoint string

	// Current language code
	LanguageTag string

	// Name of the current language
	LanguageCurrentName string

	// BlockedIPAddresses of other available languages
	LanguagePassive []Language
}

// TwoFactorData defines the structure for two-factor authentication page data.
type TwoFactorData struct {
	// WantWelcome indicates if a welcome message should be displayed
	WantWelcome bool

	// WantPolicy indicates if the policy section should be displayed
	WantPolicy bool

	// WantTos indicates if Terms of Service is mandatory
	WantTos bool

	// WantAbout indicates if displaying 'About' information is desired
	WantAbout bool

	// Title is the title of the webpage or context
	Title string

	// Welcome is the welcome message
	Welcome string

	// LogoImage is the link of the logo image
	LogoImage string

	// LogoImageAlt is the alt text of the logo image
	LogoImageAlt string

	// ApplicationName is the name of the application
	ApplicationName string

	// Code is the two-factor authentication code
	Code string

	// Policy is the policy text
	Policy string

	// PolicyUri is the link to the policy document
	PolicyUri string

	// Tos is the Terms of Service text
	Tos string

	// TosUri is the URL to the Terms of Service document
	TosUri string

	// About holds content related to 'About Us' or 'About the Application'
	About string

	// AboutUri is the URL to the 'About Us' or 'About the application' page
	AboutUri string

	// Submit is the label for the submit action
	Submit string

	// CSRFToken is the token used for Cross-Site Request Forgery protection
	CSRFToken string

	// LoginChallenge represents the challenge used for login
	LoginChallenge string

	// User is the User ID or Name
	User string

	// PostLoginEndpoint is the API endpoint to submit login data
	PostLoginEndpoint string

	// LanguageTag houses the language tag, e.g., 'en-US'
	LanguageTag string

	// LanguageCurrentName is the fullname of the current language (e.g., 'English')
	LanguageCurrentName string

	// LanguagePassive houses a slice of the languages that are passively being used/available
	LanguagePassive []Language
}

// LogoutPageData defines the data structure for details related to the logout page.
type LogoutPageData struct {
	// WantWelcome is a flag indicating if the welcome message should be displayed or not.
	WantWelcome bool

	// Title represents the title of the logout page.
	Title string

	// Welcome holds the welcome message to be displayed, if WantWelcome flag is set to true.
	Welcome string

	// LogoutMessage carries the logout message.
	LogoutMessage string

	// AcceptSubmit and RejectSubmit hold messages for submission options upon logout.
	// These could be used for multi-step or confirmation based logout procedures.
	AcceptSubmit string
	RejectSubmit string

	// CSRFToken represents the CSRF token for security measures.
	CSRFToken string

	// LogoutChallenge represents a challenge string for logout.
	// It can be used for additional validation on logout requests.
	LogoutChallenge string

	// PostLogoutEndpoint is the endpoint to which requests are made after logout.
	PostLogoutEndpoint string

	// LanguageTag refers to the IETF language tag for selected language (e.g. "en-US").
	LanguageTag string

	// LanguageCurrentName is the human-readable name of the current language (e.g. "English").
	LanguageCurrentName string

	// LanguagePassive is a slice of passive languages supported by the system.
	// These could be offered as alternative language options on the logout page.
	LanguagePassive []Language
}

// ConsentPageData defines the data structure for managing user consent information on a web page.
type ConsentPageData struct {
	// WantWelcome is a boolean to indicate if a welcome message is needed.
	WantWelcome bool

	// WantPolicy is a boolean to indicate if a policy is needed.
	WantPolicy bool

	// WantTos is a boolean to indicate if Terms of Service is required.
	WantTos bool

	// WantAbout is a boolean to indicate if an "About Us" section is needed.
	WantAbout bool

	// Title is the title of the web page.
	Title string

	// Welcome represents the welcome message on the page.
	Welcome string

	// LogoImage represents the URL or path to the logo image.
	LogoImage string

	// LogoImageAlt is the alternative text for the logo image.
	LogoImageAlt string

	// ConsentMessage is the message presented to the user asking for their consent.
	ConsentMessage string

	// ApplicationName is the name of the application requesting consent.
	ApplicationName string

	// About is information about the application or the reason for the consent.
	About string

	// AboutUri is a URI where the user can find more information about the application or consent.
	AboutUri string

	// Policy is the policy text that the user should agree to.
	Policy string

	// PolicyUri is the URI where the full policy can be read.
	PolicyUri string

	// Tos represents the terms of service that the user should agree to.
	Tos string

	// TosUri is the URI where the full terms of service can be read.
	TosUri string

	// Remember represents a message or option to remember the user's consent.
	Remember string

	// AcceptSubmit is the text for the button or link to accept the consent.
	AcceptSubmit string

	// RejectSubmit is the text for the button or link to reject the consent.
	RejectSubmit string

	// CSRFToken is the token used for CSRF protection.
	CSRFToken string

	// ConsentChallenge is a unique challenge associated with the consent request.
	ConsentChallenge string

	// PostConsentEndpoint is the endpoint where the consent decision should be posted.
	PostConsentEndpoint string

	// LanguageTag is the language tag for the page.
	LanguageTag string

	// LanguageCurrentName is the name of the currently selected language.
	LanguageCurrentName string

	// Scopes represents the list of scopes that the app is requesting access to.
	Scopes []Scope

	// LanguagePassive represents the list of passive languages.
	LanguagePassive []Language
}

type TOTPPageData struct {
	WantWelcome         bool
	WantPolicy          bool
	WantTos             bool
	HaveError           bool
	Title               string
	Welcome             string
	LogoImage           string
	LogoImageAlt        string
	TOTPMessage         string
	TOTPCopied          string
	Code                string
	Submit              string
	ErrorMessage        string
	CSRFToken           string
	QRCode              string
	PostTOTPEndpoint    string
	LanguageTag         string
	LanguageCurrentName string
	LanguagePassive     []Language
}

type HomePageData struct {
	InDevelopment       bool
	WantWelcome         bool
	WantPolicy          bool
	WantTos             bool
	HaveTOTP            bool
	Title               string
	Welcome             string
	LogoImage           string
	LogoImageAlt        string
	HomeMessage         string
	RegisterTOTP        string
	EndpointTOTP        string
	Or                  string
	RegisterWebAuthn    string
	EndpointWebAuthn    string
	LanguageTag         string
	LanguageCurrentName string
	LanguagePassive     []Language
}
