package core

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	_ "github.com/go-sql-driver/mysql"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

// sqlPassDB implements the SQL password database backend.
//
//nolint:gocognit,gocyclo,maintidx // Ignore
func sqlPassDB(auth *Authentication) (passDBResult *PassDBResult, err error) {
	var (
		assertOk      bool
		query         string
		accountField  string
		passwordField string
		password      string
		account       string
		protocol      *config.SQLSearchProtocol
		conn          *sqlx.DB
	)

	// SQL results
	result := make(map[string]any)

	passDBResult = &PassDBResult{}

	if conn, err = backend.Database.GetConn(); err != nil {
		return
	}

	if protocol, err = config.LoadableConfig.GetSQLSearchProtocol(auth.Protocol.Get()); err != nil {
		return
	}

	if query, err = protocol.GetUserQuery(); err != nil {
		return
	}

	macroSource := &util.MacroSource{
		Username:    auth.Username,
		XLocalIP:    auth.XLocalIP,
		XPort:       auth.XPort,
		ClientIP:    auth.ClientIP,
		XClientPort: auth.XClientPort,
		TOTPSecret:  auth.TOTPSecret,
		Protocol:    *auth.Protocol,
	}

	query = strings.ReplaceAll(query, "%s", auth.Username)
	query = macroSource.ReplaceMacros(query)
	query = util.RemoveCRLFFromQueryOrFilter(query, " ")

	if accountField, err = protocol.GetAccountField(); err != nil {
		return
	}

	passDBResult.AccountField = &accountField

	if passwordField, err = protocol.GetPasswordField(); err != nil {
		return
	}

	if protocol.TOTPSecretField != "" {
		passDBResult.TOTPSecretField = &protocol.TOTPSecretField
	}

	util.DebugModule(global.DbgSQL, global.LogKeyGUID, auth.GUID, global.LogKeyMsg, query)

	row := conn.QueryRowx(query)
	if err = row.MapScan(result); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return passDBResult, nil
		}

		return
	}

	// Fix []uint8 results from MariaDB
	util.MapBytesToString(result)

	for key, value := range result {
		if strings.EqualFold(strings.ToLower(key), strings.ToLower(passwordField)) {
			password, assertOk = value.(string)
			if !assertOk {
				level.Error(logging.DefaultErrLogger).Log(
					global.LogKeyGUID, auth.GUID, global.LogKeyError, "'password' result not present or type is not string")

				return
			}

			delete(result, key)
		}

		if strings.EqualFold(strings.ToLower(key), strings.ToLower(accountField)) {
			account, assertOk = value.(string)
			if !assertOk {
				level.Warn(logging.DefaultLogger).Log(
					global.LogKeyGUID, auth.GUID, "warning", "'account' result not present or type is not string")
			}
		}
	}

	logPassword := "<hidden>"
	if config.EnvConfig.DevMode {
		logPassword = password
	}

	util.DebugModule(global.DbgSQL,
		global.LogKeyGUID, auth.GUID, "account", account, "password", logPassword, "extra", fmt.Sprintf("%+v", result),
	)

	if len(result) > 0 {
		attributes := make(backend.DatabaseResult, len(result))

		for key, value := range result {
			attributes[key] = []any{value}
		}

		passDBResult.Attributes = attributes
	}

	// User found
	if password != "" {
		passDBResult.UserFound = true
		passwordMatch := false

		if !auth.NoAuth {
			if config.LoadableConfig.GetSQLConfigCrypt() {
				passwordMatch, err = util.ComparePasswords(password, auth.Password)
				if err != nil {
					level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, auth.GUID, global.LogKeyError, err)

					return
				}
			} else {
				// Pure plaintext passwords
				if auth.Password == password {
					passwordMatch = true
				}
			}
		}

		if auth.NoAuth || passwordMatch {
			passDBResult.Authenticated = true
			passDBResult.Backend = global.BackendSQL

			return
		}
	}

	return
}

// sqlAccountDB implements the list-account mode and returns all known users from an SQL server.
func sqlAccountDB(auth *Authentication) (accounts AccountList, err error) {
	var (
		query    string
		protocol *config.SQLSearchProtocol
		conn     *sqlx.DB
	)

	if conn, err = backend.Database.GetConn(); err != nil {
		return
	}

	if protocol, err = config.LoadableConfig.GetSQLSearchProtocol(auth.Protocol.Get()); err != nil {
		return
	}

	if query, err = protocol.GetListAccountsQuery(); err != nil {
		return
	}

	err = conn.Select(&accounts, query)

	return
}

// sqlAddTOTPSecret adds a newly generated TOTP secret to an SQL server.
func sqlAddTOTPSecret(auth *Authentication, totp *TOTPSecret) (err error) {
	var (
		configField string
		query       string
		protocol    *config.SQLSearchProtocol
		result      sql.Result
		conn        *sqlx.DB
	)

	if conn, err = backend.Database.GetConn(); err != nil {
		return
	}

	if protocol, err = config.LoadableConfig.GetSQLSearchProtocol(auth.Protocol.Get()); err != nil {
		return
	}

	if query, err = protocol.GetTOTPSecretQuery(); err != nil {
		return
	}

	configField = totp.getSQLTOTPSecret(protocol)
	if configField == "" {
		err = errors2.ErrSQLConfig.WithDetail(
			fmt.Sprintf("Missing SQL totp secret field; protocol=%v", auth.Protocol.Get()))

		return
	}

	mfaValue := totp.getValue()

	auth.TOTPSecret = &mfaValue
	auth.TOTPSecretField = &configField

	macroSource := &util.MacroSource{
		Username:    auth.Username,
		XLocalIP:    auth.XLocalIP,
		XPort:       auth.XPort,
		ClientIP:    auth.ClientIP,
		XClientPort: auth.XClientPort,
		TOTPSecret:  auth.TOTPSecret,
		Protocol:    *auth.Protocol,
	}

	query = macroSource.ReplaceMacros(query)

	util.DebugModule(global.DbgSQL, global.LogKeyGUID, auth.GUID, global.LogKeyMsg, query)

	result, err = conn.Exec(query)
	if numberRows, _ := result.RowsAffected(); numberRows == 0 {
		err = errors2.ErrNoSQLRowsUpdated
	}

	return
}

func sqlGetWebAuthnCredentials(uniqueUserID string) ([]webauthn.Credential, error) {
	_ = uniqueUserID

	return []webauthn.Credential{}, nil
}
