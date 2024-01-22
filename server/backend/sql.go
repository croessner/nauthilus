package backend

import (
	"context"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

var Database *SQLDatabase //nolint:gochecknoglobals // System wide SQL pool

type SQLDatabase struct {
	dsn    string
	driver string
	Conn   *sqlx.DB
}

func (s *SQLDatabase) GetConn() (*sqlx.DB, error) {
	if s.Conn == nil {
		return nil, errors.ErrNoDatabaseConnection.WithDetail("No SQL database connection established")
	}

	return s.Conn, nil
}

func NewDatabase(ctx context.Context) *SQLDatabase {
	var err error

	dsn := config.LoadableConfig.GetSQLConfigDSN()
	if dsn == "" {
		level.Error(logging.DefaultErrLogger).Log(
			global.LogKeyError, errors.ErrSQLConfig.WithDetail("No DSN configured").GetDetails())

		return nil
	}

	newDatabase := &SQLDatabase{
		dsn: dsn,
	}

	err = newDatabase.parseDSN()
	if err != nil {
		newDatabase.Conn = nil

		level.Error(logging.DefaultErrLogger).Log(global.LogKeyError, err)
		util.DebugModule(global.DbgSQL, "sql_driver", newDatabase.driver)

		return nil
	}

	newDatabase.init(ctx)

	return newDatabase
}

func (s *SQLDatabase) init(ctx context.Context) {
	var err error

	s.Conn, err = sqlx.ConnectContext(ctx, s.driver, func() string {
		if s.driver == "mysql" {
			return s.dsn[strings.Index(s.dsn, "://")+3:]
		}

		return s.dsn
	}())

	if err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyError, err)

		return
	}

	s.Conn.SetConnMaxLifetime(time.Minute * 3) //nolint:gomnd // Time factor
	s.Conn.SetMaxOpenConns(viper.GetInt("sql_max_connections"))
	s.Conn.SetMaxIdleConns(viper.GetInt("sql_max_idle_connections"))
}

func (s *SQLDatabase) parseDSN() error {
	switch {
	case strings.HasPrefix(s.dsn, "mysql://"):
		s.driver = "mysql"
	case strings.HasPrefix(s.dsn, "postgres://") || strings.HasPrefix(s.dsn, "postgresql://"):
		s.driver = "postgres"
	default:
		return errors.ErrUnsupportedSQLDriver
	}

	return nil
}
