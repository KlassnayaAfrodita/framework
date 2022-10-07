package database

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"

	contractsorm "github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/database/support"
	"github.com/goravel/framework/facades"
)

type Gorm struct {
	instance    *gorm.DB
	tx          *gorm.DB
	transaction bool
}

func NewGorm(ctx context.Context, connection string) (contractsorm.DB, error) {
	db, err := NewGormInstance(connection)

	if err != nil {
		return nil, errors.New(fmt.Sprintf("gorm open database error: %v", err))
	}

	if ctx != nil {
		db = db.WithContext(ctx)
	}

	return &Gorm{
		instance: db,
	}, nil
}

func NewGormInstance(connection string) (*gorm.DB, error) {
	gormConfig, err := getGormConfig(connection)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("init gorm config error: %v", err))
	}

	var logLevel gormLogger.LogLevel
	if facades.Config.GetBool("app.debug") {
		logLevel = gormLogger.Info
	} else {
		logLevel = gormLogger.Error
	}

	return gorm.Open(gormConfig, &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		SkipDefaultTransaction:                   true,
		Logger:                                   gormLogger.Default.LogMode(logLevel),
	})
}

func (r *Gorm) Begin() (contractsorm.Transaction, error) {
	r.transaction = true
	r.tx = r.getInstance().Begin()

	return r, r.tx.Error
}

func (r *Gorm) Commit() error {
	err := r.getInstance().Commit().Error
	r.tx = nil
	r.transaction = false

	return err
}

func (r *Gorm) Count(count *int64) error {
	err := r.getInstance().Count(count).Error
	r.close()

	return err
}

func (r *Gorm) Create(value interface{}) error {
	err := r.getInstance().Create(value).Error
	r.close()

	return err
}

func (r *Gorm) Delete(value interface{}, conds ...interface{}) error {
	err := r.getInstance().Delete(value, conds...).Error
	r.close()

	return err
}

func (r *Gorm) Exec(sql string, values ...interface{}) error {
	err := r.getInstance().Exec(sql, values...).Error
	r.close()

	return err
}

func (r *Gorm) Find(dest interface{}, conds ...interface{}) error {
	err := r.getInstance().Find(dest, conds...).Error
	r.close()

	return err
}

func (r *Gorm) First(dest interface{}) error {
	err := r.getInstance().First(dest).Error
	r.close()

	return err
}

func (r *Gorm) FirstOrCreate(dest interface{}, conds ...interface{}) error {
	var err error
	if len(conds) > 1 {
		err = r.getInstance().Attrs([]interface{}{conds[1]}...).FirstOrCreate(dest, []interface{}{conds[0]}...).Error
	} else {
		err = r.getInstance().FirstOrCreate(dest, conds...).Error
	}
	r.close()

	return err
}

func (r *Gorm) ForceDelete(value interface{}, conds ...interface{}) error {
	err := r.getInstance().Unscoped().Delete(value, conds...).Error
	r.close()

	return err
}

func (r *Gorm) Get(dest interface{}) error {
	err := r.getInstance().Find(dest).Error
	r.close()

	return err
}

func (r *Gorm) Group(name string) contractsorm.Query {
	r.tx = r.getInstance().Group(name)

	return r
}

func (r *Gorm) Having(query interface{}, args ...interface{}) contractsorm.Query {
	r.tx = r.getInstance().Having(query, args...)

	return r
}

func (r *Gorm) Join(query string, args ...interface{}) contractsorm.Query {
	r.tx = r.getInstance().Joins(query, args...)

	return r
}

func (r *Gorm) Limit(limit int) contractsorm.Query {
	r.tx = r.getInstance().Limit(limit)

	return r
}

func (r *Gorm) Model(value interface{}) contractsorm.Query {
	r.tx = r.getInstance().Model(value)

	return r
}

func (r *Gorm) Offset(offset int) contractsorm.Query {
	r.tx = r.getInstance().Offset(offset)

	return r
}

func (r *Gorm) Order(value interface{}) contractsorm.Query {
	r.tx = r.getInstance().Order(value)

	return r
}

func (r *Gorm) OrWhere(query interface{}, args ...interface{}) contractsorm.Query {
	r.tx = r.getInstance().Or(query, args...)

	return r
}

func (r *Gorm) Pluck(column string, dest interface{}) error {
	err := r.getInstance().Pluck(column, dest).Error
	r.close()

	return err
}

func (r *Gorm) Raw(sql string, values ...interface{}) contractsorm.Query {
	r.tx = r.getInstance().Raw(sql, values...)

	return r
}

func (r *Gorm) Rollback() error {
	err := r.getInstance().Rollback().Error
	r.tx = nil
	r.transaction = false

	return err
}

func (r *Gorm) Save(value interface{}) error {
	err := r.getInstance().Save(value).Error
	r.close()

	return err
}

func (r *Gorm) Scan(dest interface{}) error {
	err := r.getInstance().Scan(dest).Error
	r.close()

	return err
}

func (r *Gorm) Select(query interface{}, args ...interface{}) contractsorm.Query {
	r.tx = r.getInstance().Select(query, args...)

	return r
}

func (r *Gorm) Table(name string, args ...interface{}) contractsorm.Query {
	r.tx = r.getInstance().Table(name, args...)

	return r
}

func (r *Gorm) Update(column string, value interface{}) error {
	err := r.getInstance().Update(column, value).Error
	r.close()

	return err
}

func (r *Gorm) Updates(values interface{}) error {
	err := r.getInstance().Updates(values).Error
	r.close()

	return err
}

func (r *Gorm) Where(query interface{}, args ...interface{}) contractsorm.Query {
	r.tx = r.getInstance().Where(query, args...)

	return r
}

func (r *Gorm) WithTrashed() contractsorm.Query {
	r.tx = r.getInstance().Unscoped()

	return r
}

func (r *Gorm) Scopes(funcs ...func(contractsorm.Query) contractsorm.Query) contractsorm.Query {
	var gormFuncs []func(*gorm.DB) *gorm.DB
	for _, item := range funcs {
		gormFuncs = append(gormFuncs, func(db *gorm.DB) *gorm.DB {
			r.tx = db
			item(r)

			return r.tx
		})
	}

	r.tx = r.getInstance().Scopes(gormFuncs...)

	return r
}

func (r *Gorm) getInstance() *gorm.DB {
	if r.tx != nil {
		return r.tx
	}

	return r.instance
}

func (r *Gorm) close() {
	if !r.transaction {
		r.tx = nil
	}
}

func getGormConfig(connection string) (gorm.Dialector, error) {
	defaultDatabase := facades.Config.GetString("database.default")
	driver := facades.Config.GetString("database.connections." + defaultDatabase + ".driver")
	switch driver {
	case support.Mysql:
		return getMysqlGormConfig(connection), nil
	case support.Postgresql:
		return getPostgresqlGormConfig(connection), nil
	case support.Sqlite:
		return getSqliteGormConfig(connection), nil
	case support.Sqlserver:
		return getSqlserverGormConfig(connection), nil
	default:
		return nil, errors.New("database driver only support mysql, postgresql, sqlite and sqlserver")
	}
}

func getMysqlGormConfig(connection string) gorm.Dialector {
	return mysql.New(mysql.Config{
		DSN: support.GetMysqlDsn(connection),
	})
}

func getPostgresqlGormConfig(connection string) gorm.Dialector {
	return postgres.New(postgres.Config{
		DSN: support.GetPostgresqlDsn(connection),
	})
}

func getSqliteGormConfig(connection string) gorm.Dialector {
	return sqlite.Open(support.GetSqliteDsn(connection))
}

func getSqlserverGormConfig(connection string) gorm.Dialector {
	return sqlserver.New(sqlserver.Config{
		DSN: support.GetSqlserverDsn(connection),
	})
}
