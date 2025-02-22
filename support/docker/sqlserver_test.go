package docker

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/goravel/framework/contracts/database"
	contractstesting "github.com/goravel/framework/contracts/testing"
	mocksconfig "github.com/goravel/framework/mocks/config"
	"github.com/goravel/framework/support/env"
)

type SqlserverTestSuite struct {
	suite.Suite
	mockConfig *mocksconfig.Config
	sqlserver  *SqlserverImpl
}

func TestSqlserverTestSuite(t *testing.T) {
	if env.IsWindows() || TestModel == TestModelMinimum {
		t.Skip("Skip test that using Docker")
	}

	suite.Run(t, new(SqlserverTestSuite))
}

func (s *SqlserverTestSuite) SetupTest() {
	s.mockConfig = &mocksconfig.Config{}
	s.sqlserver = NewSqlserverImpl(testDatabase, testUsername, testPassword)
}

func (s *SqlserverTestSuite) TestBuild() {
	s.Nil(s.sqlserver.Build())
	instance, err := s.sqlserver.connect()
	s.Nil(err)
	s.NotNil(instance)

	s.Equal("127.0.0.1", s.sqlserver.Config().Host)
	s.Equal(testDatabase, s.sqlserver.Config().Database)
	s.Equal(testUsername, s.sqlserver.Config().Username)
	s.Equal(testPassword, s.sqlserver.Config().Password)
	s.True(s.sqlserver.Config().Port > 0)

	res := instance.Exec(`
	CREATE TABLE users (
	 id bigint NOT NULL IDENTITY(1,1),
	 name varchar(255) NOT NULL,
	 PRIMARY KEY (id)
	);
	`)
	s.Nil(res.Error)

	res = instance.Exec(`
	INSERT INTO users (name) VALUES ('goravel');
	`)
	s.Nil(res.Error)
	s.Equal(int64(1), res.RowsAffected)

	var count int64
	res = instance.Raw(`
	SELECT count(*) FROM sys.tables WHERE name = 'users';
	`).Scan(&count)
	s.Nil(res.Error)
	s.Equal(int64(1), count)

	s.Nil(s.sqlserver.Fresh())

	res = instance.Raw(`
	SELECT count(*) FROM sys.tables WHERE name = 'users';
	`).Scan(&count)
	s.Nil(res.Error)
	s.Equal(int64(0), count)

	databaseDriver, err := s.sqlserver.Database("another")
	s.NoError(err)
	s.NotNil(databaseDriver)

	s.Nil(s.sqlserver.Shutdown())
}

func (s *SqlserverTestSuite) TestDriver() {
	s.Equal(database.DriverSqlserver, s.sqlserver.Driver())
}

func (s *SqlserverTestSuite) TestImage() {
	image := contractstesting.Image{
		Repository: "sqlserver",
	}
	s.sqlserver.Image(image)
	s.Equal(&image, s.sqlserver.image)
}
