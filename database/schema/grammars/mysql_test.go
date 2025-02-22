package grammars

import (
	"testing"

	"github.com/stretchr/testify/suite"

	contractsschema "github.com/goravel/framework/contracts/database/schema"
	mocksschema "github.com/goravel/framework/mocks/database/schema"
)

type MysqlSuite struct {
	suite.Suite
	grammar *Mysql
}

func TestMysqlSuite(t *testing.T) {
	suite.Run(t, &MysqlSuite{})
}

func (s *MysqlSuite) SetupTest() {
	s.grammar = NewMysql("goravel_")
}

func (s *MysqlSuite) TestCompileAdd() {
	mockBlueprint := mocksschema.NewBlueprint(s.T())
	mockColumn := mocksschema.NewColumnDefinition(s.T())

	mockBlueprint.EXPECT().GetTableName().Return("users").Once()
	mockColumn.EXPECT().GetName().Return("name").Once()
	mockColumn.EXPECT().GetType().Return("string").Twice()
	mockColumn.EXPECT().GetDefault().Return("goravel").Twice()
	mockColumn.EXPECT().GetNullable().Return(false).Once()
	mockColumn.EXPECT().GetLength().Return(1).Once()
	mockColumn.EXPECT().GetOnUpdate().Return(nil).Once()
	mockColumn.EXPECT().GetComment().Return("comment").Once()
	mockColumn.EXPECT().GetUnsigned().Return(false).Once()

	sql := s.grammar.CompileAdd(mockBlueprint, &contractsschema.Command{
		Column: mockColumn,
	})

	s.Equal("alter table `goravel_users` add `name` varchar(1) not null default 'goravel' comment 'comment'", sql)
}

func (s *MysqlSuite) TestCompileChange() {
	mockBlueprint := mocksschema.NewBlueprint(s.T())
	mockColumn := mocksschema.NewColumnDefinition(s.T())

	mockBlueprint.EXPECT().GetTableName().Return("users").Once()
	mockColumn.EXPECT().GetName().Return("name").Once()
	mockColumn.EXPECT().GetType().Return("string").Twice()
	mockColumn.EXPECT().GetDefault().Return("goravel").Twice()
	mockColumn.EXPECT().GetNullable().Return(false).Once()
	mockColumn.EXPECT().GetLength().Return(1).Once()
	mockColumn.EXPECT().GetOnUpdate().Return(nil).Once()
	mockColumn.EXPECT().GetComment().Return("comment").Once()
	mockColumn.EXPECT().GetUnsigned().Return(false).Once()

	sql := s.grammar.CompileChange(mockBlueprint, &contractsschema.Command{
		Column: mockColumn,
	})

	s.Equal([]string{"alter table `goravel_users` modify `name` varchar(1) not null default 'goravel' comment 'comment'"}, sql)
}

func (s *MysqlSuite) TestCompileCreate() {
	mockColumn1 := mocksschema.NewColumnDefinition(s.T())
	mockColumn2 := mocksschema.NewColumnDefinition(s.T())
	mockBlueprint := mocksschema.NewBlueprint(s.T())

	// postgres.go::CompileCreate
	primaryCommand := &contractsschema.Command{
		Name:      "primary",
		Columns:   []string{"role_id", "user_id"},
		Algorithm: "btree",
	}
	mockBlueprint.EXPECT().GetCommands().Return([]*contractsschema.Command{
		primaryCommand,
	}).Once()
	mockBlueprint.EXPECT().GetTableName().Return("users").Once()
	// utils.go::getColumns
	mockBlueprint.EXPECT().GetAddedColumns().Return([]contractsschema.ColumnDefinition{
		mockColumn1, mockColumn2,
	}).Once()
	// utils.go::getColumns
	mockColumn1.EXPECT().GetName().Return("id").Once()
	// utils.go::getType
	mockColumn1.EXPECT().GetType().Return("integer").Once()
	// postgres.go::TypeInteger
	mockColumn1.EXPECT().GetAutoIncrement().Return(true).Once()
	// postgres.go::ModifyDefault
	mockColumn1.EXPECT().GetDefault().Return(nil).Once()
	// postgres.go::ModifyIncrement
	mockBlueprint.EXPECT().HasCommand("primary").Return(false).Once()
	mockColumn1.EXPECT().GetType().Return("integer").Once()
	// postgres.go::ModifyNullable
	mockColumn1.EXPECT().GetNullable().Return(false).Once()
	mockColumn1.EXPECT().GetOnUpdate().Return(nil).Once()
	mockColumn1.EXPECT().GetComment().Return("id").Once()
	mockColumn1.EXPECT().GetUnsigned().Return(true).Once()

	// utils.go::getColumns
	mockColumn2.EXPECT().GetName().Return("name").Once()
	// utils.go::getType
	mockColumn2.EXPECT().GetType().Return("string").Once()
	// postgres.go::TypeString
	mockColumn2.EXPECT().GetLength().Return(100).Once()
	// postgres.go::ModifyDefault
	mockColumn2.EXPECT().GetDefault().Return(nil).Once()
	// postgres.go::ModifyIncrement
	mockColumn2.EXPECT().GetType().Return("string").Once()
	// postgres.go::ModifyNullable
	mockColumn2.EXPECT().GetNullable().Return(true).Once()
	mockColumn2.EXPECT().GetOnUpdate().Return(nil).Once()
	mockColumn2.EXPECT().GetComment().Return("name").Once()
	mockColumn2.EXPECT().GetUnsigned().Return(false).Once()

	s.Equal("create table `goravel_users` (`id` int unsigned not null auto_increment primary key comment 'id', `name` varchar(100) null comment 'name', primary key using btree(`role_id`, `user_id`))",
		s.grammar.CompileCreate(mockBlueprint))
	s.True(primaryCommand.ShouldBeSkipped)
}

func (s *MysqlSuite) TestCompileDropAllTables() {
	s.Equal("drop table `domain`, `email`", s.grammar.CompileDropAllTables([]string{"domain", "email"}))
}

func (s *MysqlSuite) TestCompileDropAllViews() {
	s.Equal("drop view `domain`, `email`", s.grammar.CompileDropAllViews([]string{"domain", "email"}))
}

func (s *MysqlSuite) TestCompileDropColumn() {
	mockBlueprint := mocksschema.NewBlueprint(s.T())
	mockBlueprint.EXPECT().GetTableName().Return("users").Once()

	s.Equal([]string{
		"alter table `goravel_users` drop `id`, drop `name`",
	}, s.grammar.CompileDropColumn(mockBlueprint, &contractsschema.Command{
		Columns: []string{"id", "name"},
	}))
}

func (s *MysqlSuite) TestCompileDropIfExists() {
	mockBlueprint := mocksschema.NewBlueprint(s.T())
	mockBlueprint.EXPECT().GetTableName().Return("users").Once()

	s.Equal("drop table if exists `goravel_users`", s.grammar.CompileDropIfExists(mockBlueprint))
}

func (s *MysqlSuite) TestCompileForeign() {
	var mockBlueprint *mocksschema.Blueprint

	beforeEach := func() {
		mockBlueprint = mocksschema.NewBlueprint(s.T())
		mockBlueprint.EXPECT().GetTableName().Return("users").Once()
	}

	tests := []struct {
		name      string
		command   *contractsschema.Command
		expectSql string
	}{
		{
			name: "with on delete and on update",
			command: &contractsschema.Command{
				Index:      "fk_users_role_id",
				Columns:    []string{"role_id", "user_id"},
				On:         "roles",
				References: []string{"id", "user_id"},
				OnDelete:   "cascade",
				OnUpdate:   "restrict",
			},
			expectSql: "alter table `goravel_users` add constraint `fk_users_role_id` foreign key (`role_id`, `user_id`) references `goravel_roles` (`id`, `user_id`) on delete cascade on update restrict",
		},
		{
			name: "without on delete and on update",
			command: &contractsschema.Command{
				Index:      "fk_users_role_id",
				Columns:    []string{"role_id", "user_id"},
				On:         "roles",
				References: []string{"id", "user_id"},
			},
			expectSql: "alter table `goravel_users` add constraint `fk_users_role_id` foreign key (`role_id`, `user_id`) references `goravel_roles` (`id`, `user_id`)",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			beforeEach()

			sql := s.grammar.CompileForeign(mockBlueprint, test.command)
			s.Equal(test.expectSql, sql)
		})
	}
}

func (s *MysqlSuite) TestCompileIndex() {
	var mockBlueprint *mocksschema.Blueprint

	beforeEach := func() {
		mockBlueprint = mocksschema.NewBlueprint(s.T())
		mockBlueprint.EXPECT().GetTableName().Return("users").Once()
	}

	tests := []struct {
		name      string
		command   *contractsschema.Command
		expectSql string
	}{
		{
			name: "with Algorithm",
			command: &contractsschema.Command{
				Index:     "fk_users_role_id",
				Columns:   []string{"role_id", "user_id"},
				Algorithm: "btree",
			},
			expectSql: "alter table `goravel_users` add index `fk_users_role_id` using btree(`role_id`, `user_id`)",
		},
		{
			name: "without Algorithm",
			command: &contractsschema.Command{
				Index:   "fk_users_role_id",
				Columns: []string{"role_id", "user_id"},
			},
			expectSql: "alter table `goravel_users` add index `fk_users_role_id`(`role_id`, `user_id`)",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			beforeEach()

			sql := s.grammar.CompileIndex(mockBlueprint, test.command)
			s.Equal(test.expectSql, sql)
		})
	}
}

func (s *MysqlSuite) TestCompilePrimary() {
	mockBlueprint := mocksschema.NewBlueprint(s.T())
	mockBlueprint.EXPECT().GetTableName().Return("users").Once()

	s.Equal("alter table `goravel_users` add primary key (`role_id`, `user_id`)", s.grammar.CompilePrimary(mockBlueprint, &contractsschema.Command{
		Columns: []string{"role_id", "user_id"},
	}))
}

func (s *MysqlSuite) TestCompileKey() {
	mockBlueprint := mocksschema.NewBlueprint(s.T())
	mockBlueprint.EXPECT().GetTableName().Return("users").Twice()

	s.Equal("alter table `goravel_users` add unique `index`(`id`, `name`)", s.grammar.compileKey(mockBlueprint, &contractsschema.Command{
		Algorithm: "",
		Columns:   []string{"id", "name"},
		Index:     "index",
	}, "unique"))

	s.Equal("alter table `goravel_users` add unique `index` using btree(`id`, `name`)", s.grammar.compileKey(mockBlueprint, &contractsschema.Command{
		Algorithm: "btree",
		Columns:   []string{"id", "name"},
		Index:     "index",
	}, "unique"))
}

func (s *MysqlSuite) TestGetColumns() {
	mockColumn1 := mocksschema.NewColumnDefinition(s.T())
	mockColumn2 := mocksschema.NewColumnDefinition(s.T())
	mockBlueprint := mocksschema.NewBlueprint(s.T())

	mockBlueprint.EXPECT().GetAddedColumns().Return([]contractsschema.ColumnDefinition{
		mockColumn1, mockColumn2,
	}).Once()
	mockBlueprint.EXPECT().HasCommand("primary").Return(false).Once()

	mockColumn1.EXPECT().GetName().Return("id").Once()
	mockColumn1.EXPECT().GetType().Return("integer").Twice()
	mockColumn1.EXPECT().GetDefault().Return(nil).Once()
	mockColumn1.EXPECT().GetNullable().Return(false).Once()
	mockColumn1.EXPECT().GetOnUpdate().Return(nil).Once()
	mockColumn1.EXPECT().GetAutoIncrement().Return(true).Once()
	mockColumn1.EXPECT().GetComment().Return("id").Once()
	mockColumn1.EXPECT().GetUnsigned().Return(true).Once()

	mockColumn2.EXPECT().GetName().Return("name").Once()
	mockColumn2.EXPECT().GetType().Return("string").Twice()
	mockColumn2.EXPECT().GetDefault().Return("goravel").Twice()
	mockColumn2.EXPECT().GetNullable().Return(true).Once()
	mockColumn2.EXPECT().GetOnUpdate().Return(nil).Once()
	mockColumn2.EXPECT().GetLength().Return(10).Once()
	mockColumn2.EXPECT().GetComment().Return("name").Once()
	mockColumn2.EXPECT().GetUnsigned().Return(false).Once()

	s.Equal([]string{"`id` int unsigned not null auto_increment primary key comment 'id'", "`name` varchar(10) null default 'goravel' comment 'name'"}, s.grammar.getColumns(mockBlueprint))
}

func (s *MysqlSuite) TestModifyDefault() {
	var (
		mockBlueprint *mocksschema.Blueprint
		mockColumn    *mocksschema.ColumnDefinition
	)

	tests := []struct {
		name      string
		setup     func()
		expectSql string
	}{
		{
			name: "without change and default is nil",
			setup: func() {
				mockColumn.EXPECT().GetDefault().Return(nil).Once()
			},
		},
		{
			name: "without change and default is not nil",
			setup: func() {
				mockColumn.EXPECT().GetDefault().Return("goravel").Twice()
			},
			expectSql: " default 'goravel'",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			mockBlueprint = mocksschema.NewBlueprint(s.T())
			mockColumn = mocksschema.NewColumnDefinition(s.T())

			test.setup()

			sql := s.grammar.ModifyDefault(mockBlueprint, mockColumn)

			s.Equal(test.expectSql, sql)
		})
	}
}

func (s *MysqlSuite) TestModifyNullable() {
	mockBlueprint := mocksschema.NewBlueprint(s.T())
	mockColumn := mocksschema.NewColumnDefinition(s.T())
	mockColumn.EXPECT().GetNullable().Return(true).Once()

	s.Equal(" null", s.grammar.ModifyNullable(mockBlueprint, mockColumn))

	mockColumn.EXPECT().GetNullable().Return(false).Once()

	s.Equal(" not null", s.grammar.ModifyNullable(mockBlueprint, mockColumn))
}

func (s *MysqlSuite) TestModifyIncrement() {
	mockBlueprint := mocksschema.NewBlueprint(s.T())

	mockColumn := mocksschema.NewColumnDefinition(s.T())
	mockBlueprint.EXPECT().HasCommand("primary").Return(false).Once()
	mockColumn.EXPECT().GetType().Return("bigInteger").Once()
	mockColumn.EXPECT().GetAutoIncrement().Return(true).Once()

	s.Equal(" auto_increment primary key", s.grammar.ModifyIncrement(mockBlueprint, mockColumn))
}

func (s *MysqlSuite) TestModifyOnUpdate() {
	mockBlueprint := mocksschema.NewBlueprint(s.T())
	mockColumn := mocksschema.NewColumnDefinition(s.T())
	mockColumn.EXPECT().GetOnUpdate().Return(Expression("CURRENT_TIMESTAMP")).Once()

	s.Equal(" on update CURRENT_TIMESTAMP", s.grammar.ModifyOnUpdate(mockBlueprint, mockColumn))

	mockColumn.EXPECT().GetOnUpdate().Return("CURRENT_TIMESTAMP").Once()
	s.Equal(" on update CURRENT_TIMESTAMP", s.grammar.ModifyOnUpdate(mockBlueprint, mockColumn))

	mockColumn.EXPECT().GetOnUpdate().Return("").Once()
	s.Empty(s.grammar.ModifyOnUpdate(mockBlueprint, mockColumn))

	mockColumn.EXPECT().GetOnUpdate().Return(nil).Once()
	s.Empty(s.grammar.ModifyOnUpdate(mockBlueprint, mockColumn))
}

func (s *MysqlSuite) TestTypeDateTime() {
	mockColumn := mocksschema.NewColumnDefinition(s.T())
	mockColumn.EXPECT().GetPrecision().Return(3).Once()
	mockColumn.EXPECT().GetUseCurrent().Return(true).Once()
	mockColumn.EXPECT().Default(Expression("CURRENT_TIMESTAMP(3)")).Return(mockColumn).Once()
	mockColumn.EXPECT().GetUseCurrentOnUpdate().Return(true).Once()
	mockColumn.EXPECT().OnUpdate(Expression("CURRENT_TIMESTAMP(3)")).Return(mockColumn).Once()
	s.Equal("datetime(3)", s.grammar.TypeDateTime(mockColumn))

	mockColumn = mocksschema.NewColumnDefinition(s.T())
	mockColumn.EXPECT().GetPrecision().Return(0).Once()
	mockColumn.EXPECT().GetUseCurrent().Return(false).Once()
	mockColumn.EXPECT().GetUseCurrentOnUpdate().Return(false).Once()
	s.Equal("datetime", s.grammar.TypeDateTime(mockColumn))
}

func (s *MysqlSuite) TestTypeDecimal() {
	mockColumn := mocksschema.NewColumnDefinition(s.T())
	mockColumn.EXPECT().GetTotal().Return(4).Once()
	mockColumn.EXPECT().GetPlaces().Return(2).Once()

	s.Equal("decimal(4, 2)", s.grammar.TypeDecimal(mockColumn))
}

func (s *MysqlSuite) TestTypeEnum() {
	mockColumn := mocksschema.NewColumnDefinition(s.T())
	mockColumn.EXPECT().GetAllowed().Return([]any{"a", "b"}).Once()

	s.Equal(`enum('a', 'b')`, s.grammar.TypeEnum(mockColumn))
}

func (s *MysqlSuite) TestTypeFloat() {
	mockColumn := mocksschema.NewColumnDefinition(s.T())
	mockColumn.EXPECT().GetPrecision().Return(0).Once()

	s.Equal("float", s.grammar.TypeFloat(mockColumn))

	mockColumn.EXPECT().GetPrecision().Return(2).Once()

	s.Equal("float(2)", s.grammar.TypeFloat(mockColumn))
}

func (s *MysqlSuite) TestTypeString() {
	mockColumn1 := mocksschema.NewColumnDefinition(s.T())
	mockColumn1.EXPECT().GetLength().Return(100).Once()

	s.Equal("varchar(100)", s.grammar.TypeString(mockColumn1))

	mockColumn2 := mocksschema.NewColumnDefinition(s.T())
	mockColumn2.EXPECT().GetLength().Return(0).Once()

	s.Equal("varchar(255)", s.grammar.TypeString(mockColumn2))
}

func (s *MysqlSuite) TestTypeTimestamp() {
	mockColumn := mocksschema.NewColumnDefinition(s.T())
	mockColumn.EXPECT().GetPrecision().Return(3).Once()
	mockColumn.EXPECT().GetUseCurrent().Return(true).Once()
	mockColumn.EXPECT().Default(Expression("CURRENT_TIMESTAMP(3)")).Return(mockColumn).Once()
	mockColumn.EXPECT().GetUseCurrentOnUpdate().Return(true).Once()
	mockColumn.EXPECT().OnUpdate(Expression("CURRENT_TIMESTAMP(3)")).Return(mockColumn).Once()
	s.Equal("timestamp(3)", s.grammar.TypeTimestamp(mockColumn))

	mockColumn = mocksschema.NewColumnDefinition(s.T())
	mockColumn.EXPECT().GetPrecision().Return(0).Once()
	mockColumn.EXPECT().GetUseCurrent().Return(false).Once()
	mockColumn.EXPECT().GetUseCurrentOnUpdate().Return(false).Once()
	s.Equal("timestamp", s.grammar.TypeTimestamp(mockColumn))
}
