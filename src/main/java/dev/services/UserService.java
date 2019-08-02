package dev.services;

import java.util.List;

import org.mindrot.jbcrypt.BCrypt;

import dev.domains.User;
import dev.utils.DbUtils;

public class UserService {

	private static final String INSERT_USER_SQL = "insert into user(firstname,lastname,login, password) values('%s','%s', '%s', '%s')";
	private static final String SELECT_ALL_USERS_SQL = "select * from user";

	private DbUtils dbUtils = new DbUtils();

	public void save(User user) {

		this.dbUtils.executeInsert(String.format(INSERT_USER_SQL, user.getFirstname(), user.getLastname(),
				user.getLogin(), BCrypt.hashpw(user.getPassword(), BCrypt.gensalt())));
	}

	public List<User> list() {
		return this.dbUtils.executeSelect(SELECT_ALL_USERS_SQL, resultSet -> this.dbUtils.resultSetToUser(resultSet));
	}
}
