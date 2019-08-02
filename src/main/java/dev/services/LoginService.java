package dev.services;

import dev.domains.User;
import dev.exceptions.AppException;
import dev.utils.DbUtils;

import java.util.List;
import java.util.Optional;


public class LoginService {

    public Optional<User> connect(String login, String password) {
        List<User> results = new DbUtils().executeSelect(String.format("select * from user where login='%s' and password='%s'", login, password), resultSet -> new DbUtils().resultSetToUser(resultSet));

        if(results.size() > 1) {
            throw new AppException("at least 2 users with same login");
        }

        return results.stream().findAny();
    }


}
