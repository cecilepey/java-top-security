package dev.services;

public interface ServicesFactory {
    UserService USER_SERVICE = new UserService();
    LoginService LOGIN_SERVICE = new LoginService();
}
