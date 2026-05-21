package com.example.sqlinjectiondemo;

public interface UserRepositoryCustom {
    User findUserByUsernameAndPassword(String username, String password);
    User findUserByUsernameAndPasswordSecure(String username, String password);
}
