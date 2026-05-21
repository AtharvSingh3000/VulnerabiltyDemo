package com.example.sqlinjectiondemo.repository;

import com.example.sqlinjectiondemo.model.User;

public interface UserRepositoryCustom {
    User findUserByUsernameAndPassword(String username, String password);
    User findUserByUsernameAndPasswordSecure(String username, String password);
}
