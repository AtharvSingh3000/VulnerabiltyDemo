package com.example.sqlinjectiondemo;

import org.springframework.stereotype.Repository;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;

import java.util.List;

@Repository
public class UserRepositoryImpl implements UserRepositoryCustom {

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * Vulnerable implementation (for SQL injection demonstration).
     */
    @Override
    public User findUserByUsernameAndPassword(String username, String password) {
        // Insecure: Vulnerable to SQL Injection
        String sql = "SELECT * FROM User WHERE username = '" + username + "' AND password = '" + password + "'";
        Query query = entityManager.createNativeQuery(sql, User.class);

        @SuppressWarnings("unchecked")
        List<User> users = query.getResultList();

        return users.isEmpty() ? null : users.get(0);
    }

    /**
     * Secure implementation using parameterized queries.
     */
    public User findUserByUsernameAndPasswordSecure(String username, String password) {
        // Secure: Uses parameterized query to prevent SQL Injection
        String sql = "SELECT * FROM User WHERE username = :username AND password = :password";
        Query query = entityManager.createNativeQuery(sql, User.class);
        query.setParameter("username", username);
        query.setParameter("password", password);

        @SuppressWarnings("unchecked")
        List<User> users = query.getResultList();

        return users.isEmpty() ? null : users.get(0);
    }
}
        

