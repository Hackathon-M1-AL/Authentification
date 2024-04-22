package com.esgi.spring.security.postgresql.hexa.domain.persistence.adapter;

import com.esgi.spring.security.postgresql.hexa.domain.Test;
import com.esgi.spring.security.postgresql.hexa.domain.spi.IDao;
import com.esgi.spring.security.postgresql.repository.UserRepository;

public class UserDao implements IDao {
    private final UserRepository userRepository;

    public UserDao(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Test add(Test newTest) {
        return null;
    }

    /*@Override
    public Test add(Test newTest) {
        return userRepository.findByUsername(newTest.name);
    }*/
}
