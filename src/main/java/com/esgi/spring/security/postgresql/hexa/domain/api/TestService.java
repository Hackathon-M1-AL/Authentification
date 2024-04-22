package com.esgi.spring.security.postgresql.hexa.domain.api;

import com.esgi.spring.security.postgresql.hexa.domain.Test;
import com.esgi.spring.security.postgresql.hexa.domain.spi.IDao;

public class TestService implements IService{

    private final IDao dao;

    public TestService(IDao dao) {
        this.dao = dao;
    }

    @Override
    public Test add(Test newTest) {
        return dao.add(newTest);
    }
}
