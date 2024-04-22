package com.esgi.spring.security.postgresql.hexa.domain.spi;

import com.esgi.spring.security.postgresql.hexa.domain.Test;

public interface IDao {

    Test add(final Test newTest);
}
