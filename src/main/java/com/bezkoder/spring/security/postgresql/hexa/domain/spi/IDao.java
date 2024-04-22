package com.bezkoder.spring.security.postgresql.hexa.domain.spi;

import com.bezkoder.spring.security.postgresql.hexa.domain.Test;

public interface IDao {

    Test add(final Test newTest);
}
