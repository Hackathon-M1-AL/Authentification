package com.esgi.spring.security.postgresql;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource(locations = "classpath:application-test.properties")
public class SpringBootSecurityPostgresqlApplicationTests {

  @Test
  public void contextLoads() {
  }

}