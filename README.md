# Spring Boot, Spring Security, PostgreSQL: JWT Authentication & Authorization example

## Docker compose

Deux docker-compose sont fournis pour lancer l'application en local.

### docker-compose.yml

Le premier docker-compose permet de lancer l'application en local base de données PostgreSQL et l'application Spring Boot.

Pour lancer l'application, il suffit de lancer la commande suivante :

```bash
docker-compose -f docker-compose.yml up
```

### docker-compose-dev.yml

Le deuxième docker-compose permet de lancer juste la base de données PostgreSQL en local.

Pour lancer la base de données, il suffit de lancer la commande suivante :

```bash
docker-compose -f docker-compose-dev.yml up
```

## User Registration, User Login and Authorization process.
The diagram shows flow of how we implement User Registration, User Login and Authorization process.

![spring-boot-spring-security-postgresql-jwt-authentication-flow](spring-boot-spring-security-postgresql-jwt-authentication-flow.png)

## Spring Boot Server Architecture with Spring Security
You can have an overview of our Spring Boot Server with the diagram below:

![spring-boot-spring-security-postgresql-jwt-authentication-architecture](spring-boot-spring-security-postgresql-jwt-authentication-architecture.png)

## Configure Spring Datasource, JPA, App properties
Open `src/main/resources/application.properties`

```
spring.datasource.url= jdbc:postgresql://localhost:5432/testdb
spring.datasource.username= postgres
spring.datasource.password= 123

spring.jpa.properties.hibernate.jdbc.lob.non_contextual_creation= true
spring.jpa.properties.hibernate.dialect= org.hibernate.dialect.PostgreSQLDialect

# Hibernate ddl auto (create, create-drop, validate, update)
spring.jpa.hibernate.ddl-auto= update

# App Properties
esgi.app.jwtSecret= ======================esgi=Spring===========================
esgi.app.jwtExpirationMs= 86400000
```

## Run Spring Boot application
```
mvn spring-boot:run
```

## Run following SQL insert statements
```
INSERT INTO roles(name) VALUES('ROLE_USER');
INSERT INTO roles(name) VALUES('ROLE_MODERATOR');
INSERT INTO roles(name) VALUES('ROLE_ADMIN');
```

For more detail, please visit:
> [Spring Boot, Spring Security, PostgreSQL: JWT Authentication & Authorization example](https://esgi.com/spring-boot-security-postgresql-jwt-authentication/)

> [For MySQL](https://esgi.com/spring-boot-jwt-authentication/)

> [For MongoDB](https://esgi.com/spring-boot-jwt-auth-mongodb/)

## Refresh Token

![spring-boot-refresh-token-jwt-example-flow](spring-boot-refresh-token-jwt-example-flow.png)

For instruction: [Spring Boot Refresh Token with JWT example](https://esgi.com/spring-boot-refresh-token-jwt/)

## More Practice:
> [Spring Boot File upload example with Multipart File](https://esgi.com/spring-boot-file-upload/)

> [Exception handling: @RestControllerAdvice example in Spring Boot](https://esgi.com/spring-boot-restcontrolleradvice/)

> [Spring Boot Repository Unit Test with @DataJpaTest](https://esgi.com/spring-boot-unit-test-jpa-repo-datajpatest/)

> [Spring Boot Rest Controller Unit Test with @WebMvcTest](https://www.esgi.com/spring-boot-webmvctest/)

> [Spring Boot Pagination & Sorting example](https://www.esgi.com/spring-boot-pagination-sorting-example/)

> Validation: [Spring Boot Validate Request Body](https://www.esgi.com/spring-boot-validate-request-body/)

> Documentation: [Spring Boot and Swagger 3 example](https://www.esgi.com/spring-boot-swagger-3/)

> Caching: [Spring Boot Redis Cache example](https://www.esgi.com/spring-boot-redis-cache-example/)

Associations:
> [Spring Boot One To Many example with Spring JPA, Hibernate](https://www.esgi.com/jpa-one-to-many/)

> [Spring Boot Many To Many example with Spring JPA, Hibernate](https://www.esgi.com/jpa-many-to-many/)

> [JPA One To One example with Spring Boot](https://www.esgi.com/jpa-one-to-one/)

## Fullstack Authentication

> [Spring Boot + Vue.js JWT Authentication](https://esgi.com/spring-boot-vue-js-authentication-jwt-spring-security/)

> [Spring Boot + Angular 8 JWT Authentication](https://esgi.com/angular-spring-boot-jwt-auth/)

> [Spring Boot + Angular 10 JWT Authentication](https://esgi.com/angular-10-spring-boot-jwt-auth/)

> [Spring Boot + Angular 11 JWT Authentication](https://esgi.com/angular-11-spring-boot-jwt-auth/)

> [Spring Boot + Angular 12 JWT Authentication](https://www.esgi.com/angular-12-spring-boot-jwt-auth/)

> [Spring Boot + Angular 13 JWT Authentication](https://www.esgi.com/angular-13-spring-boot-jwt-auth/)

> [Spring Boot + Angular 14 JWT Authentication](https://www.esgi.com/angular-14-spring-boot-jwt-auth/)

> [Spring Boot + Angular 15 JWT Authentication](https://www.esgi.com/angular-15-spring-boot-jwt-auth/)

> [Spring Boot + Angular 16 JWT Authentication](https://www.esgi.com/angular-16-spring-boot-jwt-auth/)

> [Spring Boot + Angular 17 JWT Authentication](https://www.esgi.com/angular-17-spring-boot-jwt-auth/)

> [Spring Boot + React JWT Authentication](https://esgi.com/spring-boot-react-jwt-auth/)

## Fullstack CRUD App

> [Vue.js + Spring Boot + PostgreSQL example](https://www.esgi.com/spring-boot-vue-js-postgresql/)

> [Angular 8 + Spring Boot + PostgreSQL example](https://esgi.com/angular-spring-boot-postgresql/)

> [Angular 10 + Spring Boot + PostgreSQL example](https://esgi.com/angular-10-spring-boot-postgresql/)

> [Angular 11 + Spring Boot + PostgreSQL example](https://esgi.com/angular-11-spring-boot-postgresql/)

> [Angular 12 + Spring Boot + PostgreSQL example](https://www.esgi.com/angular-12-spring-boot-postgresql/)

> [Angular 13 + Spring Boot + PostgreSQL example](https://www.esgi.com/spring-boot-angular-13-postgresql/)

> [Angular 14 + Spring Boot + PostgreSQL example](https://www.esgi.com/spring-boot-angular-14-postgresql/)

> [Angular 15 + Spring Boot + PostgreSQL example](https://www.esgi.com/spring-boot-angular-15-postgresql/)

> [Angular 16 + Spring Boot + PostgreSQL example](https://www.esgi.com/spring-boot-angular-16-postgresql/)

> [Angular 17 + Spring Boot + PostgreSQL example](https://www.esgi.com/spring-boot-angular-17-postgresql/)

> [React + Spring Boot + PostgreSQL example](https://esgi.com/spring-boot-react-postgresql/)

Run both Back-end & Front-end in one place:
> [Integrate Angular with Spring Boot Rest API](https://esgi.com/integrate-angular-spring-boot/)

> [Integrate React.js with Spring Boot Rest API](https://esgi.com/integrate-reactjs-spring-boot/)

> [Integrate Vue.js with Spring Boot Rest API](https://esgi.com/integrate-vue-spring-boot/)
