# Projet API Authentification - Hackathon

## Contexte du projet

Ce projet a été réalisé dans le cadre d'un `hackathon` durant notre quatrième année de formation supérieure, sur une période de deux jours. 

Notre objectif était de mettre en place un système d'authentification (IAM : Identity and Access Management) utilisé par différents micro-services.

L'authentification permettra :
- L'ajout d'utilisateur
- Le login
- La validation de token et des rôles
- La modification de mot de passe
- La déconnexion

Participants au projet : 
- Dimitri Chine
- Aurélien Penot--Perbet
- Robin Peignet

## Installation / Mise en place

Deux docker-compose sont fournis par l'équipe chargé de la partie DevOps pour lancer l'application en local.

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

## Test des différents endpoints

Après avoir lancé le projet en local, nous pouvons ajouter des utilisateurs via différents endpoint.

Dans le cadre de la démonstration, on utilisera insomnia ou postman pour tester les routes.

### 1) Ajout d'utilisateur (signup)

Pour insérer un nouvel utilisateur dans la base postgres on utilise la route suivante : 

```bash
# Méthode : POST
http://localhost:8080/api/auth/signup
```

Les informations de l'utilisateur créé (username, mail, role...) sont renseigné dans le corps de la requête en JSON : 

```json
{
  "username": "new_user",
  "email": "new_user@example.com",
  "password": "new_password",
  "role": ["ROLE_USER"] // ROLE_MODERATEUR, ROLE_ADMIN
}
```

*Résultats attendus* :

```json
{
	"message": "User registered successfully!"
}
```
```json
{
	"message": "Error: Username is already taken!"
}
```
```json
{
    "message": "Error: Email is already in use!"
}
```

### 2) Connexion (signin)

Après avoir créé l'utilisateur, on peut donc utiliser ses nouveaux crédentials pour s'authentifier : 

```bash
# Méthode : POST
http://localhost:8080/api/auth/signin
```
```json
{
  "username": "new_user",
  "password": "new_password"
}
```

*Résultats attendus* :
```json
{
	"refreshToken": "refresh_token",
	"id": 2,
	"username": "new_user",
	"email": "new_user@example.com",
	"roles": [
		"ROLE_USER"
	],
	"accessToken": "access_token",
	"tokenType": "Bearer"
}
```
*Résultats attendus en cas d'erreur* :
```json
{
    "path": "/api/auth/signin",
    "error": "Unauthorized",
    "message": "Bad credentials",
    "status": 401
}
```

### 3) Vérification du token

La route de vérification du token permet de tester la validité du token jwt.

```bash
# Méthode : GET
http://localhost:8080/api/auth/verifytoken
```

On doit donc également ajouter le `token` que l'on souhaite vérifier dans les en-têtes (headers) de la requête : 

```bash
Authorization | Bearer {token}
```

*Réponse attendu* :
```json
{
    "message": "Token is valid"
}
```

### 4) Refresh token

Route pour récupérer un token dans le cas d'une expiration : 
```bash
# Méthode : POST
http://localhost:8080/api/auth/verifytoken
```
```json
{
	"refreshToken": "refresh_token"
}
```

*Résultat attendu* :
```json
{
	"accessToken": "access_token",
	"refreshToken": "refresh_token",
    "tokenType": "Bearer"
}
```

### 4) Validation des rôles
Route pour valider qu'un token appartient à un rôle spécifique : 
```bash
# Méthode : GET
http://localhost:8080/api/auth/verify/all
http://localhost:8080/api/auth/verify/mod
http://localhost:8080/api/auth/verify/admin
```

*Résultat attendu* :
```bash
Public content
Moderator Board.
Admin Board.
```

*Résultat attendus en cas d'erreur* :
```json
{
    "path": "/refresh",
    "message": "JWT token is expired",
    "status": 401
}
```
```json
{
    "path": "/error",
    "message": "Erreur technique lié au token",
    "status": 400
}
```
*Remarque : Chaque endpoints est accessible et documenté sur SWAGGER par l'URL :*

```bash
localhost:8080/swagger-ui/index.html
```

## Partie technique

Le système d'authentification est basé sur ce repository github (Oauth2) : https://github.com/bezkoder/spring-boot-security-postgresql

Le projet a été développé en java avec le framework `spring` pour fonctionner avec le SGBDR (système de gestion de bases de données relationnelles) `Postgres`, et organisé en respectant une méthode de clean architecture.

*Image tirée du README d'origine.*
![spring-boot-spring-security-postgresql-jwt-authentication-flow](spring-boot-spring-security-postgresql-jwt-authentication-flow.png)

### 1) Les endpoints

Le projet d'origine embarquait l'ajout de compte (utilisateur, modérateur et administrateur) et l'authentification.

Nous avons donc ajouté des routes supplémentaires pour répondre au besoins spécifiques exprimés (vérification du token, rafraîchissement...).

Chaque endpoints attend des informations spécifiques en entrée / sortie organisés en DTOs.

*Exemple des DTOs d'entrée / sortie du refresh token :*

```java
public class TokenRefreshRequest {
    @NotBlank
    private String refreshToken;

    // getter / setter
}

public class TokenRefreshResponse {
    private String accessToken;
    private String refreshToken;
    private String tokenType = "Bearer";

    // getter / setter
}
```

### 2) Les mappers

Pour convertir ces DTO en objets métier (et inversement) nous avons utilisé la librairie `mapstruct` : 
```xml
<dependency>
    <groupId>org.mapstruct</groupId>
    <artifactId>mapstruct</artifactId>
    <version>1.4.2.Final</version>
</dependency>
```

Ainsi, nous avons créé des mappers automatiquement pris en charge par Spring.

*Exemple d'un mapper utilisé pour renvoyer des exceptions liées au token JWT :*
```java
@Mapper(componentModel = "spring")
public interface JwtErrorMapper {
    public JwtErrorMapper INSTANCE = Mappers.getMapper(JwtErrorMapper.class);

    @Mapping(target = "status", source = "httpStatus")
    JwtErrorDTO toDto(SecurityException e);
}
```
Dans ce cas `JwtErrorMapper` à pour entrée un SecurityException et pour destination une exception `JwtErrorDTO`.

Il va mapper le paramètre `httpStatus` de l'exception vers l'attribut `status` du DTO.

### 3) Gestion des erreurs

Pour gérer les différents cas d'erreurs, nous avons créer nos propres exceptions.

L'objectif est donc de renvoyer une erreur spécifique (au client qui a exécuter la requête) avec plusieurs informations : 
- Un code HTTP d'erreur
- Un message de description
- Une route de redirection

```java
public class SecurityException extends JwtException {
    protected String message;
    protected String path;
    protected final int httpStatus;

    // getter / setter
}

// Classe qui hérite de SecurityException
public class TokenRefreshException extends SecurityException {
    public TokenRefreshException() {
        super("/error", "Refresh token is not in database!", HttpStatus.BAD_REQUEST);
    }
}
```
Chaque exception catchée (et liée au token) est peut alors être gérer par les classes qui héritent de SecurityException (et par extention de JwtException).