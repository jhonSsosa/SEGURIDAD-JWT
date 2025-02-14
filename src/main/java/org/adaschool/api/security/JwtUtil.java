package org.adaschool.api.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.adaschool.api.controller.auth.TokenDto;
import org.adaschool.api.data.user.RoleEnum;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;

import static org.adaschool.api.utils.Constants.CLAIMS_ROLES_KEY;

@Component
public class JwtUtil {

    private final JwtConfig jwtConfig;

    public JwtUtil(JwtConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
    }

    public TokenDto generateToken(String username, List<RoleEnum> roles) {
        Date expirationDate = jwtConfig.getExpirationDate();

        String token = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(expirationDate)
                .claim(CLAIMS_ROLES_KEY, roles)
                .signWith(jwtConfig.getSigningKey(), SignatureAlgorithm.HS256)
                .compact();

        return new TokenDto(token, expirationDate);
    }

    public Claims extractAndVerifyClaims(String token) {
        return Jwts.parser()
                .verifyWith(jwtConfig.getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
