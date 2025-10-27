package store.auth;

import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    @Value("${store.jwt.issuer}")
    private String issuer;

    @Value("${store.jwt.secret-key}")
    private String secretKey;

    public String createToken(String accountId, Date notBefore, Date expiration) {
        return Jwts.builder()
            .header()
            .and()
            .id(accountId)
            .issuer(issuer)
            .signWith(getSecretKey())
            .notBefore(notBefore)
            .expiration(expiration)
            .compact();
    }

    public String getAccountId(String token) {
        Claims claims = parseAndValidateToken(token);
        return claims.getId();
    }

    private Claims parseAndValidateToken(String token) {
        JwtParser parser = Jwts.parser()
            .verifyWith(getSecretKey())
            .build();
        
        Claims claims = parser.parseSignedClaims(token).getPayload();
        
        Date now = new Date();
        
        if (claims.getNotBefore().after(now)) {
            throw new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Token is not active yet"
            );
        }
        
        if (claims.getExpiration().before(now)) {
            throw new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Token has expired"
            );
        }
        
        return claims;
    }

    private SecretKey getSecretKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
    
}