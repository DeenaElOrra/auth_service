package store.auth;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import store.account.AccountController;
import store.account.AccountIn;
import store.account.AccountOut;

@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    @Autowired
    private AccountController accountController;

    @Autowired
    private JwtService jwtService;

    public String register(Register register) {
        logger.debug("Registering account: {} with email: {}", 
            register.name(), register.email());

        AccountIn accountIn = AccountIn.builder()
            .name(register.name())
            .email(register.email())
            .password(register.password())
            .build();

        ResponseEntity<AccountOut> response = accountController.create(accountIn);
        
        if (!response.hasBody()) {
            logger.error("Failed to create account for email: {}", register.email());
            throw new ResponseStatusException(
                HttpStatus.INTERNAL_SERVER_ERROR, 
                "Failed to create account"
            );
        }

        AccountOut accountOut = response.getBody();
        logger.debug("Account created successfully with ID: {}", accountOut.id());

        return generateToken(accountOut.id());
    }

    public String login(String email, String password) {
        logger.debug("Login attempt for email: {}", email);

        ResponseEntity<AccountOut> response = accountController.findByEmailAndPassword(
            AccountIn.builder()
                .email(email)
                .password(password)
                .build()
        );

        if (!response.hasBody()) {
            logger.warn("Login failed: invalid credentials for email: {}", email);
            throw new ResponseStatusException(
                HttpStatus.UNAUTHORIZED, 
                "Invalid credentials"
            );
        }

        AccountOut accountOut = response.getBody();
        logger.debug("Login successful for account ID: {}", accountOut.id());

        return generateToken(accountOut.id());
    }

    public SolveOut solve(String token) {
        String accountId = jwtService.getAccountId(token);
        
        return SolveOut.builder()
            .idAccount(accountId)
            .build();
    }

    private String generateToken(String accountId) {
        Date issuedAt = new Date();
        Date expiration = new Date(issuedAt.getTime() + 1000L * 60 * 60 * 24); // 24 hours
        
        return jwtService.createToken(accountId, issuedAt, expiration);
    }

}