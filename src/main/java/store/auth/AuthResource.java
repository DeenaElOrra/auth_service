package store.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

@RestController
public class AuthResource implements AuthController {

    @Autowired
    private AuthService authService;

    @Override
    public ResponseEntity<TokenOut> register(RegisterIn registerIn) {
        String token = authService.register(registerIn);
                
        return ResponseEntity
            .created(ServletUriComponentsBuilder.fromCurrentRequest().build().toUri())
            .body(AuthParser.toTokenOut(token));
    }

    @Override
    public ResponseEntity<TokenOut> login(LoginIn loginIn) {
        String token = authService.login(loginIn.email(), loginIn.password());
        
        return ResponseEntity
            .ok()
            .body(AuthParser.toTokenOut(token));
    }

    @Override
    public ResponseEntity<SolveOut> solve(TokenOut tokenOut) {
        SolveOut solveOut = authService.solve(tokenOut.token());
        
        return ResponseEntity.ok(solveOut);
    }

}