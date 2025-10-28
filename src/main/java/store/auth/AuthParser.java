package store.auth;

public class AuthParser {

    public static RegisterIn toRegister(RegisterIn in) {
        if (in == null) return null;
        
        return RegisterIn.builder()
            .name(in.name())
            .email(in.email())
            .password(in.password())
            .build();
    }

    public static TokenOut toTokenOut(String token) {
        if (token == null) return null;
        
        return TokenOut.builder()
            .token(token)
            .build();
    }
    
}