package org.alouastudios.videoplatform.filter;

import com.auth0.jwk.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URL;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwkProvider jwkProvider;

    public JwtAuthFilter(@Value("${supabase.jwks.url}") String jwksUrl) throws Exception {
        this.jwkProvider = new JwkProviderBuilder(new URL(jwksUrl))
                .cached(10, 24, TimeUnit.HOURS) // 10 keys for 24 hours
                .rateLimited(10, 1, TimeUnit.MINUTES) // Rate limiting protection
                .build();
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        // No token, pass. Security config handles blocking
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Skip "Bearer "
        String token = authHeader.substring(7);

        try {

            DecodedJWT jwt = JWT.decode(token);
            Jwk jwk = jwkProvider.get(jwt.getKeyId());
            ECPublicKey publicKey = (ECPublicKey) jwk.getPublicKey();

            Algorithm algorithm = Algorithm.ECDSA256(publicKey, null); // Building verifier using ES256
            // Checks signature, expiry, and structure
            JWTVerifier verifier = JWT.require(algorithm)
                    .withAudience("authenticated")
                    .build();

            DecodedJWT verifiedJwt = verifier.verify(token);
            String userId = verifiedJwt.getSubject(); // Extracts user UUID

            // Set authentication in Spring Security context
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userId, null, List.of());

            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (JWTVerificationException | JwkException e) {
            // Verification failure results in a 401 status
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid or expired token");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
