package ma.mugiwara.springbootpractice.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtConfig {

    @Value("${jwt.encryption.type:SYMMETRIC}")
    private String encryptionType; // SYMMETRIC or ASYMMETRIC

    // Symmetric key
    private static final String SYMMETRIC_SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";

    // Asymmetric keys (you'll need to generate these)
    private static final String PRIVATE_KEY_PATH = "keys/private_key.der";
    private static final String PUBLIC_KEY_PATH = "keys/public_key.der";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSigningKey(), getSignatureAlgorithm())
                .compact();
    }

    private SignatureAlgorithm getSignatureAlgorithm() {
        return encryptionType.equals("SYMMETRIC") ? SignatureAlgorithm.HS256 : SignatureAlgorithm.RS256;
    }

    private Key getSigningKey() {
        if (encryptionType.equals("SYMMETRIC")) {
            return getSymmetricKey();
        } else {
            return getPrivateKey();
        }
    }

    private Key getVerificationKey() {
        if (encryptionType.equals("SYMMETRIC")) {
            return getSymmetricKey();
        } else {
            return getPublicKey();
        }
    }

    private Key getSymmetricKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SYMMETRIC_SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private PrivateKey getPrivateKey() {
        try {
            byte[] keyBytes = new ClassPathResource(PRIVATE_KEY_PATH).getInputStream().readAllBytes();
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        } catch (Exception e) {
            throw new RuntimeException("Error loading private key", e);
        }
    }

    private PublicKey getPublicKey() {
        try {
            byte[] keyBytes = new ClassPathResource(PUBLIC_KEY_PATH).getInputStream().readAllBytes();
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            throw new RuntimeException("Error loading public key", e);
        }
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getVerificationKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Utility method to generate RSA key pair
    public static void generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Save private key
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        Files.write(new ClassPathResource(PRIVATE_KEY_PATH).getFile().toPath(), privateKeyBytes);

        // Save public key
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        Files.write(new ClassPathResource(PUBLIC_KEY_PATH).getFile().toPath(), publicKeyBytes);
    }
}