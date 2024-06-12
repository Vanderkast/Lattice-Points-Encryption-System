package net.vanderkast.lpes;

import lombok.RequiredArgsConstructor;
import net.vanderkast.lpes.spec.LpesPrivateKeySpec;
import net.vanderkast.lpes.spec.LpesPublicKeySpec;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

@RequiredArgsConstructor
public class LpesKeyFactory extends KeyFactorySpi {
    private final SecureRandom random;

    public LpesKeyFactory() {
        this.random = new SecureRandom();
    }

    @Override
    protected LpesPublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof LpesPublicKeySpec publicKeySpec) {
            var privateKey = publicKeySpec.privateKey().key();
            var n = publicKeySpec.privateKey().N().intValue();
            var publicKey = new BigInteger[n][n];
            var coefs = publicKeySpec.coefficients();
            for (int i = 0; i < n; i++) {
                publicKey[i] = new BigInteger[n];
                publicKey[i][0] = BigInteger.ZERO;
                for (int j = 0; j < n; j++) {
                    publicKey[i][j] = publicKey[i][0].add(privateKey[j].multiply(BigInteger.valueOf(coefs[i][j])));
                }
            }
            return new LpesPublicKeyImpl(publicKeySpec.privateKey().N(), publicKeySpec.privateKey().Q(), publicKey);
        } else
            throw new InvalidKeySpecException("An instance of LpesPublicKeySpec was expected.");
    }

    @Override
    protected LpesPrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof LpesPrivateKeySpec privateKeySpec) {
            var n = privateKeySpec.N().intValue();
            var q = privateKeySpec.q();
            var key = new BigInteger[n];
            for (int i = 0; i < n; ++i) {
                var v = new BigInteger(privateKeySpec.qMax().bitLength(), random);
                if (v.compareTo(q) < 1)
                    v = v.add(q);
                else if (v.compareTo(privateKeySpec.qMax()) > -1)
                    v = v.subtract(q);
                key[i] = v;
            }
            return new LpesPrivateKeyImpl(privateKeySpec.N(), q, key);
        } else
            throw new InvalidKeySpecException("An instance of LpesPrivateKeySpec was expected.");
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        throw new UnsupportedOperationException();
    }
}
