package net.vanderkast.lpes;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.math.BigInteger;
import java.security.SecureRandom;

@RequiredArgsConstructor
@Getter
public class LpesCore {
    private final SecureRandom random;
    private final int coefficientMin;
    private final int coefficientMax;

    BigInteger[] encode(int[] message, BigInteger Q) {
        var encoded = new BigInteger[message.length];
        for (int i = 0; i < message.length; i++) {
            encoded[i] = message[i] == 0 ? BigInteger.ZERO : Q.divide(BigInteger.TWO).add(BigInteger.ONE);
        }
        return encoded;
    }

    public BigInteger[] encrypt(int[] message, LpesPublicKey publicKey) {
        if (publicKey.N().intValue() != message.length)
            throw new IllegalArgumentException("Message length must be equal to parameter N.");
        var n = publicKey.N().intValue();
        var errMax = publicKey.N().divide(BigInteger.valueOf(4));
        var errMin = errMax.multiply(BigInteger.valueOf(-1));
        var cipher = encode(message, publicKey.Q());
        for (int i = 0; i < n; i++) {
            cipher[i] = cipher[i].add(LpesUtils.genBigInteger(random, errMin, errMax));
            for (int j = 0; j < n; j++) {
                cipher[i] = cipher[i].add(
                        publicKey.key()[j][i].multiply(BigInteger.valueOf(random.nextInt(coefficientMin, coefficientMax))));
            }
        }
        return cipher;
    }

    public int[] decrypt(BigInteger[] cipher, LpesPrivateKey privateKey) {
        if (cipher.length != privateKey.N().intValue())
            throw new IllegalArgumentException("Message length must be equal to parameter N.");
        var n = privateKey.N().intValue();
        var q = privateKey.Q();
        var message = new int[n];
        var key = privateKey.key();
        var oneMin = q.divide(BigInteger.valueOf(4));
        var oneMax = q.subtract(oneMin);
        for (int i = 0; i < n; i++) {
            var d = cipher[i].divide(key[i]).abs();
            message[i] = d.compareTo(oneMin) > 0 && d.compareTo(oneMax) < 0 ? 1 : 0;
        }
        return message;
    }
}
