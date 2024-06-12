package net.vanderkast.lpes;

import java.math.BigInteger;
import java.security.PrivateKey;

public interface LpesPrivateKey extends PrivateKey, Lpes {

    BigInteger[] key();

    @Override
    default String getAlgorithm() {
        return ALGORITHM;
    }

    @Override
    default String getFormat() {
        return FORMAT;
    }
}
