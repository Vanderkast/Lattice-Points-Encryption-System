package net.vanderkast.lpes;

import java.math.BigInteger;
import java.security.PublicKey;

public interface LpesPublicKey extends PublicKey, Lpes {

    BigInteger[][] key();

    @Override
    default String getAlgorithm() {
        return ALGORITHM;
    }

    @Override
    default String getFormat() {
        return FORMAT;
    }
}
