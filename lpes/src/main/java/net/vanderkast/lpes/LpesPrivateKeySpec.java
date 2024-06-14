package net.vanderkast.lpes;

import java.math.BigInteger;
import java.security.spec.KeySpec;

public record LpesPrivateKeySpec(
        BigInteger N,
        BigInteger q,
        BigInteger qMax
) implements KeySpec {
    public LpesPrivateKeySpec {
        if (qMax.subtract(q).compareTo(BigInteger.TWO) < 0)
            throw new IllegalArgumentException("Parameter qMax must be at least two times higher than q.");
    }
}
