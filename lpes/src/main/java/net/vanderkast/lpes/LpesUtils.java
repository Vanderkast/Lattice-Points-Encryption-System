package net.vanderkast.lpes;

import java.math.BigInteger;
import java.security.SecureRandom;

public class LpesUtils {
    private LpesUtils() {
    }

    public static BigInteger genBigInteger(SecureRandom random, BigInteger low, BigInteger high) {
        var value = new BigInteger(high.bitLength(), random);
        if (value.compareTo(low) < 1)
            value = value.add(low);
        else if (value.compareTo(high) > -1)
            value = value.subtract(low);
        return value;
    }
}
