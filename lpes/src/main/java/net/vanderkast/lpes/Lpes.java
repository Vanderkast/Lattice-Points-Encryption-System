package net.vanderkast.lpes;

import java.math.BigInteger;

public interface Lpes {
    String ALGORITHM = "LPES";
    String FORMAT = "PKCS#8";

    BigInteger N();

    BigInteger Q();
}
